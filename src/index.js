// Design Board – Cloudflare Worker
// Env vars / secrets: JWT_SECRET, MODELSCOPE_API_KEY, QWEN_API_KEY,
// DEEPSEEK_API_KEY, ZHIPU_API_KEY
// D1 binding: DB

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  })
}

// ── JWT ──

async function getKey(secret) {
  const enc = new TextEncoder()
  return crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  )
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function signJWT(payload, secret) {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)))
  const key = await getKey(secret)
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`))
  return `${header}.${body}.${b64url(sig)}`
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.')
    const key = await getKey(secret)
    const valid = await crypto.subtle.verify(
      'HMAC', key,
      Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
      new TextEncoder().encode(`${header}.${body}`)
    )
    if (!valid) return null
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')))
    if (payload.exp < Date.now() / 1000) return null
    return payload
  } catch {
    return null
  }
}

async function authMiddleware(req, env) {
  const auth = req.headers.get('Authorization') || ''
  const token = auth.replace('Bearer ', '')
  return verifyJWT(token, env.JWT_SECRET)
}

// ── Helpers ──

async function hashPassword(salt, password) {
  const data = new TextEncoder().encode(salt + password)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function parseDataUrl(data) {
  const match = String(data || '').match(/^data:([^;,]+)?;base64,([\s\S]+)$/)
  if (!match) return null
  const binary = atob(match[2])
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return { contentType: match[1] || 'application/octet-stream', bytes }
}

function bytesToBase64(bytes) {
  let binary = ''
  const chunkSize = 0x8000
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
  }
  return btoa(binary)
}

function extForContentType(contentType = '') {
  const type = contentType.toLowerCase().split(';')[0]
  if (type === 'image/jpeg' || type === 'image/jpg') return 'jpg'
  if (type === 'image/png') return 'png'
  if (type === 'image/webp') return 'webp'
  if (type === 'image/gif') return 'gif'
  if (type === 'image/svg+xml') return 'svg'
  return 'bin'
}

function publicAssetBase(env) {
  return (env.ASSET_PUBLIC_BASE_URL || '').replace(/\/+$/, '')
}

function assetPublicUrl(env, key, id) {
  const base = publicAssetBase(env)
  if (!base) return `/api/assets/${id}`
  return `${base}/${key.split('/').map(encodeURIComponent).join('/')}`
}

function keyFromPublicUrl(imageUrl, env) {
  const base = publicAssetBase(env)
  if (!base || !imageUrl.startsWith(`${base}/`)) return ''
  return decodeURIComponent(imageUrl.slice(base.length + 1))
}

function dataUrlFromBytes(bytes, contentType) {
  return `data:${contentType || 'application/octet-stream'};base64,${bytesToBase64(bytes)}`
}

async function getAssetById(env, id) {
  if (!env.DB || !id) return null
  try {
    return await env.DB.prepare(
      'SELECT r2_key, public_url, content_type FROM assets WHERE id = ? AND deleted_at IS NULL'
    ).bind(id).first()
  } catch {
    return null
  }
}

async function r2ObjectToDataUrl(object) {
  if (!object) return ''
  const bytes = new Uint8Array(await object.arrayBuffer())
  const contentType = object.httpMetadata?.contentType || object.customMetadata?.contentType || 'application/octet-stream'
  return dataUrlFromBytes(bytes, contentType)
}

async function loadJsonSetting(env, key) {
  if (!env.DB) return null
  try {
    const row = await env.DB.prepare('SELECT value FROM app_settings WHERE key = ?').bind(key).first()
    return row?.value ? JSON.parse(row.value) : null
  } catch {
    return null
  }
}

async function saveJsonSetting(env, key, value) {
  if (!env.DB || value === undefined) return
  await env.DB.prepare(
    `INSERT INTO app_settings (key, value, updated_at)
     VALUES (?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
  ).bind(key, JSON.stringify(value ?? null)).run()
}

function collectAssetRefs(value, env, refs = { ids: new Set(), keys: new Set(), urls: new Set() }) {
  if (!value) return refs
  if (Array.isArray(value)) {
    for (const item of value) collectAssetRefs(item, env, refs)
    return refs
  }
  if (typeof value !== 'object') return refs

  if (typeof value.assetId === 'string' && value.assetId) refs.ids.add(value.assetId)
  if (typeof value.imageKey === 'string' && value.imageKey) refs.keys.add(value.imageKey)
  if (typeof value.publicUrl === 'string' && value.publicUrl) refs.urls.add(value.publicUrl)

  if (typeof value.imageUrl === 'string' && value.imageUrl) {
    refs.urls.add(value.imageUrl)
    const assetRouteMatch = value.imageUrl.match(/\/api\/assets\/([^/?#]+)/)
    if (assetRouteMatch) refs.ids.add(assetRouteMatch[1])
    const publicKey = keyFromPublicUrl(value.imageUrl, env)
    if (publicKey) refs.keys.add(publicKey)
  }

  for (const item of Object.values(value)) collectAssetRefs(item, env, refs)
  return refs
}

async function syncAssetReferences(cards, env) {
  if (!env.DB) return
  let rows
  try {
    rows = await env.DB.prepare('SELECT id, r2_key, public_url, deleted_at FROM assets').all()
  } catch {
    return
  }

  const refs = collectAssetRefs(cards, env)
  for (const asset of rows.results || []) {
    const referenced = refs.ids.has(asset.id) || refs.keys.has(asset.r2_key) || refs.urls.has(asset.public_url)
    if (referenced && asset.deleted_at) {
      await env.DB.prepare('UPDATE assets SET deleted_at = NULL WHERE id = ?').bind(asset.id).run()
    } else if (!referenced && !asset.deleted_at) {
      await env.DB.prepare("UPDATE assets SET deleted_at = datetime('now') WHERE id = ?").bind(asset.id).run()
    }
  }
}

async function cleanupAssets(env, opts = {}) {
  if (!env.DB || !env.ASSETS) return { ok: false, error: 'Asset storage is not configured' }

  const olderThanDays = Math.max(1, Math.min(365, Number(opts.olderThanDays) || 7))
  const limit = Math.max(1, Math.min(500, Number(opts.limit) || 50))
  const dryRun = opts.dryRun === true
  const cutoff = `-${olderThanDays} days`

  const rows = await env.DB.prepare(
    "SELECT id, r2_key, public_url, deleted_at FROM assets WHERE deleted_at IS NOT NULL AND deleted_at < datetime('now', ?) LIMIT ?"
  ).bind(cutoff, limit).all()

  const candidates = rows.results || []
  if (dryRun) return { ok: true, dryRun, count: candidates.length, assets: candidates }

  const deleted = []
  const failed = []
  for (const asset of candidates) {
    try {
      await env.ASSETS.delete(asset.r2_key)
      await env.DB.prepare('DELETE FROM assets WHERE id = ?').bind(asset.id).run()
      deleted.push(asset.id)
    } catch (e) {
      failed.push({ id: asset.id, error: e.message })
    }
  }

  return { ok: failed.length === 0, deleted, failed }
}

async function handleCleanupAssets(req, env) {
  const body = await req.json().catch(() => ({}))
  const result = await cleanupAssets(env, body)
  return json(result, result.ok ? 200 : 500)
}

// ── Generated pages (Phase 2 durable persistence) ──

function versionR2Keys(groupId, pageId, versionNo) {
  const prefix = `generated/${groupId}/${pageId}/v${versionNo}`
  return {
    html: `${prefix}/index.html`,
    css: `${prefix}/styles.css`,
    js: `${prefix}/script.js`,
  }
}

async function handleCreateGroup(req, env) {
  const body = await req.json().catch(() => ({}))
  const { cardId, title, promptCardId } = body
  const id = crypto.randomUUID()
  try {
    await env.DB.prepare(
      `INSERT INTO generated_page_groups (id, card_id, title, prompt_card_id)
       VALUES (?,?,?,?)`
    ).bind(id, cardId || null, title || null, promptCardId || null).run()
    return json({ id })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleCreatePage(req, env) {
  const body = await req.json().catch(() => ({}))
  const { groupId, slug, title, routePath, sortOrder, parentPageId } = body
  if (!groupId) return json({ error: 'groupId is required' }, 400)
  const id = crypto.randomUUID()
  try {
    await env.DB.prepare(
      `INSERT INTO generated_pages (id, group_id, slug, title, route_path, sort_order, parent_page_id)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(id, groupId, slug || null, title || null, routePath || null, Number(sortOrder) || 0, parentPageId || null).run()
    return json({ id })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleCreateVersion(req, env) {
  if (!env.ASSETS) return json({ error: 'Asset storage is not configured' }, 500)
  const body = await req.json().catch(() => ({}))
  const { pageId, html, css, js, sourcePrompt, editInstruction, summary } = body
  if (!pageId) return json({ error: 'pageId is required' }, 400)

  try {
    const page = await env.DB.prepare(
      'SELECT group_id, current_version_id FROM generated_pages WHERE id = ?'
    ).bind(pageId).first()
    if (!page) return json({ error: 'Page not found' }, 404)
    const groupId = page.group_id

    const maxRow = await env.DB.prepare(
      'SELECT MAX(version_no) AS max_no FROM generated_page_versions WHERE page_id = ?'
    ).bind(pageId).first()
    const versionNo = (Number(maxRow?.max_no) || 0) + 1

    const keys = versionR2Keys(groupId, pageId, versionNo)
    await env.ASSETS.put(keys.html, html || '', { httpMetadata: { contentType: 'text/html; charset=utf-8' } })
    await env.ASSETS.put(keys.css, css || '', { httpMetadata: { contentType: 'text/css; charset=utf-8' } })
    await env.ASSETS.put(keys.js, js || '', { httpMetadata: { contentType: 'text/javascript; charset=utf-8' } })

    const versionId = crypto.randomUUID()
    await env.DB.prepare(
      `INSERT INTO generated_page_versions
        (id, page_id, version_no, source_prompt, edit_instruction, html_r2_key, css_r2_key, js_r2_key, summary, created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      versionId, pageId, versionNo, sourcePrompt || null, editInstruction || null,
      keys.html, keys.css, keys.js, summary || null, null
    ).run()

    await env.DB.prepare(
      "UPDATE generated_pages SET current_version_id = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(versionId, pageId).run()

    await env.DB.prepare(
      `INSERT INTO page_edit_events (id, page_id, from_version_id, to_version_id, operation, instruction)
       VALUES (?,?,?,?,?,?)`
    ).bind(
      crypto.randomUUID(), pageId, page.current_version_id || null, versionId,
      editInstruction ? 'edit' : 'create', editInstruction || null
    ).run()

    return json({ versionId, versionNo })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleGetVersionContent(req, env, id) {
  if (!env.ASSETS) return json({ error: 'Asset storage is not configured' }, 500)
  try {
    const row = await env.DB.prepare(
      'SELECT html_r2_key, css_r2_key, js_r2_key FROM generated_page_versions WHERE id = ?'
    ).bind(id).first()
    if (!row) return json({ error: 'Version not found' }, 404)

    async function readKey(key) {
      if (!key) return ''
      const object = await env.ASSETS.get(key)
      if (!object) return ''
      return await object.text()
    }

    const [html, css, js] = await Promise.all([
      readKey(row.html_r2_key),
      readKey(row.css_r2_key),
      readKey(row.js_r2_key),
    ])
    return json({ html, css, js })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleGetPageVersions(req, env, id) {
  try {
    const rows = await env.DB.prepare(
      `SELECT id, version_no, summary, created_at FROM generated_page_versions
       WHERE page_id = ? ORDER BY version_no DESC`
    ).bind(id).all()
    const versions = (rows.results || []).map(r => ({
      id: r.id,
      versionNo: r.version_no,
      summary: r.summary,
      createdAt: r.created_at,
    }))
    return json({ versions })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleDeleteGroup(req, env, id) {
  try {
    await env.DB.prepare(
      "UPDATE generated_page_groups SET deleted_at = datetime('now'), updated_at = datetime('now') WHERE id = ?"
    ).bind(id).run()
    await env.DB.prepare(
      "UPDATE generated_pages SET deleted_at = datetime('now'), updated_at = datetime('now') WHERE group_id = ?"
    ).bind(id).run()
    return json({ ok: true })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleDeletePage(req, env, id) {
  try {
    await env.DB.prepare(
      "UPDATE generated_pages SET deleted_at = datetime('now'), updated_at = datetime('now') WHERE id = ?"
    ).bind(id).run()
    return json({ ok: true })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function deleteGeneratedPageObjects(env, pageId) {
  const versions = await env.DB.prepare(
    'SELECT html_r2_key, css_r2_key, js_r2_key FROM generated_page_versions WHERE page_id = ?'
  ).bind(pageId).all()

  for (const v of versions.results || []) {
    for (const key of [v.html_r2_key, v.css_r2_key, v.js_r2_key]) {
      if (key) await env.ASSETS.delete(key)
    }
  }

  await env.DB.prepare('DELETE FROM generated_page_versions WHERE page_id = ?').bind(pageId).run()
  await env.DB.prepare('DELETE FROM page_edit_events WHERE page_id = ?').bind(pageId).run()
  await env.DB.prepare('DELETE FROM generated_pages WHERE id = ?').bind(pageId).run()
}

async function cleanupGeneratedPages(env, opts = {}) {
  if (!env.DB || !env.ASSETS) return { ok: false, error: 'Storage is not configured' }

  const olderThanDays = Math.max(1, Math.min(365, Number(opts.olderThanDays) || 7))
  const limit = Math.max(1, Math.min(500, Number(opts.limit) || 50))
  const cutoff = `-${olderThanDays} days`
  const deletedPages = []

  const groups = await env.DB.prepare(
    "SELECT id FROM generated_page_groups WHERE deleted_at IS NOT NULL AND deleted_at < datetime('now', ?) LIMIT ?"
  ).bind(cutoff, limit).all()

  const candidates = groups.results || []
  const deletedGroups = []
  const failed = []

  const stalePages = await env.DB.prepare(
    `SELECT p.id FROM generated_pages p
     LEFT JOIN generated_page_groups g ON g.id = p.group_id
     WHERE p.deleted_at IS NOT NULL
       AND p.deleted_at < datetime('now', ?)
       AND g.deleted_at IS NULL
     LIMIT ?`
  ).bind(cutoff, limit).all()

  for (const page of stalePages.results || []) {
    try {
      await deleteGeneratedPageObjects(env, page.id)
      deletedPages.push(page.id)
    } catch (e) {
      failed.push({ id: page.id, error: e.message })
    }
  }

  for (const group of candidates) {
    try {
      const pages = await env.DB.prepare(
        'SELECT id FROM generated_pages WHERE group_id = ?'
      ).bind(group.id).all()

      for (const page of pages.results || []) {
        await deleteGeneratedPageObjects(env, page.id)
      }

      await env.DB.prepare('DELETE FROM generated_page_groups WHERE id = ?').bind(group.id).run()
      deletedGroups.push(group.id)
    } catch (e) {
      failed.push({ id: group.id, error: e.message })
    }
  }

  return { ok: failed.length === 0, deletedGroups, deletedPages, failed }
}

// ── Route handlers ──

async function handleLogin(req, env) {
  let body
  try { body = await req.json() } catch (e) { return json({ error: '请求体解析失败: ' + e.message }, 400) }
  const { username, password } = body

  if (!env.DB) return json({ error: 'D1 database binding missing' }, 500)
  if (!env.JWT_SECRET) return json({ error: 'JWT_SECRET not configured' }, 500)

  try {
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first()
    if (!user) return json({ error: '用户名或密码不正确' }, 401)

    const [salt, storedHash] = user.password_hash.split(':')
    const hash = await hashPassword(salt, password)
    if (hash !== storedHash) return json({ error: '用户名或密码不正确' }, 401)

    const token = await signJWT(
      { sub: username, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 },
      env.JWT_SECRET
    )
    return json({ token })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleGetBoard(req, env) {
  try {
    const state = await env.DB.prepare('SELECT transform FROM board_state WHERE id = 1').first()
    const cards = await env.DB.prepare('SELECT * FROM cards ORDER BY created_at').all()
    const transform = state ? JSON.parse(state.transform) : { x: 0, y: 0, scale: 1 }
    const settings = await loadJsonSetting(env, 'provider_settings')
    const uiSettings = await loadJsonSetting(env, 'ui_settings')

    const mapped = cards.results.map(row => {
      const content = JSON.parse(row.content)
      const card = { id: row.id, type: row.type, x: row.x, y: row.y, w: row.w, h: row.h, ...content }
      if (row.linked_to) card.linkedTo = row.linked_to
      return card
    })

    return json({ cards: mapped, transform, settings, uiSettings })
  } catch (e) {
    return json({ cards: [], transform: { x: 0, y: 0, scale: 1 } })
  }
}

async function handleSaveBoard(req, env) {
  const { cards, transform, settings, uiSettings } = await req.json()

  try {
    await env.DB.prepare('UPDATE board_state SET transform = ? WHERE id = 1')
      .bind(JSON.stringify(transform)).run()
    await saveJsonSetting(env, 'provider_settings', settings)
    await saveJsonSetting(env, 'ui_settings', uiSettings)

    const existing = await env.DB.prepare('SELECT id FROM cards').all()
    const existingIds = new Set(existing.results.map(r => r.id))
    const incomingIds = new Set(cards.map(c => c.id))

    for (const id of existingIds) {
      if (!incomingIds.has(id)) {
        await env.DB.prepare('DELETE FROM cards WHERE id = ?').bind(id).run()
        await env.DB.prepare('DELETE FROM images WHERE card_id = ?').bind(id).run()
      }
    }

    for (const card of cards) {
      const { id, type, x, y, w, h, linkedTo, ...rest } = card
      const content = JSON.stringify(rest)

      if (existingIds.has(id)) {
        await env.DB.prepare(
          'UPDATE cards SET type=?, x=?, y=?, w=?, h=?, content=?, linked_to=?, updated_at=datetime(\'now\') WHERE id=?'
        ).bind(type, x, y, w, h, content, linkedTo || null, id).run()
      } else {
        await env.DB.prepare(
          'INSERT INTO cards (id, type, x, y, w, h, content, linked_to) VALUES (?,?,?,?,?,?,?,?)'
        ).bind(id, type, x, y, w, h, content, linkedTo || null).run()
      }
    }

    await syncAssetReferences(cards, env)

    return json({ ok: true })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleUpload(req, env) {
  const { data, filename, contentType } = await req.json()
  if (!data) return json({ error: '没有收到图片数据' }, 400)

  const id = crypto.randomUUID()
  const parsed = parseDataUrl(data)
  if (!parsed) return json({ error: '图片格式无效' }, 400)
  const resolvedContentType = contentType || parsed.contentType || 'image/jpeg'

  if (env.ASSETS) {
    const ext = extForContentType(resolvedContentType)
    const date = new Date()
    const objectKey = `images/${date.getUTCFullYear()}/${String(date.getUTCMonth() + 1).padStart(2, '0')}/${id}.${ext}`
    const publicUrl = assetPublicUrl(env, objectKey, id)

    await env.ASSETS.put(objectKey, parsed.bytes, {
      httpMetadata: { contentType: resolvedContentType },
      customMetadata: {
        assetId: id,
        filename: filename || '',
        contentType: resolvedContentType,
      },
    })

    try {
      await env.DB.prepare(
        `INSERT INTO assets (id, r2_key, public_url, filename, content_type, size, created_at)
         VALUES (?,?,?,?,?,?,datetime('now'))`
      ).bind(id, objectKey, publicUrl, filename || '', resolvedContentType, parsed.bytes.length).run()
    } catch {}

    return json({
      url: publicUrl,
      publicUrl,
      assetId: id,
      imageKey: objectKey,
      key: objectKey,
      storage: 'r2',
      contentType: resolvedContentType,
      size: parsed.bytes.length,
    })
  }

  await env.DB.prepare(
    'INSERT INTO images (id, data, filename, content_type) VALUES (?,?,?,?)'
  ).bind(id, data, filename, resolvedContentType).run()

  return json({ url: `/api/images/${id}`, storage: 'd1', contentType: resolvedContentType })
}

async function handleGetImage(req, env, id) {
  const row = await env.DB.prepare('SELECT data, content_type FROM images WHERE id = ?').bind(id).first()
  if (!row) return new Response('未找到图片', { status: 404, headers: CORS })

  const parsed = parseDataUrl(row.data)
  if (!parsed) return new Response('图片格式无效', { status: 400, headers: CORS })

  return new Response(parsed.bytes, {
    headers: { 'Content-Type': row.content_type || parsed.contentType, ...CORS }
  })
}

async function handleGetAsset(req, env, id) {
  const row = await getAssetById(env, id)
  if (!row || !env.ASSETS) return new Response('未找到图片', { status: 404, headers: CORS })

  const object = await env.ASSETS.get(row.r2_key)
  if (!object) return new Response('未找到图片', { status: 404, headers: CORS })

  return new Response(object.body, {
    headers: {
      'Content-Type': object.httpMetadata?.contentType || row.content_type || 'application/octet-stream',
      'Cache-Control': 'public, max-age=31536000, immutable',
      ...CORS,
    }
  })
}

// Resolve Worker image URLs to data URLs so external APIs can access them
async function resolveImageUrl(imageUrl, env) {
  if (!imageUrl) return imageUrl

  const assetRouteMatch = imageUrl.match(/\/api\/assets\/([^/?#]+)/)
  if (assetRouteMatch) {
    const asset = await getAssetById(env, assetRouteMatch[1])
    if (asset && env.ASSETS) {
      const object = await env.ASSETS.get(asset.r2_key)
      return await r2ObjectToDataUrl(object) || imageUrl
    }
  }

  const publicKey = keyFromPublicUrl(imageUrl, env)
  if (publicKey && env.ASSETS) {
    const object = await env.ASSETS.get(publicKey)
    return await r2ObjectToDataUrl(object) || imageUrl
  }

  const match = imageUrl.match(/\/api\/images\/([^/?#]+)/)
  if (match) {
    const row = await env.DB.prepare('SELECT data FROM images WHERE id = ?').bind(match[1]).first()
    return row?.data || imageUrl
  }

  return imageUrl
}

async function handleAI(req, env) {
  const {
    mode = 'single',
    imageUrl,
    images = [],
    analyses = [],
    notes = [],
    context,
    provider = 'qwen',
    apiKey,
    model,
    baseUrl,
    lmstudioUrl,
    ollamaUrl,
    // Reference-driven page generation fields
    target = '',
    platform = 'web',
    maxPages = 5,
    referenceMode = 'strict',
    generationScope = 'core',
    appName = '',
    designIntent = '',
    globalStyle = null,
    page = null,
    current = null,
    instruction = '',
  } = await req.json()

  // Platform → concrete layout / viewport constraints injected into prompts.
  function platformSpec(p) {
    if (p === 'app') return {
      label: 'App 移动端（iOS/Android 原生风格）',
      rules: '画布按移动端竖屏设计，视口宽度 375–430px；根容器 max-width:430px、margin:0 auto、min-height:100vh；触控友好（点击区 ≥44px）；底部 tabbar / 顶部 navbar 按需要；不要桌面多列布局。',
    }
    if (p === 'miniprogram') return {
      label: '微信小程序',
      rules: '画布按微信小程序设计，视口宽度 375px；根容器 max-width:375px、margin:0 auto；预留顶部胶囊/导航高度；卡片化、圆角、留白克制；触控友好；不要桌面多列布局、不要浏览器地址栏式元素。',
    }
    return {
      label: 'Web 网页（桌面优先，响应式）',
      rules: '桌面优先并响应式；内容容器 max-width 960–1200px 居中；可用多列/栅格布局；适配窄屏断点。',
    }
  }
  const pf = platformSpec(platform)
  const pageLimit = Math.max(1, Math.min(8, Number.parseInt(maxPages, 10) || 5))
  const planScope = generationScope === 'single' ? 'single' : 'core'
  const effectivePageLimit = planScope === 'single' ? 1 : pageLimit
  const refMode = referenceMode === 'balanced' ? 'balanced' : 'strict'
  const referenceRule = refMode === 'strict'
    ? '严格沿用设计 DNA 与大爆炸具体因子：优先复用其中出现的具体色值、字体、字号、圆角、阴影、间距、动效参数和组件结构；如果证据不足，可以补齐功能，但不要另起一套视觉风格。'
    : '适度迁移设计 DNA 与大爆炸具体因子：保留核心色调、质感、密度、组件语言和关键视觉比例；允许为了目标产品调整信息架构和局部组件。'
  const evidencePriority = '证据优先级：1) style-group / aesthetic DNA 与 design-bubbles（大爆炸）里的具体设计因子是 UI 生成主输入；2) target、platform、page 规划用于决定产品结构；3) 图像提示词、图片描述、单图 AI 分析、用户备注只作为辅助语义证据，不能覆盖 DNA / 大爆炸中的具体视觉数值。'
  const explosionDimensionGuide = `维度必须尽量覆盖：上下文目的、主体/内容、构图与视觉层级、布局/网格/空间、色彩/光影/对比、字体与文本、组件和状态、材质/纹理/质感、动效/交互、可迁移 CSS 参数、反向约束/不要做。`
  const explosionCategoryRule = 'category 只能是：上下文、主体内容、构图层级、布局空间、色彩光影、字体文本、组件状态、材质质感、动效交互、CSS参数、反向约束。'

  function buildSinglePrompt() {
    const systemPrompt = `你是一名资深 UI 设计分析师。请把产品/UI 图片分析成可复用的设计情报，要求具体、结构化、可执行。`
    const userPrompt = context
      ? `用户补充背景："${context}"\n\n请严格按照下面的 Markdown 结构分析这张图片。`
      : `请严格按照下面的 Markdown 结构分析这张图片。`
    const format = `
# 单图参考分析

## 界面类型
- 判断这可能是什么页面、组件或产品界面。

## 核心风格
- 3-5 个关键词。
- 用一句话描述它的设计人格。

## 布局结构
- 构图、层级、信息密度、留白和视觉焦点。

## 视觉系统
- 可见时给出色板和十六进制颜色。
- 字体气质、字号层级、字重和行高。
- 圆角、描边、阴影、模糊、纹理和背景处理。

## 组件模式
- 按钮、卡片、导航、输入框、工具栏、图表、标签或内容区块。

## 高级感来源
- 具体说明它如何制造品质感、信任感或价格感。

## 可复用规则
- 4-6 条可以复用到其他 app 的可执行设计规则。

## 提示词片段
- 可用于 AI 生成 UI 的短语。`
    return { systemPrompt, userPrompt: `${userPrompt}\n${format}`, imageUrls: imageUrl ? [imageUrl] : [] }
  }

  function buildGroupPrompt() {
    const imageUrls = images.map(img => img.imageUrl).filter(Boolean).slice(0, 8)
    const analysisText = analyses.map((item, i) => `分析 ${i + 1}：\n${item.text}`).join('\n\n')
    const noteText = notes.map((item, i) => `备注 ${i + 1}：${item.text}`).join('\n')
    const systemPrompt = `你是一名资深产品设计总监。请把一组 UI 参考图综合成可落地的设计 DNA，用于构建一个有高级感的 app。重点提炼共同规律和可复用规范，不要逐图流水账描述。`
    const userPrompt = `请根据附带的 UI 参考图、已有分析和备注，推断这一组素材共同的设计方向。

${context || ''}

${noteText ? `用户备注：\n${noteText}` : ''}

${analysisText ? `已有单图分析：\n${analysisText}` : ''}

请用简洁中文 Markdown 输出，严格包含下面这些部分：

# 设计 DNA

## 1. 核心风格
- 用一句话总结整体审美。
- 给出 3-5 个风格关键词。

## 2. 视觉系统
- 可见时给出色板和十六进制颜色。
- 字体气质和层级。
- 布局、留白、密度、圆角、描边、阴影。
- 图标、图片和组件处理方式。

## 3. 可复用模式
- 4-7 条可以直接复用的界面设计规则。

## 4. 高级感来源
- 解释它为什么显得有品质、有信任感、有价格感。

## 5. 应该做 / 不要做
- 应该做：
- 不要做：

## 6. 给 Codex / Claude Code / v0 的实现简报
- 写成可以直接给 AI 编程工具执行的页面目标、组件清单、布局规则、视觉规范和交互要求。

## 7. 可直接复制的实现提示词
- 写一段完整提示词，要求 AI 编程工具根据上面的设计 DNA 直接实现界面。
- 提示词必须包含：产品类型、目标用户、页面/组件、布局、颜色、字体、间距、圆角、阴影、交互状态、响应式要求、不要做什么。
- 提示词可以使用中文，但需要足够具体，让 Codex 或 Claude Code 能直接开始写代码。`
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildTextExplosionPrompt() {
    const systemPrompt = `你是一名资深 UI 设计分析师。用户会用文字描述一个让他印象深刻的设计、界面、图片或产品体验。请根据描述拆解出极其具体的 design-bubbles（大爆炸）设计因子。这些因子会作为后续 UI 生成主链路的核心视觉证据，并与 style-group / aesthetic DNA 一起优先于普通图像提示词、图片描述和 AI 分析。每条必须包含可直接写入 CSS/代码的数值，禁止模糊形容词。`
    const userPrompt = `用户描述：
"${context || ''}"

请根据这段文字描述，提取 14-18 个**极其具体**的设计因子。要求：
- ${explosionDimensionGuide}
- 每条因子都要说明它服务的画面目的、界面主体或迁移价值之一，避免只写感受词。
- 色彩类：具体十六进制色号（如 #1A1A2E），说明用在哪个元素上
- 字体类：字体族名、字号（px）、字重、行高、字间距
- 结构类：间距（px）、圆角（px）、栅格、最大宽度
- 质感类：具体 CSS 值 — box-shadow、backdrop-filter、渐变色值
- 组件类：组件尺寸、颜色、圆角、间距的具体数值
- 动效类：缓动函数、时长、动画属性
- 高级感类：具体实现手法而非抽象感受
- 反向约束：明确 2-3 条不要做的视觉偏差，例如不要改成高饱和渐变、不要使用默认卡片阴影、不要破坏主次层级

禁止"简洁""现代""高级""优雅"等模糊词。每条必须可直接写 CSS。

尽量只返回 JSON 数组，不要长段落。
格式：
[
  {"category":"色彩光影","label":"深灰主文字 #1A1A2E","reason":"正文用深灰而非纯黑，降低对比度疲劳","prompt":"正文颜色 color: #1A1A2E，标题 #111111，次要信息 #8C8C8C。"},
  {"category":"材质质感","label":"8px柔光投影","reason":"卡片浮起感来自低扩散阴影","prompt":"box-shadow: 0 2px 8px rgba(0,0,0,0.06), 0 8px 24px rgba(0,0,0,0.04); border-radius: 16px。"},
  {"category":"反向约束","label":"不要默认灰卡片","reason":"默认灰卡片会破坏描述中的轻盈层级","prompt":"避免 background:#f5f5f5 + box-shadow:0 1px 3px rgba(0,0,0,.1) 的默认卡片；保留低对比背景与柔光阴影。"}
]
${explosionCategoryRule}
label 必须 2-8 个中文词（色彩类带色号、字体类带参数），适合显示在小气泡里。
prompt 必须是可直接复制为 CSS/代码的实现指令，包含具体数值。
即使描述抽象，也必须推断出具体数值。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  function buildVideoExplosionPrompt() {
    const systemPrompt = `你是一名资深交互与动效设计分析师。用户提供了一段界面录屏的关键帧截图，请拆解出极其具体的 design-bubbles（大爆炸）设计因子。这些因子会作为后续 UI 生成主链路的核心视觉与交互证据，并与 style-group / aesthetic DNA 一起优先于普通图像提示词、图片描述和 AI 分析。每条必须包含可直接写入 CSS/JS 的数值，禁止模糊形容词。`
    const userPrompt = `${context ? `用户补充说明："${context}"\n\n` : ''}以下是从一段界面录屏中提取的关键帧。请提取 14-18 个**极其具体**的因子，重点关注动效和质感：
- ${explosionDimensionGuide}
- 上下文目的：判断这段动效服务的是进入、切换、反馈、确认、导航还是状态变化
- 主体/内容：说明关键 UI 主体、文本内容、按钮/卡片/导航/图表等对象如何变化
- 构图与视觉层级：说明动效前后视觉焦点、主次关系、遮罩/浮层/背景层变化
- 转场：具体 CSS transition/animation 属性、时长（ms）、缓动函数（cubic-bezier 值）
- 动画：具体 keyframes、transform 值、opacity 变化范围
- 交互反馈：hover/active/focus 的具体样式变化（scale 值、颜色变化、阴影变化）
- 视觉节奏：具体延迟间隔（stagger delay）、动画编排顺序
- 色彩/质感：具体十六进制色号、backdrop-filter 值、box-shadow 值、渐变色值
- 反向约束：明确不要做的动效偏差，例如不要线性匀速、不要过度弹跳、不要让背景层抢焦点

禁止"流畅""自然""优雅"等模糊词。每条必须可直接写 CSS/JS。

尽量只返回 JSON 数组，不要长段落。
格式：
[
  {"category":"动效交互","label":"300ms弹性页面转场","reason":"页面切换有弹性回弹感","prompt":"transition: transform 300ms cubic-bezier(0.34, 1.56, 0.64, 1); 页面进入时 translateX(100%) 到 translateX(0)。"},
  {"category":"材质质感","label":"20px毛玻璃白层","reason":"多层半透明叠加营造深度","prompt":"backdrop-filter: blur(20px) saturate(1.2); background: rgba(255,255,255,0.72); border: 1px solid rgba(255,255,255,0.3)。"},
  {"category":"反向约束","label":"不要线性硬切换","reason":"线性切换会削弱关键帧里的缓入缓出节奏","prompt":"避免 transition-timing-function: linear；页面级转场使用 cubic-bezier(0.34,1.56,0.64,1)，透明度与位移错开 40ms。"}
]
${explosionCategoryRule}
label 必须 2-8 个中文词（带关键数值），适合显示在小气泡里。
prompt 必须是可直接复制为 CSS/JS 代码的实现指令。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildDesignExplosionPrompt() {
    const systemPrompt = `你是一名资深 UI 设计分析师。请把图片拆解成极其具体的 design-bubbles（大爆炸）设计因子。这些因子会作为后续 UI 生成主链路的核心视觉证据，并与 style-group / aesthetic DNA 一起优先于普通图像提示词、图片描述和 AI 分析。每条必须包含可直接写入 CSS/代码的数值，禁止模糊形容词。`
    const userPrompt = `${context ? `用户补充说明："${context}"\n\n` : ''}请把这个素材拆成 14-18 个**极其具体**的设计因子。要求：
- ${explosionDimensionGuide}
- 上下文目的：判断这张图片/界面服务的场景、用户任务、情绪目标或商业目标
- 主体/内容：指出画面主体、核心信息、内容类型、关键文本和可迁移到 UI 的对象
- 构图与视觉层级：说明主视觉焦点、视线路径、前中后景、层级关系和对齐方式
- 布局/网格/空间：给出容器宽度、栅格、间距、留白比例、内容密度和边界处理
- 色彩类：具体十六进制色号（如 #1A1A2E、#E8E3D9），说明用在哪里（背景/文字/强调/边框），给出主色、辅色、点缀色
- 光影/对比：说明明暗关系、对比度、投影方向、透明度和背景层处理
- 字体类：字体族名（如 SF Pro、思源黑体）、字号（如 14px/28px）、字重（如 400/600/700）、行高（如 1.5）、字间距（如 0.02em）
- 文本类：说明标题/正文/标签/数字/按钮文案的长度、层级和排版规则
- 结构类：间距（如 padding 16px 20px）、圆角（如 border-radius 16px）、栅格列数、内容最大宽度
- 质感类：具体 CSS 值 — 阴影（如 box-shadow: 0 4px 24px rgba(0,0,0,0.08)）、模糊度、透明度、渐变方向和色值
- 材质/纹理：说明玻璃、纸张、金属、噪点、描边、颗粒、图片处理等质感如何用 CSS 近似
- 组件与状态：按钮尺寸/圆角/颜色、卡片间距/边框、导航高度/布局，以及 hover/active/selected/disabled/loading/empty/error 状态
- 动效类：缓动函数（如 cubic-bezier(0.4, 0, 0.2, 1)）、时长（如 200ms）、属性（transform/opacity）
- 可迁移 CSS 参数：把图片中的关键视觉规律转成可复制的 CSS/HTML 规则
- 反向约束：明确 2-3 条不要做的视觉偏差，例如不要使用默认蓝色按钮、不要高饱和渐变、不要把留白压缩成信息流

禁止使用"简洁"、"现代"、"高级"、"优雅"等模糊形容词。每个因子必须具体到可以直接写 CSS。

只返回 JSON 数组，不要其他文字。
格式：
[
  {"category":"色彩光影","label":"深灰主文字 #1A1A2E","reason":"正文用深灰而非纯黑，降低对比度疲劳","prompt":"正文颜色 color: #1A1A2E，标题 #111111，次要信息 #8C8C8C。"},
  {"category":"字体文本","label":"SF Pro 16/24 W500","reason":"正文 16px 配 1.5 行高，medium 字重保证可读性","prompt":"font-family: 'SF Pro Display', -apple-system; font-size: 16px; line-height: 24px; font-weight: 500。"},
  {"category":"材质质感","label":"8px柔光投影","reason":"卡片浮起感来自低扩散阴影","prompt":"box-shadow: 0 2px 8px rgba(0,0,0,0.06), 0 8px 24px rgba(0,0,0,0.04); border-radius: 16px。"},
  {"category":"反向约束","label":"不要默认蓝按钮","reason":"默认蓝色主按钮会破坏素材里的低饱和色彩系统","prompt":"避免使用 #1677ff / #0d6efd 作为主按钮；按钮使用素材主色或中性色系统，并保持 border-radius 与卡片一致。"}
]
${explosionCategoryRule}
label 必须 2-8 个中文词（色彩类带色号、字体类带参数），适合显示在小气泡里。
prompt 必须是可直接复制为 CSS/代码的实现指令，包含具体数值。`
    return { systemPrompt, userPrompt, imageUrls: imageUrl ? [imageUrl] : [] }
  }

  function buildPolishPrompt() {
    return {
      systemPrompt: '你是一名资深设计文案编辑。请润色用户提供的文案，保留原始结构和内容，让表达更流畅自然。',
      userPrompt: context || '',
      imageUrls: [],
    }
  }

  function buildPagePlanPrompt() {
    const systemPrompt = `你是一名资深产品设计总监。你将根据已有的 style-group / aesthetic DNA 与 design-bubbles（大爆炸）具体因子，为一个 ${pf.label} 产品规划页面结构。
要求：
- 根据产品目标自行判断合理的页面数量，但最多 ${effectivePageLimit} 个页面；覆盖核心流程即可，合并低价值或重复页面，宁少勿滥。
- 当前生成范围：${planScope === 'single' ? '单页探索，只规划 1 个最关键页面。' : '核心流程，规划能闭环的关键页面。'}
- 目标平台为「${pf.label}」，规划必须贴合该平台的形态：${pf.rules}
- ${evidencePriority}
- ${referenceRule}
- 设计 DNA / 大爆炸具体因子是**视觉基线**，globalStyle 必须从中提炼（保留其中的十六进制色值、字体、圆角、阴影、间距等具体数值），不要凭空发明风格。
- 把图像提示词、图片描述、单图 AI 分析、用户备注都当作"辅助语义证据"，而不是必须照做的 UI 生成指令。
- 只输出页面规划的设计层信息，绝对不要输出任何 HTML / CSS / JS 代码。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要额外说明文字。`
    const userPrompt = `生成目标（target）："${target || ''}"
目标平台（platform）：${pf.label}

设计 DNA / 大爆炸因子 / 辅助语义证据（按证据优先级读取，globalStyle 必须优先从 DNA 与大爆炸具体因子提炼具体数值）：
${context || '（无）'}

请输出严格符合下面结构的 JSON（字段名、层级必须完全一致）：
{
  "appName": "",
  "designIntent": "",
  "globalStyle": {
    "layout": "",
    "palette": [],
    "typography": "",
    "componentRules": [],
    "motionRules": [],
    "avoid": []
  },
  "pages": [
    {
      "id": "home",
      "title": "",
      "route": "/",
      "purpose": "",
      "sections": [],
      "components": [],
      "states": [],
      "responsiveNotes": "",
      "evidenceIds": []
    }
  ]
}

约束：
- 页面数量必须在 1-${effectivePageLimit} 个之间。${planScope === 'single' ? '只能输出 1 个页面。' : '超过上限时合并次要页面。'}
- appName / designIntent 用简洁中文概括产品与设计意图。
- globalStyle 必须从设计 DNA 与大爆炸具体因子中提炼出可复用的全局规范，并尽量保留主证据里的**具体数值**（色板十六进制、字体族与字号、圆角、阴影、间距、动效缓动）。
- 图像提示词、图片描述、单图 AI 分析只能帮助理解产品语义和氛围，不得作为主要视觉规范。
- globalStyle.layout 要体现 ${pf.label} 的形态约束。
- 每个 page 的 sections / components / states 用具体短语数组。
- 不要输出任何代码。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildPageGeneratePrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle, null, 2) : '（无，按 designIntent 自行合理推断）'
    const pageStr = page ? JSON.stringify(page, null, 2) : '（无）'
    const systemPrompt = `你是一名资深 UI 工程师，能把参考视觉精确迁移到可运行界面。你将为一个 ${pf.label} 产品的"单个页面"生成完整、自包含、可直接预览的前端代码。
要求：
- 目标平台「${pf.label}」：${pf.rules}
- ${evidencePriority}
- **设计 DNA 与大爆炸具体因子是最高优先级的视觉规范**：${referenceRule} 必须把下方主证据里的具体数值（十六进制色值、字体族/字号/字重、圆角、阴影 box-shadow、间距、渐变、毛玻璃等）直接落到 CSS 上。globalStyle 是它的结构化摘要，二者冲突时以 DNA / 大爆炸具体因子为准。
- 图像提示词、图片描述、单图 AI 分析只用于理解内容主题、对象语义和氛围方向，不得覆盖主证据里的 CSS 数值和组件语言。
- 不要输出"默认浏览器风格"的简陋页面：要有完整的配色、排版层级、留白、组件细节、hover/active 状态与微交互。
- 页面必须自包含、覆盖常见状态（加载 / 空 / 错误 / 交互态，参考 page.states）。
- 使用语义化 HTML、现代 CSS；JS 只为必要交互，不依赖任何外部脚本或 CDN（可用 data-uri / 纯 CSS 占位图，不要外链图片）。
- notes 必须写出 3-6 条“DNA 到代码”的映射，例如某个色值用于哪个元素、某个圆角/阴影如何落地。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要额外说明文字。`
    const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}

设计 DNA / 大爆炸因子 / 辅助语义证据（DNA 与大爆炸具体因子是最高优先级视觉规范；图像提示词/图片描述/AI 分析仅作辅助语义证据）：
${context || '（无，按 globalStyle 与 designIntent 合理发挥，仍需有完整精致的视觉）'}

全局风格摘要（globalStyle）：
${styleStr}

当前要生成的页面（page）：
${pageStr}

请输出严格符合下面结构的 JSON（字段名必须完全一致）：
{
  "pageId": "home",
  "title": "",
  "html": "",
  "css": "",
  "js": "",
  "notes": [],
  "validationChecklist": []
}

约束：
- pageId 与 page.id 保持一致。
- html / css / js 为该页面的完整代码字符串（html 不含 <style>/<script>，分别放入 css 与 js）。
- 布局必须符合 ${pf.label} 的视口与容器约束（见上方平台规则）。
- 必须实现 page.sections 与 page.components，并覆盖 page.states 描述的状态。
- 按参考约束执行：${referenceRule}
- 严格复用设计 DNA 与大爆炸具体因子的具体数值（色板十六进制、字体、圆角、阴影、间距、渐变）；遵守 globalStyle.avoid 列表。
- 不要把图像提示词或图片描述当成 UI 生成主 prompt；它们只补充语义和内容方向。
- 成品要体现参考素材的视觉基线，避免简陋的无样式默认外观。
- notes 说明“DNA 到代码”的映射，validationChecklist 给出可自检的验收项。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildPageEditPrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle, null, 2) : '（无，保持现状）'
    const pageStr = page ? JSON.stringify(page, null, 2) : '（无）'
    const cur = current || {}
    const systemPrompt = `你是一名资深 UI 工程师。你将根据用户指令修改一个已有页面，并输出"全量替换"的完整页面代码。
要求：
- 仅按 instruction 修改对应内容；不要改动与指令无关的部分。
- 除非 instruction 明确要求改变风格，否则保持原有 globalStyle 全局风格不变。
- ${evidencePriority}
- 参考约束：${referenceRule}
- 输出仍是完整、自包含、响应式、覆盖状态的单页面代码（全量替换，而非补丁）。
- notes 必须说明本次修改如何保留或调整设计 DNA / 大爆炸具体因子；若使用图像提示词、图片描述或 AI 分析，只能说明其辅助语义作用。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要额外说明文字。`
    const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}（${pf.rules}）

设计 DNA / 大爆炸因子 / 辅助语义证据（DNA 与大爆炸具体因子是视觉基线；除非指令要求否则不偏离其具体数值；图像提示词/图片描述/AI 分析仅作辅助语义证据）：
${context || '（无）'}

全局风格摘要（globalStyle，除非指令要求否则保持不变）：
${styleStr}

页面规划（page）：
${pageStr}

当前页面代码（current）：
HTML:
${cur.html || ''}

CSS:
${cur.css || ''}

JS:
${cur.js || ''}

用户修改指令（instruction）：
"${instruction || ''}"

请输出严格符合下面结构的 JSON（字段名必须完全一致），作为该页面的全量替换：
{
  "pageId": "home",
  "title": "",
  "html": "",
  "css": "",
  "js": "",
  "notes": [],
  "validationChecklist": []
}

约束：
- 只改与 instruction 相关的部分，保留其余内容。
- 保持 globalStyle，除非指令明确要求修改风格。
- html / css / js 为修改后的完整代码字符串（全量）。
- notes 说明本次改动，validationChecklist 给出可自检的验收项。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  const prompt = mode === 'polish' ? buildPolishPrompt() : mode === 'video-explosion' ? buildVideoExplosionPrompt() : mode === 'text-explosion' ? buildTextExplosionPrompt() : mode === 'design-explosion' ? buildDesignExplosionPrompt() : mode === 'group' ? buildGroupPrompt() : mode === 'page-plan' ? buildPagePlanPrompt() : mode === 'page-generate' ? buildPageGeneratePrompt() : mode === 'page-edit' ? buildPageEditPrompt() : buildSinglePrompt()

  // Determine if this task needs a vision model or pure LLM
  const needsVision = prompt.imageUrls.length > 0 || mode === 'single' || mode === 'video-explosion'

  // Default models per provider — auto-select VL vs LLM
  const MODEL_DEFAULTS = {
    modelscope: { vl: 'Qwen/Qwen3-VL-235B-A22B-Instruct', llm: 'Qwen/Qwen3-235B-A22B' },
    qwen:       { vl: 'qwen-vl-max',                    llm: 'qwen-max' },
    deepseek:   { vl: 'deepseek-chat',                   llm: 'deepseek-chat' },
    zhipu:      { vl: 'glm-4v',                          llm: 'glm-4-plus' },
  }
  const defaults = MODEL_DEFAULTS[provider] || MODEL_DEFAULTS.modelscope
  const resolvedModel = model || (needsVision ? defaults.vl : defaults.llm)

  // Resolve Worker image URLs to data URLs so external APIs can fetch them
  const resolvedImages = await Promise.all(
    prompt.imageUrls.map(url => resolveImageUrl(url, env))
  )

  try {
    let result = ''

    async function callOpenAICompat(apiUrl, apiKey, modelName) {
      if (!apiKey) return '缺少接口密钥，请在设置中填写。'
      const content = needsVision
        ? [
            { type: 'text', text: `${prompt.systemPrompt}\n\n${prompt.userPrompt}` },
            ...resolvedImages.map(url => ({ type: 'image_url', image_url: { url } })),
          ]
        : `${prompt.systemPrompt}\n\n${prompt.userPrompt}`
      // Explosion + page modes return JSON — force JSON output format
      const wantsJson = ['text-explosion', 'video-explosion', 'design-explosion', 'page-plan', 'page-generate', 'page-edit'].includes(mode)
      const body = {
        model: modelName,
        messages: [{ role: 'user', content }],
        max_tokens: (mode === 'page-generate' || mode === 'page-edit') ? 8192 : mode === 'page-plan' ? 4096 : wantsJson ? 4096 : (mode === 'group' || mode === 'polish') ? 2048 : 1024,
        stream: true,
        enable_thinking: false,
      }
      if (wantsJson) {
        body.response_format = { type: 'json_object' }
      }
      const res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        const errMsg = data.error?.message || data.error?.code || data.message || `HTTP ${res.status}`
        return `AI 请求失败: ${errMsg}`
      }
      // Parse SSE stream and collect content chunks
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let text = ''
      let buffer = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          const payload = line.slice(6).trim()
          if (payload === '[DONE]') continue
          try {
            const chunk = JSON.parse(payload)
            const delta = chunk.choices?.[0]?.delta?.content
            if (delta) text += delta
          } catch {}
        }
      }
      if (!text) {
        console.log(`[AI] Empty streamed response from ${modelName}`)
        return 'AI 返回为空，请检查模型是否可用。'
      }
      return text
    }

    if (provider === 'qwen') {
      const key = apiKey || env.QWEN_API_KEY
      result = await callOpenAICompat(
        'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions',
        key,
        resolvedModel
      )
    } else if (provider === 'deepseek') {
      const key = apiKey || env.DEEPSEEK_API_KEY
      result = await callOpenAICompat(
        'https://api.deepseek.com/v1/chat/completions',
        key,
        resolvedModel
      )
    } else if (provider === 'zhipu') {
      const key = apiKey || env.ZHIPU_API_KEY
      result = await callOpenAICompat(
        'https://open.bigmodel.cn/api/paas/v4/chat/completions',
        key,
        resolvedModel
      )
    } else if (provider === 'modelscope') {
      const key = apiKey || env.MODELSCOPE_API_KEY
      const apiBase = (baseUrl || env.MODELSCOPE_BASE_URL || 'https://api-inference.modelscope.cn/v1').replace(/\/$/, '')
      result = await callOpenAICompat(
        `${apiBase}/chat/completions`,
        key,
        resolvedModel
      )
    } else if (provider === 'lmstudio') {
      const baseUrl = lmstudioUrl || 'http://localhost:1234'
      result = await callOpenAICompat(
        `${baseUrl}/v1/chat/completions`,
        'lm-studio',
        model || 'default'
      )
    } else if (provider === 'ollama') {
      const baseUrl = ollamaUrl || 'http://localhost:11434'
      const b64Images = []
      for (const url of prompt.imageUrls) {
        const imgRes = await fetch(url)
        const imgBuf = await imgRes.arrayBuffer()
        b64Images.push(btoa(String.fromCharCode(...new Uint8Array(imgBuf))))
      }
      const res = await fetch(`${baseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: model || 'llava',
          prompt: `${prompt.systemPrompt}\n\n${prompt.userPrompt}`,
          images: b64Images,
          stream: false
        })
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) return json({ error: data.error || `AI request failed (${res.status})` }, 500)
      result = data.response || '无结果'
    } else {
      return json({ error: 'Unsupported AI provider' }, 400)
    }

    return json({ result })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

// ── Main ──

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      cleanupAssets(env, { olderThanDays: 7, limit: 500 })
        .then(result => console.log('[assets.cleanup]', JSON.stringify(result)))
        .catch(error => console.log('[assets.cleanup] failed', error.message))
    )
    ctx.waitUntil(
      cleanupGeneratedPages(env, { olderThanDays: 7, limit: 500 })
        .then(result => console.log('[generated.cleanup]', JSON.stringify(result)))
        .catch(error => console.log('[generated.cleanup] failed', error.message))
    )
  },

  async fetch(req, env) {
    const url = new URL(req.url)
    const path = url.pathname

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS })
    }

    // Public routes
    if (path === '/api/login' && req.method === 'POST') return handleLogin(req, env)

    if (path.startsWith('/api/images/') && req.method === 'GET') {
      const id = path.slice('/api/images/'.length)
      return handleGetImage(req, env, id)
    }

    if (path.startsWith('/api/assets/') && req.method === 'GET') {
      const id = path.slice('/api/assets/'.length)
      return handleGetAsset(req, env, id)
    }

    // Protected routes
    const user = await authMiddleware(req, env)
    if (!user) return json({ error: '未授权，请重新登录' }, 401)

    if (path === '/api/board' && req.method === 'GET') return handleGetBoard(req, env)
    if (path === '/api/board' && req.method === 'PUT') return handleSaveBoard(req, env)
    if (path === '/api/upload' && req.method === 'POST') return handleUpload(req, env)
    if (path === '/api/assets/cleanup' && req.method === 'POST') return handleCleanupAssets(req, env)
    if (path === '/api/ai' && req.method === 'POST') return handleAI(req, env)

    // Generated pages (Phase 2 durable persistence)
    if (path === '/api/generated/groups' && req.method === 'POST') return handleCreateGroup(req, env)
    if (path === '/api/generated/pages' && req.method === 'POST') return handleCreatePage(req, env)
    if (path === '/api/generated/versions' && req.method === 'POST') return handleCreateVersion(req, env)

    let m
    if ((m = path.match(/^\/api\/generated\/versions\/([^/]+)\/content$/)) && req.method === 'GET') {
      return handleGetVersionContent(req, env, m[1])
    }
    if ((m = path.match(/^\/api\/generated\/pages\/([^/]+)\/versions$/)) && req.method === 'GET') {
      return handleGetPageVersions(req, env, m[1])
    }
    if ((m = path.match(/^\/api\/generated\/pages\/([^/]+)$/)) && req.method === 'DELETE') {
      return handleDeletePage(req, env, m[1])
    }
    if ((m = path.match(/^\/api\/generated\/groups\/([^/]+)$/)) && req.method === 'DELETE') {
      return handleDeleteGroup(req, env, m[1])
    }

    return json({ error: '未找到接口' }, 404)
  }
}
