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

function sanitizeModelText(text) {
  return String(text || '')
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/<thought>[\s\S]*?<\/thought>/gi, '')
    .replace(/^<thought>[\s\S]*?(?=\{|\[|##|#)/i, '')
    .trim()
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

async function loadJsonSetting(env, userId, key) {
  if (!env.DB) return null
  try {
    const row = await env.DB.prepare('SELECT value FROM app_settings WHERE user_id = ? AND key = ?').bind(userId, key).first()
    return row?.value ? JSON.parse(row.value) : null
  } catch {
    return null
  }
}

async function saveJsonSetting(env, userId, key, value) {
  if (!env.DB || value === undefined) return
  await env.DB.prepare(
    `INSERT INTO app_settings (user_id, key, value, updated_at)
     VALUES (?, ?, ?, datetime('now'))
     ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
  ).bind(userId, key, JSON.stringify(value ?? null)).run()
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

async function syncAssetReferences(cards, env, userId) {
  if (!env.DB) return
  let rows
  try {
    rows = await env.DB.prepare('SELECT id, r2_key, public_url, deleted_at FROM assets WHERE user_id = ?').bind(userId).all()
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

async function handleCreateGroup(req, env, userId) {
  const body = await req.json().catch(() => ({}))
  const { cardId, title, promptCardId } = body
  const id = crypto.randomUUID()
  try {
    await env.DB.prepare(
      `INSERT INTO generated_page_groups (id, card_id, title, prompt_card_id, user_id)
       VALUES (?,?,?,?,?)`
    ).bind(id, cardId || null, title || null, promptCardId || null, userId).run()
    return json({ id })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleCreatePage(req, env, userId) {
  const body = await req.json().catch(() => ({}))
  const { groupId, slug, title, routePath, sortOrder, parentPageId } = body
  if (!groupId) return json({ error: 'groupId is required' }, 400)
  const id = crypto.randomUUID()
  try {
    // Ensure the target group belongs to the caller.
    const group = await env.DB.prepare(
      'SELECT id FROM generated_page_groups WHERE id = ? AND user_id = ?'
    ).bind(groupId, userId).first()
    if (!group) return json({ error: 'Group not found' }, 404)
    await env.DB.prepare(
      `INSERT INTO generated_pages (id, group_id, slug, title, route_path, sort_order, parent_page_id, user_id)
       VALUES (?,?,?,?,?,?,?,?)`
    ).bind(id, groupId, slug || null, title || null, routePath || null, Number(sortOrder) || 0, parentPageId || null, userId).run()
    return json({ id })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleCreateVersion(req, env, userId) {
  if (!env.ASSETS) return json({ error: 'Asset storage is not configured' }, 500)
  const body = await req.json().catch(() => ({}))
  const { pageId, html, css, js, sourcePrompt, editInstruction, summary } = body
  if (!pageId) return json({ error: 'pageId is required' }, 400)

  try {
    const page = await env.DB.prepare(
      'SELECT group_id, current_version_id FROM generated_pages WHERE id = ? AND user_id = ?'
    ).bind(pageId, userId).first()
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
        (id, page_id, version_no, source_prompt, edit_instruction, html_r2_key, css_r2_key, js_r2_key, summary, created_by, user_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      versionId, pageId, versionNo, sourcePrompt || null, editInstruction || null,
      keys.html, keys.css, keys.js, summary || null, userId, userId
    ).run()

    await env.DB.prepare(
      "UPDATE generated_pages SET current_version_id = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?"
    ).bind(versionId, pageId, userId).run()

    await env.DB.prepare(
      `INSERT INTO page_edit_events (id, page_id, from_version_id, to_version_id, operation, instruction, user_id)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(
      crypto.randomUUID(), pageId, page.current_version_id || null, versionId,
      editInstruction ? 'edit' : 'create', editInstruction || null, userId
    ).run()

    return json({ versionId, versionNo })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleGetVersionContent(req, env, id, userId) {
  if (!env.ASSETS) return json({ error: 'Asset storage is not configured' }, 500)
  try {
    const row = await env.DB.prepare(
      'SELECT html_r2_key, css_r2_key, js_r2_key FROM generated_page_versions WHERE id = ? AND user_id = ?'
    ).bind(id, userId).first()
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

async function handleGetPageVersions(req, env, id, userId) {
  try {
    const rows = await env.DB.prepare(
      `SELECT id, version_no, summary, created_at FROM generated_page_versions
       WHERE page_id = ? AND user_id = ? ORDER BY version_no DESC`
    ).bind(id, userId).all()
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

async function handleDeleteGroup(req, env, id, userId) {
  try {
    await env.DB.prepare(
      "UPDATE generated_page_groups SET deleted_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND user_id = ?"
    ).bind(id, userId).run()
    await env.DB.prepare(
      "UPDATE generated_pages SET deleted_at = datetime('now'), updated_at = datetime('now') WHERE group_id = ? AND user_id = ?"
    ).bind(id, userId).run()
    return json({ ok: true })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleDeletePage(req, env, id, userId) {
  try {
    await env.DB.prepare(
      "UPDATE generated_pages SET deleted_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND user_id = ?"
    ).bind(id, userId).run()
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

async function handleGetBoard(req, env, userId) {
  try {
    const state = await env.DB.prepare('SELECT transform FROM board_state WHERE user_id = ?').bind(userId).first()
    const cards = await env.DB.prepare('SELECT * FROM cards WHERE user_id = ? ORDER BY created_at').bind(userId).all()
    const transform = state ? JSON.parse(state.transform) : { x: 0, y: 0, scale: 1 }
    const settings = await loadJsonSetting(env, userId, 'provider_settings')
    const uiSettings = await loadJsonSetting(env, userId, 'ui_settings')

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

async function handleSaveBoard(req, env, userId) {
  const { cards, transform, settings, uiSettings } = await req.json()

  try {
    // Per-user board_state: update the user's row, insert it if absent.
    const upd = await env.DB.prepare('UPDATE board_state SET transform = ? WHERE user_id = ?')
      .bind(JSON.stringify(transform), userId).run()
    if (!upd.meta?.changes) {
      await env.DB.prepare('INSERT INTO board_state (user_id, transform) VALUES (?, ?)')
        .bind(userId, JSON.stringify(transform)).run()
    }
    await saveJsonSetting(env, userId, 'provider_settings', settings)
    await saveJsonSetting(env, userId, 'ui_settings', uiSettings)

    const existing = await env.DB.prepare('SELECT id FROM cards WHERE user_id = ?').bind(userId).all()
    const existingIds = new Set(existing.results.map(r => r.id))
    const incomingIds = new Set(cards.map(c => c.id))

    for (const id of existingIds) {
      if (!incomingIds.has(id)) {
        await env.DB.prepare('DELETE FROM cards WHERE id = ? AND user_id = ?').bind(id, userId).run()
        await env.DB.prepare('DELETE FROM images WHERE card_id = ? AND user_id = ?').bind(id, userId).run()
      }
    }

    for (const card of cards) {
      const { id, type, x, y, w, h, linkedTo, ...rest } = card
      const content = JSON.stringify(rest)

      if (existingIds.has(id)) {
        await env.DB.prepare(
          'UPDATE cards SET type=?, x=?, y=?, w=?, h=?, content=?, linked_to=?, updated_at=datetime(\'now\') WHERE id=? AND user_id=?'
        ).bind(type, x, y, w, h, content, linkedTo || null, id, userId).run()
      } else {
        await env.DB.prepare(
          'INSERT INTO cards (id, type, x, y, w, h, content, linked_to, user_id) VALUES (?,?,?,?,?,?,?,?,?)'
        ).bind(id, type, x, y, w, h, content, linkedTo || null, userId).run()
      }
    }

    await syncAssetReferences(cards, env, userId)

    return json({ ok: true })
  } catch (e) {
    return json({ error: e.message }, 500)
  }
}

async function handleUpload(req, env, userId) {
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
        `INSERT INTO assets (id, r2_key, public_url, filename, content_type, size, user_id, created_at)
         VALUES (?,?,?,?,?,?,?,datetime('now'))`
      ).bind(id, objectKey, publicUrl, filename || '', resolvedContentType, parsed.bytes.length, userId).run()
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
    'INSERT INTO images (id, data, filename, content_type, user_id) VALUES (?,?,?,?,?)'
  ).bind(id, data, filename, resolvedContentType, userId).run()

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

  // Public R2 URLs are already reachable by model providers. Keep them as URLs
  // instead of inflating the request body with base64 data.
  if (keyFromPublicUrl(imageUrl, env)) return imageUrl

  const match = imageUrl.match(/\/api\/images\/([^/?#]+)/)
  if (match) {
    const row = await env.DB.prepare('SELECT data FROM images WHERE id = ?').bind(match[1]).first()
    return row?.data || imageUrl
  }

  return imageUrl
}

async function handleAI(req, env) {
  const startedAt = Date.now()
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
    uiContract = null,
    page = null,
    current = null,
    instruction = '',
    fastMode = false,
    streamPreview = false,
    compositionMode = false,
    directHtml = false,
    // Block-level targeted edit fields (mode: page-block-edit)
    blockId = '',
    blockHtml = '',
    blockCss = '',
  } = await req.json()

  // Platform → concrete layout / viewport constraints injected into prompts.
  function platformSpec(p) {
    if (p === 'app') return {
      label: 'App 移动端（iOS/Android 原生风格）',
      rules: '画布按移动端竖屏设计，固定设计视口 390px 宽；根容器 width:100%、min-height:100vh，铺满当前视口；不要再写更小的 max-width 居中壳；触控友好（点击区 ≥44px）；底部 tabbar / 顶部 navbar 按需要；不要桌面多列布局。',
    }
    if (p === 'miniprogram') return {
      label: '微信小程序',
      rules: '画布按微信小程序设计，固定设计视口 375px 宽；根容器 width:100%、min-height:100vh，铺满当前视口；不要再写更小的 max-width 居中壳；可表现小程序顶部导航语义，但不要画手机边框/刘海/浏览器外壳；卡片化、圆角、留白克制；触控友好；不要桌面多列布局、不要浏览器地址栏式元素。',
    }
    return {
      label: 'Web 网页（桌面优先，响应式）',
      rules: '桌面优先并响应式；内容容器 max-width 960–1200px 居中；可用多列/栅格布局；适配窄屏断点。',
    }
  }
  const pf = platformSpec(platform)
  const viewport = uiContract?.viewport || (platform === 'miniprogram'
    ? { platform, width: 375, height: 812 }
    : platform === 'app'
      ? { platform, width: 390, height: 844 }
      : { platform: 'web', width: 1280, height: 720 })
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
    const systemPrompt = `你是一名图片描述专家。请把图片描述成可用于图像生成模型的素材，不要做 UI 结构分析，不要输出组件规则，不要写 CSS 或页面实现规格。`
    const userPrompt = context
      ? `用户补充背景："${context}"\n\n请严格按照下面的 Markdown 结构描述这张图片。`
      : `请严格按照下面的 Markdown 结构描述这张图片。`
    const format = `
# 图片描述

## 画面主体
- 描述画面里能确认的主体、对象、内容元素和大致关系。

## 场景氛围
- 描述整体情绪、风格、场景感和观看距离。

## 色彩光影
- 描述主色、辅色、明暗、对比、光源方向和整体色调，不需要给 CSS。

## 材质风格
- 描述材质、纹理、颗粒、玻璃感、纸感、金属感、摄影/插画/截图风格等。

## 最终图片描述
- 写一段可以直接给图像生成模型使用的中文描述，用来生成主体、场景、氛围和色彩相似的新图片。
- 不要包含品牌、真实 logo、可识别人物、真实文案或专有内容。

## 不确定信息
- 列出无法确认或不应该猜测的内容。`
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
- **语言：所有面向人阅读的文本一律用简体中文**（包括 title、purpose、sections、components、states、responsiveNotes、designIntent、globalStyle 里的 layout/typography/componentRules/motionRules/avoid、sharedComponents 的中文说明等）。只有 id、route、navKey、slug 这类技术标识符和 CSS 数值/英文技术名词（如 #FFFFFF、px、box-shadow、bottom-nav）保持英文，绝不要把词条写成英文短语。
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
      "layoutIr": {
        "version": 1,
        "intent": "",
        "regions": [
          { "id": "topbar", "type": "header", "label": "顶部导航", "x": 0, "y": 0, "w": ${viewport.width}, "h": 56 },
          { "id": "content", "type": "list", "label": "主体内容", "x": 18, "y": 76, "w": ${Math.max(320, viewport.width - 36)}, "h": 360 }
        ]
      },
      "navKey": "",
      "responsiveNotes": "",
      "evidenceIds": []
    }
  ]
}

约束：
- 页面数量必须在 1-${effectivePageLimit} 个之间。${planScope === 'single' ? '只能输出 1 个页面。' : '超过上限时合并次要页面。'}
- appName / designIntent 用简洁中文概括产品与设计意图。
- globalStyle 必须从设计 DNA 与大爆炸具体因子中提炼出可复用的全局规范，并尽量保留主证据里的**具体数值**（色板十六进制、字体族与字号、圆角、阴影、间距、动效缓动）。
- 每个页面都会被独立生成为一份自包含界面：如果产品需要全局导航（顶部/底部/侧边），就在相应页面的 sections / components 里写明，并用 navKey 标注当前页的激活项，保证各页导航文案一致。
- 图像提示词、图片描述、单图 AI 分析只能帮助理解产品语义和氛围，不得作为主要视觉规范。
- globalStyle.layout 要体现 ${pf.label} 的形态约束。
- 每个 page 的 sections / components / states 用具体的**简体中文**短语数组（例如「顶部横幅」「错题卡片列表」「批量管理」），不要用英文短语。
- 每个 page 必须输出 layoutIr：它是给前端绘制“页面正在被画出来”的轻量蓝图，不是最终代码。regions 只描述 5-10 个主要视觉区块的位置、尺寸、类型、中文标签和意图，坐标必须使用当前固定视口像素：x/y/w/h 都是数字。移动端宽度必须贴合 ${viewport.width}px；Web 可按 ${viewport.width}px 设计视口。type 可用 header、hero、tabs、grid、list、card、chart、form、tabbar、action、text、media 等。layoutIr 不要输出 HTML/CSS，不要写长文。
- 再次强调：除 id / route / navKey / slug / CSS 值外，所有词条文本必须是简体中文。
- 不要输出任何代码。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildPageGeneratePrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle, null, 2) : '（无，按 designIntent 自行合理推断）'
    const contractStr = uiContract ? JSON.stringify(uiContract, null, 2) : '（无）'
    const pageStr = page ? JSON.stringify(page, null, 2) : '（无）'
    if (directHtml) {
      const systemPrompt = `你是世界顶级的产品 UI 设计师兼前端工程师，作品达到 Dribbble / Mobbin 精选水准。你将为「${pf.label}」产品的单个页面，直接产出一份自包含、可立即预览、视觉精致的前端代码（HTML + 内联 CSS + 必要 JS）。不要线框图、不要示意稿，要像真实上线产品的第一屏。

## 平台约束
- ${pf.rules}
- 固定设计视口 ${viewport.width}x${viewport.height}。移动端根容器 width:100%、min-height:100vh 铺满，禁止更小的 max-width 居中壳导致左右留白；Web 才可用居中容器。

## 视觉证据优先级（最重要）
- ${evidencePriority}
- ${referenceRule}
- 设计 DNA / 大爆炸具体因子是**最高优先级视觉规范**：必须把其中的具体色值(#RRGGBB)、字体族/字号/字重、圆角、阴影 box-shadow、间距、渐变、毛玻璃、质感直接落到 CSS。globalStyle 是它的结构化摘要，冲突时以 DNA 具体值为准。

## 设计系统纪律（决定"高级感"，必须严格遵守）
1. **令牌化**：在 :root 定义全部设计 token（colors / spacing / radius / shadow / font）。所有数值都引用 token，不要散落魔法数。
2. **间距用 8pt 体系**：4/8/12/16/24/32/48/64。同组元素间距一致，区块之间留白要慷慨、有呼吸感。
3. **字阶有明确层级**：至少 4 级字号 + 字重对比（如 13/15/20/28，weight 400/500/700），正文行高 1.5–1.7，标题更紧。一屏内信息层级 ≥3 层。
4. **克制配色**：以 DNA 主色 + 中性灰阶为主，强调色只用在关键 CTA / 选中态，不要彩虹色。对比度达到 WCAG AA。
5. **一个视觉焦点**：首屏有明确主视觉/主操作，其余元素服从它，不要平铺堆砌。
6. **组件细节**：圆角统一、阴影柔和有层次（避免生硬黑边）、边框用低对比分隔线、交互元素有 hover/active/focus 态。
7. **真实内容**：所有文案、数字、列表项、标签都是贴合产品的具体中文内容。严禁 Lorem ipsum、"示例标题"、"暂无内容"、大面积灰色占位块。没有真实图片时用 CSS 渐变、内联 SVG 图标、纯 CSS 插画/数据可视化形状替代。
8. **状态完整**：覆盖 page.states，至少实现 hover / active / selected / empty / loading / error 中的 4 种。

## 内容要求
- 必须实现 page.sections / page.components，整页 8–14 个具体内容单元，不同 pageType 要有不同构图（详情页强调阅读区、列表页强调浏览、表单页强调流程、概览页强调数据）。
- 必须建立可见的 design system：导航/标题区、内容容器、卡片、按钮、标签、列表/图表至少覆盖 5 类。

## 块级可编辑结构（强制，供后续局部编辑）
- 每个 page.sections 逻辑分区包成 \`<section data-block="<kebab-slug>" data-block-label="<简短中文标签>"> ... </section>\`，slug 页面内唯一、语义化（如 hero / category-nav / article-body），不嵌套块、不漏分区。
- CSS 中每个块的规则用 \`/* block:<slug> */ ... /* /block:<slug> */\` 注释定界；:root / reset / 共享基础样式放在 CSS 最顶部，不被任何 block 注释包裹。

## 技术约束
- 自包含、可直接渲染在沙箱 iframe 内。JS 只为必要交互（标签切换、展开等），写在 js 字段，**不依赖任何外部脚本/CDN/远程字体**（外链脚本会被安全策略剥离）。可用 https 图片 URL、data-uri、内联 SVG、纯 CSS 图形。
- 语义化 HTML、现代 CSS（flex/grid、变量、clamp）。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要解释、不要 thinking。`
      const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}

设计 DNA / 大爆炸因子 / 辅助语义证据（DNA 与大爆炸具体因子为最高优先级视觉规范）：
${context || '（无，按 globalStyle 与 designIntent 合理发挥，仍须完整精致的视觉）'}

全局风格摘要（globalStyle）：
${styleStr}

当前要生成的页面（page）：
${pageStr}

请输出严格符合下面结构的 JSON（字段名必须完全一致）：
{
  "pageId": "${page?.id || 'home'}",
  "title": "页面中文标题",
  "html": "完整页面 body 内 HTML，按上面块级结构组织",
  "css": "完整 CSS：:root tokens 在最顶部，每个块用 /* block:slug */ 定界",
  "js": "必要交互 JS，可为空字符串",
  "notes": ["2-4 条 DNA 到代码的映射，简短中文"]
}

约束：
- pageId 与 page.id 一致；title 用简洁中文。
- html 不要包含 <html>/<head>/<body> 外壳，只输出 body 内部内容（页面级 wrapper 可有）。
- 严格复用 DNA / 大爆炸的具体数值；遵守 globalStyle.avoid。
- 不要使用大面积 #e5e7eb / #f3f4f6 灰块充当图片或内容。
- 再次强调：除技术标识符和 CSS 值外，所有面向人阅读的文本一律简体中文。`
      const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 6)
      return { systemPrompt, userPrompt, imageUrls }
    }
    if (compositionMode) {
      const systemPrompt = `你是一名顶级 AI 产品视觉设计师。你的任务不是写 HTML/CSS，而是先让"整个页面画面"成立，再把它拆成带布局约束的组件树。
核心原则：
- 先做 screen design，再做 component breakdown；不要先想组件库。
- 每个组件必须知道自己在页面里的 x/y/w/h、视觉角色、信息密度和内容，不允许返回抽象占位。
- ${pf.rules}
- 固定设计视口 ${viewport.width}x${viewport.height}；所有 layout 坐标必须在该视口内，移动端必须按真实小程序/App 画面设计。
- ${evidencePriority}
- ${referenceRule}
- 设计 DNA / 大爆炸具体因子是最高优先级视觉规范：必须复用其中的具体色值、字体、圆角、阴影、间距、质感和组件语言；缺口才补齐。
- 页面之间要共享同一个 designSystem，但不同功能页必须有不同构图，不要用同一套 hero + list 套所有页面。
- 输出要能被前端稳定编译：只返回 JSON，不要 Markdown，不要 HTML/CSS/JS，不要解释。`
      const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}

高置信设计证据：
${context || '（无）'}

globalStyle:
${styleStr}

uiContract:
${contractStr}

当前页面 page:
${pageStr}

请严格返回这个 JSON 结构：
{
  "pageId": "home",
  "title": "",
  "composition": {
    "version": 1,
    "pageType": "home | categoryBrowser | articleDetail | favoritesManager | formFlow | dashboard | settings | custom",
    "screen": {
      "width": ${viewport.width},
      "height": ${viewport.height},
      "density": "calm | balanced | dense | editorial",
      "visualFocus": "",
      "layoutIdea": "",
      "background": ""
    },
    "tokens": {
      "primary": "",
      "ink": "",
      "muted": "",
      "canvas": "",
      "surface": "",
      "line": "",
      "radius": 18,
      "shadow": ""
    },
    "components": [
      {
        "id": "stable-kebab-id",
        "type": "header | tabbar | hero | categoryMenu | cardList | articleBody | stats | actionBar | searchBar | filterBar | form | media | custom",
        "label": "中文标签",
        "order": 0,
        "layout": { "x": 0, "y": 0, "w": ${viewport.width}, "h": 72, "role": "navigation | primary-focus | content | action | support", "density": "calm | balanced | dense" },
        "props": {
          "title": "",
          "subtitle": "",
          "eyebrow": "",
          "items": [],
          "tabs": [],
          "stats": [],
          "actions": []
        }
      }
    ],
    "rationale": []
  },
  "notes": [],
  "validationChecklist": []
}

强约束：
- components 必须是 4-9 个主要视觉组件，按视觉顺序排列；每个组件 layout 都要有数字 x/y/w/h，不能超出 ${viewport.width}x${viewport.height}，重要组件不能互相重叠。
- x/y/w/h 是这个组件在最终页面中的真实位置和尺寸，不是建议值；前端会按这些数值直接绘制。
- pageType 要根据功能判断：分类/栏目页用 categoryBrowser；文章/详情页用 articleDetail；收藏/书签页用 favoritesManager；表单流程用 formFlow；数据概览用 dashboard。
- 不同 pageType 必须有不同构图：详情页要强调阅读区，收藏页要强调管理/列表状态，分类页要强调导航与内容浏览。
- 每个 props.items/tabs/stats/actions 都必须是具体中文内容，不要写"示例"、"占位"、"暂无"。
- tokens 必须尽量来自 globalStyle / DNA 证据；没有时才补齐。颜色用 #RRGGBB。
- notes 写 2-4 条"为什么这个页面这样构图"；validationChecklist 写 3-5 条可检查项。
- 严格只返回 JSON 对象。`
      const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 4)
      return { systemPrompt, userPrompt, imageUrls }
    }
    if (streamPreview) {
      const systemPrompt = `你是一名资深 UI 工程师。为 ${pf.label} 生成一个可直接预览的单页界面。你必须按 NDJSON 区块协议输出，方便浏览器收到一个完整区块就渲染一个完整区块。
硬约束：
- ${pf.rules}
- 固定视口 ${viewport.width}x${viewport.height}；移动端根内容 width:100%，不要写更小 max-width 居中壳。
- 严格复用给定 DNA / 大爆炸因子的色值、字体、圆角、阴影、间距和组件语言；缺口才合理补齐。
- 输出真实页面内容，禁止灰色占位块、Lorem ipsum、示例标题、空白卡片。
- 每个区块必须是完整 outerHTML，最外层必须有 data-block="slug" 和 data-block-label="中文标签"。
- 每个区块 CSS 只负责自己和必要的 :root/page 基础变量；选择器尽量以 [data-block="slug"] 开头。
- 不要输出 Markdown 代码块、解释、thought、XML 标签或普通文本。只输出 NDJSON：每一行必须是一个完整 JSON 对象。`
      const userPrompt = `appName: ${appName || ''}
designIntent: ${designIntent || ''}
platform: ${pf.label}

高置信设计证据：
${context || '（无）'}

globalStyle:
${styleStr}

uiContract:
${contractStr}

page:
${pageStr}

请严格按下面协议逐行输出 NDJSON。每行都是一个完整 JSON 对象；不要把一个 JSON 对象拆成多行；字符串里的换行必须转义为 \\n。

第一行必须输出全局基础区块：
{"type":"block","blockId":"page-base","order":0,"label":"页面基础","rect":{"x":0,"y":0,"w":${viewport.width},"h":${viewport.height}},"html":"<div data-block=\\"page-base\\" data-block-label=\\"页面基础\\" hidden></div>","css":"完整 :root tokens、html/body、页面背景、字体、viewport 基础、通用按钮/标签/卡片状态。不要写当前页面具体内容。","js":""}

之后按视觉顺序输出 5-10 个页面区块：
{"type":"block","blockId":"hero","order":10,"label":"顶部重点","rect":{"x":24,"y":88,"w":${Math.max(1, viewport.width - 48)},"h":160},"html":"<section data-block=\\"hero\\" data-block-label=\\"顶部重点\\">完整且真实的中文 UI 内容...</section>","css":"/* block:hero */\\n[data-block=\\"hero\\"]{...}\\n/* /block:hero */","js":""}

最后一行输出完成事件：
{"type":"done","meta":{"notes":["2-4 条 DNA 到代码映射，简短中文"]}}

区块要求：
- 必须覆盖 page.sections / page.components / page.states，整体至少 8-14 个具体中文内容单元。
- 每个内容 block 必须带 rect，坐标使用固定视口像素，x/y/w/h 都是数字；rect 要与该区块在页面中的真实位置和尺寸大致一致，不能互相重叠，不能超出 ${viewport.width}x${viewport.height}。
- 如果需要底部导航/顶部导航，作为独立区块输出，order 靠前或靠后；同一项目的导航文案必须来自 uiContract/sharedComponents/page.navKey，不要自由改名。
- 不要使用会裂开的远程图片；没有可靠图片时用 CSS 渐变、内联 SVG、主题纹理或色块插画。
- 每个 block 必须完整闭合，不能输出半个标签后等待下一行补齐。`
      const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 4)
      return { systemPrompt, userPrompt, imageUrls }
    }
    if (fastMode) {
      const systemPrompt = `你是一名资深 UI 工程师。为 ${pf.label} 生成一个可直接预览的单页界面，优先速度和可解析性，但不能降低视觉完成度。
硬约束：
- ${pf.rules}
- 固定视口 ${viewport.width}x${viewport.height}；移动端根内容 width:100%，不要写更小 max-width 居中壳。
- 严格复用给定 DNA / 大爆炸因子的色值、字体、圆角、阴影、间距和组件语言；缺口才合理补齐。
- 如果 uiContract.sharedShell 已存在，只生成 pageContent；如果 sharedComponents 非空但 sharedShell 不存在，同时生成 sharedShell + pageContent。
- 输出真实页面内容，禁止灰色占位块、Lorem ipsum、示例标题、空白卡片。
- 每个 page.sections 分区必须有 <section data-block="slug" data-block-label="中文标签">，CSS 用 /* block:slug */ 定界。
- 严格只返回 JSON 对象，不要 Markdown、解释、thought。`
      const userPrompt = `appName: ${appName || ''}
designIntent: ${designIntent || ''}
platform: ${pf.label}

高置信设计证据：
${context || '（无）'}

globalStyle:
${styleStr}

uiContract:
${contractStr}

page:
${pageStr}

返回 JSON 结构：
{
  "pageId": "home",
  "title": "",
  "html": "",
  "css": "",
  "js": "",
  "sharedShell": null,
  "pageContent": { "html": "", "css": "", "js": "" },
  "notes": []
}

生成要求：
- pageId 与 page.id 一致。
- 页面主体至少包含 6-10 个真实中文内容单元，体现 page.sections / page.components / page.states。
- CSS 要有 :root tokens、背景、导航/标题区、卡片、按钮/标签、列表或统计、selected/loading/empty/error/hover 中至少 4 种状态。
- 移动端页面内部不得出现小于设计视口的 max-width 居中容器。
- notes 只保留 2-4 条 DNA 到代码映射。`
      const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 4)
      return { systemPrompt, userPrompt, imageUrls }
    }
    const systemPrompt = `你是一名资深 UI 工程师，能把参考视觉精确迁移到可运行界面。你将为一个 ${pf.label} 产品的"单个页面"生成完整、自包含、可直接预览的前端代码。
要求：
- 目标平台「${pf.label}」：${pf.rules}
- ${evidencePriority}
- **设计 DNA 与大爆炸具体因子是最高优先级的视觉规范**：${referenceRule} 必须把下方主证据里的具体数值（十六进制色值、字体族/字号/字重、圆角、阴影 box-shadow、间距、渐变、毛玻璃等）直接落到 CSS 上。globalStyle 是它的结构化摘要，二者冲突时以 DNA / 大爆炸具体因子为准。
- 图像提示词、图片描述、单图 AI 分析只用于理解内容主题、对象语义和氛围方向，不得覆盖主证据里的 CSS 数值和组件语言。
- 不要输出"默认浏览器风格"的简陋页面：要有完整的配色、排版层级、留白、组件细节、hover/active 状态与微交互。
- 必须建立可见的 design system：:root CSS tokens（颜色/字体/圆角/阴影/间距）、页面背景、导航/标题区、内容容器、卡片、按钮、标签、输入/筛选、列表或图表至少覆盖其中 5 类；不要只堆文本。
- 固定设计视口：本次平台 viewport 为 ${viewport.width}x${viewport.height}。移动端页面内容必须按这个精确宽度设计，根内容 width:100%，不要再写更小的 max-width 居中壳；Web 才允许响应式容器。
- sharedComponents / sharedShell 是跨页面复用资产，不能每页重画。如果 uiContract 已包含 sharedShell，则本次只生成 pageContent；如果 uiContract 还没有 sharedShell，但 sharedComponents 非空，则本次必须同时生成 sharedShell（只生成一次，含 {{PAGE_CONTENT}} 插槽）。
- 页面必须像真实可上线的第一稿，而不是线框图或示意稿：正文、标题、标签、数字、列表项、按钮文案要具体可信；首屏必须有明确主视觉/内容焦点和 3 层以上信息层级。
- 严禁大面积灰色图片占位块、空白卡片、"Lorem ipsum"、"示例标题"、"暂无内容"式偷懒内容。没有真实图片时，用 CSS 渐变、内联 SVG 图标、数据可视化形状、纹理块或主题相关的抽象插画替代；如果证据里提供了公开图片/R2 URL，可以直接作为 img src 使用。
- 页面必须自包含、覆盖常见状态（加载 / 空 / 错误 / 交互态，参考 page.states）。
- 使用语义化 HTML、现代 CSS；JS 只为必要交互，不依赖任何外部脚本或 CDN。允许使用 https 图片 URL、data-uri、内联 SVG 或纯 CSS 图形；不要依赖远程脚本/字体。
- notes 必须写出 3-6 条“DNA 到代码”的映射，例如某个色值用于哪个元素、某个圆角/阴影如何落地。
- **块级可编辑结构（强制）**：把 page.sections 里每个逻辑分区包成一个块元素 \`<section data-block="<kebab-slug>" data-block-label="<简短标签>"> ... </section>\`。data-block 是 kebab-case 稳定 slug（页面内唯一，来源于该分区语义，例如 hero / feature-list / pricing），data-block-label 是简短人类可读标签（可中文，例如 顶部横幅）。每个分区只能对应一个块，不要嵌套块、不要漏掉任何分区。
- **CSS 块定界（强制）**：每个块对应的 CSS 规则用注释定界 \`/* block:<slug> */ ... /* /block:<slug> */\` 包裹（slug 与 data-block 完全一致）；全局/根/重置类 CSS（:root tokens、reset、共享基础样式）必须放在所有块定界之外，集中在 CSS 字符串最顶部，不被任何 block 注释包裹。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要额外说明文字。`
    const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}

设计 DNA / 大爆炸因子 / 辅助语义证据（DNA 与大爆炸具体因子是最高优先级视觉规范；图像提示词/图片描述/AI 分析仅作辅助语义证据）：
${context || '（无，按 globalStyle 与 designIntent 合理发挥，仍需有完整精致的视觉）'}

全局风格摘要（globalStyle）：
${styleStr}

项目 UI 契约（uiContract，跨页面持久化；已有 sharedShell 时必须复用）：
${contractStr}

当前要生成的页面（page）：
${pageStr}

请输出严格符合下面结构的 JSON（字段名必须完全一致）：
{
  "pageId": "home",
  "title": "",
  "html": "",
  "css": "",
  "js": "",
  "sharedShell": null,
  "pageContent": { "html": "", "css": "", "js": "" },
  "notes": [],
  "validationChecklist": []
}

约束：
- pageId 与 page.id 保持一致。
- 如果 uiContract.sharedShell 已存在：pageContent 必须输出该页主体内容，html/css/js 可与 pageContent 保持相同；绝对不要重新生成 topbar/bottom-nav/sidebar/searchbar/filterbar 等 sharedComponents。
- 如果 uiContract.sharedShell 不存在且 uiContract.sharedComponents 非空：sharedShell 必须输出共享外壳代码，html 中必须包含 {{PAGE_CONTENT}} 插槽；pageContent 输出当前页主体内容。sharedShell 只能包含跨页面复用的顶部/底部/侧边/全局控件，不包含当前页专属列表内容。
- 如果没有 sharedComponents：按旧模式输出 html/css/js 完整页面。
- 布局必须符合 ${pf.label} 的固定视口：移动端严格 ${viewport.width}px 宽，不要在页面内部使用更小 max-width 居中导致左右留白。
- 必须实现 page.sections 与 page.components，并覆盖 page.states 描述的状态。
- 每个主要区块都要填充面向目标产品的真实中文内容，至少包含 8-14 个具体内容单元（如新闻条目、题目卡片、统计块、分类、操作按钮、状态标签等），避免只做 2-3 个重复卡片。
- pageContent/html 中每个 page.sections 分区必须包成 \`<section data-block="<kebab-slug>" data-block-label="<简短标签>">...</section>\`，slug 页面内唯一。
- css 中每个块的规则用 \`/* block:<slug> */ ... /* /block:<slug> */\` 定界，slug 与 data-block 一致；:root / reset / 共享 token 等全局样式放在最顶部、不被任何 block 注释包裹。
- 按参考约束执行：${referenceRule}
- 严格复用设计 DNA 与大爆炸具体因子的具体数值（色板十六进制、字体、圆角、阴影、间距、渐变）；遵守 globalStyle.avoid 列表。
- CSS 必须包含明确的视觉 token 和组件状态：hover / active / selected / disabled / loading / empty / error 中至少覆盖 4 种。
- 不要把图像提示词或图片描述当成 UI 生成主 prompt；它们只补充语义和内容方向。
- 成品要体现参考素材的视觉基线，避免简陋的无样式默认外观；不要使用大面积 #e5e7eb / #f3f4f6 灰块充当图片或内容。
- notes 说明“DNA 到代码”的映射，validationChecklist 给出可自检的验收项。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildPageEditPrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle, null, 2) : '（无，保持现状）'
    const contractStr = uiContract ? JSON.stringify(uiContract, null, 2) : '（无）'
    const pageStr = page ? JSON.stringify(page, null, 2) : '（无）'
    const cur = current || {}
    const systemPrompt = `你是一名资深 UI 工程师。你将根据用户指令修改一个已有页面，并输出"全量替换"的完整页面代码。
要求：
- 仅按 instruction 修改对应内容；不要改动与指令无关的部分。
- 除非 instruction 明确要求改变风格，否则保持原有 globalStyle 全局风格不变。
- ${evidencePriority}
- 参考约束：${referenceRule}
- 输出仍是完整、自包含、响应式、覆盖状态的单页面代码（全量替换，而非补丁）。
- 如果 uiContract.sharedShell 已存在，sharedComponents 是跨页面复用外壳，不能在本页编辑中重画或修改；本次只输出 pageContent/html/css/js 的页面主体内容。除非 instruction 明确要求调整全局导航/外壳，否则不要改 topbar/bottom-nav/sidebar/searchbar/filterbar。
- 必须保留并维护现有的 \`data-block\` 区块结构：除非 instruction 明确要求新增/删除区块，否则不要删改已有 data-block slug；新增区块也必须使用 \`<section data-block="...">\`。
- 必须保持目标平台「${pf.label}」的容器和视口约束：${pf.rules}
- 不要把已有真实内容改成灰色占位、空白卡片、"示例标题" 或 Lorem ipsum；编辑后仍要像真实可上线页面。
- notes 必须说明本次修改如何保留或调整设计 DNA / 大爆炸具体因子；若使用图像提示词、图片描述或 AI 分析，只能说明其辅助语义作用。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要额外说明文字。`
    const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}（${pf.rules}）

设计 DNA / 大爆炸因子 / 辅助语义证据（DNA 与大爆炸具体因子是视觉基线；除非指令要求否则不偏离其具体数值；图像提示词/图片描述/AI 分析仅作辅助语义证据）：
${context || '（无）'}

全局风格摘要（globalStyle，除非指令要求否则保持不变）：
${styleStr}

项目 UI 契约（uiContract，跨页面持久化；已有 sharedShell 时必须复用）：
${contractStr}

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
  "pageContent": { "html": "", "css": "", "js": "" },
  "notes": [],
  "validationChecklist": []
}

约束：
- 只改与 instruction 相关的部分，保留其余内容。
- 保持 globalStyle，除非指令明确要求修改风格。
- 保留原有 data-block / data-block-label；不要因为全量输出而丢失区块可编辑标记。
- 保留已有页面的内容密度和信息层级；不要生成大面积灰色图片占位块。
- CSS 继续包含 :root tokens、平台容器约束和已有组件状态；不要退化成少量默认样式。
- html / css / js 为修改后的完整代码字符串（全量）。
- 如果 uiContract.sharedShell 已存在：pageContent 必须输出修改后的主体内容；html/css/js 可与 pageContent 保持相同；不要把共享外壳、顶栏、底栏、侧栏重新输出到页面内容里。
- notes 说明本次改动，validationChecklist 给出可自检的验收项。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildPageBlockEditPrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle, null, 2) : '（无，保持现状）'
    const systemPrompt = `你是一名资深 UI 工程师。你只修改页面中的"单个区块"，绝不触碰页面其他区块。
要求：
- 只编辑 data-block="${blockId}" 这一个块，按 instruction 修改其内容/结构/样式；不要改动、不要输出任何其他块。
- 返回的 html 必须仍然是这个块的完整 outerHTML，且最外层仍是 \`<section data-block="${blockId}" data-block-label="...">...</section>\`（data-block 值必须保持为 "${blockId}"，不可改名、不可拆分或新增块）。
- 返回的 css 只能包含这个块自身的规则（针对块内选择器），不要输出 :root / reset / 共享 token 等全局样式，也不要包含 /* block */ 定界注释（外层会自动处理）。
- css 选择器必须尽量以 \`[data-block="${blockId}"]\` 或该区块内的局部类名开头，避免影响其他区块；不要输出 body、html、:root、*、section、button 这类全局选择器。
- 除非 instruction 明确要求改风格，否则严格复用设计 DNA / 大爆炸具体因子的具体数值（十六进制色值、字体族/字号/字重、圆角、阴影、间距、渐变）与 globalStyle；保持与目标平台「${pf.label}」一致。
- 不得对其他块产生视觉影响（不要写会波及其他块的全局或宽泛选择器）。
- 不要把该区块已有真实内容替换成灰色占位或空白示意；如果 instruction 是视觉调整，优先保留内容，只改样式。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要额外说明文字。`
    const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}（${pf.rules}）

设计 DNA / 大爆炸因子 / 辅助语义证据（DNA 与大爆炸具体因子是视觉基线；除非指令要求否则不偏离其具体数值；图像提示词/图片描述/AI 分析仅作辅助语义证据）：
${context || '（无）'}

全局风格摘要（globalStyle，除非指令要求否则保持不变）：
${styleStr}

要编辑的区块 ID（blockId）：${blockId}

当前区块 HTML（blockHtml，含 data-block 外层）：
${blockHtml || ''}

当前区块 CSS（blockCss，仅该块的规则）：
${blockCss || ''}

用户修改指令（instruction）：
"${instruction || ''}"

请输出严格符合下面结构的 JSON（字段名必须完全一致）：
{
  "blockId": "${blockId}",
  "html": "",
  "css": ""
}

约束：
- blockId 必须等于 "${blockId}"。
- html = 修改后该块的完整 outerHTML，最外层保留 \`<section data-block="${blockId}" ...>\` 包裹。
- css = 只包含该块自身的规则，不含全局样式、不含 block 定界注释。
- css 不要包含会影响全页的选择器；推荐写成 \`[data-block="${blockId}"] .class-name { ... }\`。
- 只改与 instruction 相关的内容，保留该块其余部分；不要影响其他块。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  function buildDesignTokensPrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle, null, 2) : '（无）'
    const systemPrompt = `你是一名资深设计系统工程师。你将根据一份美学 DNA（Markdown 文本）以及可选的 globalStyle，提炼出一套最核心的设计 token。
要求：
- 只提炼核心 token，严格输出下面这个 JSON 对象结构，不要多余字段、不要嵌套展开：
{ "appName": "", "palette": [{"name":"","role":"","hex":""}], "fonts": {"headline":"","body":"","label":""}, "radius": 12, "shadow": "", "accentText": "" }
- palette：3-6 个基础色（不是色阶渐变），每个含 name（如 Primary/Secondary/Neutral）、role（如 primary/secondary/neutral/accent/background）、hex（标准 #RRGGBB）。优先**直接复用** DNA 文本里出现的具体十六进制色值；色值不足时再合理推断补齐，但总数保持 3-6 个。
- fonts：headline / body / label 三个字段，给出合理的字体族名（family name，如 "Plus Jakarta Sans"、"Inter"）；DNA 中出现就复用，缺失则按整体气质推断。
- radius：基础圆角，px 数值（number，不带单位）。
- shadow：一条合法的 CSS box-shadow 值字符串（如 "0 8px 24px rgba(0,0,0,0.08)"）。
- accentText：用于小型 UI 强调文本/图标的强调色，标准 #RRGGBB（缺失时可复用 palette 中的强调/主色）。
- 严格只返回这个 JSON 对象本身，不要 Markdown 代码块、不要任何说明文字、不要思考过程、不要 <think> 或 <thought> 标签。`
    const userPrompt = `美学 DNA（aesthetic DNA，Markdown，作为主证据）：
${context || '（无）'}

可选全局风格（globalStyle）：
${styleStr}

请严格只返回符合下面结构的 JSON 对象（字段名、层级必须完全一致），不要任何其他文字、解释、列表或 thought：
{
  "appName": "",
  "palette": [
    { "name": "Primary", "role": "primary", "hex": "#000000" }
  ],
  "fonts": { "headline": "", "body": "", "label": "" },
  "radius": 12,
  "shadow": "",
  "accentText": "#000000"
}

约束：
- palette 含 3-6 个基础色，优先复用 DNA 中出现的具体十六进制色值。
- radius 为 px 数值（number）。
- shadow 为合法 CSS box-shadow 字符串。
- 只返回 JSON 对象本身，不要代码块、不要解释。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  const prompt = mode === 'polish' ? buildPolishPrompt() : mode === 'video-explosion' ? buildVideoExplosionPrompt() : mode === 'text-explosion' ? buildTextExplosionPrompt() : mode === 'design-explosion' ? buildDesignExplosionPrompt() : mode === 'group' ? buildGroupPrompt() : mode === 'page-plan' ? buildPagePlanPrompt() : mode === 'page-generate' ? buildPageGeneratePrompt() : mode === 'page-edit' ? buildPageEditPrompt() : mode === 'page-block-edit' ? buildPageBlockEditPrompt() : mode === 'design-tokens' ? buildDesignTokensPrompt() : buildSinglePrompt()

  // Determine if this task needs a vision model or pure LLM
  const needsVision = prompt.imageUrls.length > 0 || mode === 'single' || mode === 'video-explosion'
  const promptChars = `${prompt.systemPrompt || ''}\n\n${prompt.userPrompt || ''}`.length

  // Default models per provider — auto-select VL vs LLM
  const MODEL_DEFAULTS = {
    modelscope: { vl: 'Qwen/Qwen3-VL-235B-A22B-Instruct', llm: 'Qwen/Qwen3-235B-A22B' },
    qwen:       { vl: 'qwen-vl-max',                    llm: 'qwen-max' },
    deepseek:   { vl: 'deepseek-chat',                   llm: 'deepseek-chat' },
    zhipu:      { vl: 'glm-4v',                          llm: 'glm-4-plus' },
    mi:         { vl: 'mimo-v2-omni',                    llm: 'mimo-v2-flash' },
    google:     { vl: 'gemini-2.5-flash',                llm: 'gemini-2.5-flash' },
  }
  const defaults = MODEL_DEFAULTS[provider] || MODEL_DEFAULTS.modelscope
  const resolvedModel = model || (needsVision ? defaults.vl : defaults.llm)

  // Resolve Worker image URLs to data URLs so external APIs can fetch them
  const resolvedImages = await Promise.all(
    prompt.imageUrls.map(url => resolveImageUrl(url, env))
  )

  try {
    let result = ''

    async function callOpenAICompat(apiUrl, apiKey, modelName, onDelta) {
      if (!apiKey) {
        const err = new Error('缺少接口密钥，请在设置中填写。')
        err.status = 400
        throw err
      }
      const content = needsVision
        ? [
            { type: 'text', text: `${prompt.systemPrompt}\n\n${prompt.userPrompt}` },
            ...resolvedImages.map(url => ({ type: 'image_url', image_url: { url } })),
          ]
        : `${prompt.systemPrompt}\n\n${prompt.userPrompt}`
      // Explosion + page modes return JSON — force JSON output format
      const wantsJson = !streamPreview && ['text-explosion', 'video-explosion', 'design-explosion', 'page-plan', 'page-generate', 'page-edit', 'page-block-edit', 'design-tokens'].includes(mode)
      const needsStableJson = !streamPreview && ['page-plan', 'page-generate', 'page-edit', 'page-block-edit'].includes(mode)
      const body = {
        model: modelName,
        messages: [{ role: 'user', content }],
        // page-plan bumped to 8192: Gemini 2.5/3.x "thinking" models spend part
        // of the budget reasoning, so a 4096 cap could truncate the JSON before
        // the plan is emitted → unparseable result.
        max_tokens: (mode === 'page-generate' && fastMode) ? 6144 : (mode === 'page-generate' || mode === 'page-edit' || mode === 'page-plan') ? 8192 : (mode === 'page-block-edit') ? 4096 : mode === 'design-tokens' ? 2048 : wantsJson ? 4096 : (mode === 'group' || mode === 'polish') ? 2048 : 1024,
        // Always stream. Non-streaming long generations get killed by idle
        // timeouts on proxies / providers (DeepSeek etc) → "no response".
        stream: true,
      }
      // `enable_thinking` is a Qwen/DashScope/ModelScope-only field. DeepSeek,
      // Zhipu and other OpenAI-compatible endpoints may reject the unknown
      // param (400) — only send it where supported.
      if (provider === 'qwen' || provider === 'modelscope') {
        body.enable_thinking = false
      }
      // Many OpenAI-compatible third-party endpoints either reject
      // response_format or handle large JSON worse when it is enabled. Page
      // generation/edit prompts already require strict JSON and the frontend
      // parser is tolerant, so only force response_format for smaller JSON jobs.
      // EXCEPTION: Gemini (google) handles json_object mode reliably and tends
      // to otherwise wrap output in prose / markdown / thinking — which makes
      // the page-plan/generate result unparseable. Force JSON mode for Gemini
      // on every JSON task.
      if (wantsJson && (provider === 'google' || !needsStableJson)) {
        body.response_format = { type: 'json_object' }
      }
      if (provider === 'google' && ['page-plan', 'page-generate', 'page-edit', 'page-block-edit', 'design-tokens'].includes(mode)) {
        body.reasoning_effort = /gemini-2\.5/i.test(String(modelName || '')) ? 'none' : 'minimal'
      }
      const timeoutMs = (mode === 'page-generate' || mode === 'page-edit' || mode === 'page-block-edit') ? 280000 : mode === 'page-plan' ? 150000 : 70000
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs)
      let res
      const providerStartedAt = Date.now()
      try {
        const makeRequest = () => fetch(apiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
          body: JSON.stringify(body),
          signal: controller.signal,
        })
        res = await makeRequest()
        if (!res.ok && body.reasoning_effort) {
          const clone = await res.clone().text().catch(() => '')
          if (/reasoning_effort|unsupported|unknown|unrecognized|extra/i.test(clone)) {
            delete body.reasoning_effort
            res = await makeRequest()
          }
        }
      } catch (e) {
        if (e.name === 'AbortError') {
          const err = new Error(`AI 请求超时（${Math.round(timeoutMs / 1000)}s）。模型生成页面太慢或供应商繁忙，请换更快的模型/降低页面复杂度后重试。`)
          err.status = 504
          throw err
        }
        throw e
      } finally {
        clearTimeout(timeoutId)
      }
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        const errMsg = data.error?.message || data.error?.code || data.message || `HTTP ${res.status}`
        const err = new Error(`AI 请求失败: ${errMsg}`)
        err.status = res.status
        throw err
      }
      // Parse SSE stream and collect content chunks
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let text = ''
      let buffer = ''
      let firstDeltaAt = 0
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
            if (delta) {
              if (!firstDeltaAt) {
                firstDeltaAt = Date.now()
                console.log(`[AI] first delta mode=${mode} provider=${provider} model=${modelName} promptChars=${promptChars} images=${resolvedImages.length} waitMs=${firstDeltaAt - providerStartedAt}`)
              }
              text += delta
              if (onDelta) onDelta(delta)
            }
          } catch {}
        }
      }
      if (!text) {
        console.log(`[AI] Empty streamed response from ${modelName}`)
        const err = new Error('AI 返回为空，请检查模型是否可用。')
        err.status = 502
        throw err
      }
      console.log(`[AI] done mode=${mode} provider=${provider} model=${modelName} len=${text.length} head=${JSON.stringify(text.slice(0, 200))}`)
      return text
    }

    const compatBase = (fallback) => (baseUrl || fallback).replace(/\/$/, '')

    // Resolve the OpenAI-compatible endpoint + key for the chosen provider.
    function resolveEndpoint() {
      switch (provider) {
        case 'qwen': return { apiUrl: `${compatBase('https://dashscope.aliyuncs.com/compatible-mode/v1')}/chat/completions`, key: apiKey || env.QWEN_API_KEY, model: resolvedModel }
        case 'deepseek': return { apiUrl: `${compatBase('https://api.deepseek.com/v1')}/chat/completions`, key: apiKey || env.DEEPSEEK_API_KEY, model: resolvedModel }
        case 'zhipu': return { apiUrl: `${compatBase('https://open.bigmodel.cn/api/paas/v4')}/chat/completions`, key: apiKey || env.ZHIPU_API_KEY, model: resolvedModel }
        case 'modelscope': return { apiUrl: `${(baseUrl || env.MODELSCOPE_BASE_URL || 'https://api-inference.modelscope.cn/v1').replace(/\/$/, '')}/chat/completions`, key: apiKey || env.MODELSCOPE_API_KEY, model: resolvedModel }
        case 'mi': return { apiUrl: `${compatBase('https://api.mimo-v2.com/v1')}/chat/completions`, key: apiKey || env.MI_API_KEY, model: resolvedModel }
        case 'google': return { apiUrl: `${compatBase('https://generativelanguage.googleapis.com/v1beta/openai')}/chat/completions`, key: apiKey || env.GOOGLE_API_KEY, model: resolvedModel }
        case 'lmstudio': return { apiUrl: `${(baseUrl || lmstudioUrl || 'http://localhost:1234').replace(/\/$/, '')}/v1/chat/completions`, key: 'lm-studio', model: model || 'default' }
        default: return null
      }
    }

    // Slow page-generation modes stream the result straight back to the
    // browser. Keeping bytes flowing prevents the edge / client connection
    // from timing out on slow models (Gemma, DeepSeek under load, etc).
    const streamToClient = ['page-plan', 'page-generate', 'page-edit', 'page-block-edit'].includes(mode)
    if (provider !== 'ollama' && streamToClient) {
      const ep = resolveEndpoint()
      if (!ep) return json({ error: 'Unsupported AI provider' }, 400)
      const { readable, writable } = new TransformStream()
      const writer = writable.getWriter()
      const enc = new TextEncoder()
      ;(async () => {
        try {
          await callOpenAICompat(ep.apiUrl, ep.key, ep.model, (delta) => {
            writer.write(enc.encode(delta)).catch(() => {})
          })
        } catch (e) {
          await writer.write(enc.encode('__DB_AI_ERROR__:' + (e.message || 'AI 请求失败'))).catch(() => {})
        } finally {
          await writer.close().catch(() => {})
        }
      })()
      return new Response(readable, {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-cache',
          'X-AI-Prompt-Chars': String(promptChars),
          'X-AI-Image-Count': String(resolvedImages.length),
          ...CORS,
        },
      })
    }

    if (provider !== 'ollama') {
      const ep = resolveEndpoint()
      if (!ep) return json({ error: 'Unsupported AI provider' }, 400)
      result = await callOpenAICompat(ep.apiUrl, ep.key, ep.model)
    } else if (provider === 'ollama') {
      const localBase = (baseUrl || ollamaUrl || 'http://localhost:11434').replace(/\/$/, '')
      const b64Images = []
      for (const url of prompt.imageUrls) {
        const imgRes = await fetch(url)
        const imgBuf = await imgRes.arrayBuffer()
        b64Images.push(btoa(String.fromCharCode(...new Uint8Array(imgBuf))))
      }
      const res = await fetch(`${localBase}/api/generate`, {
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
    result = sanitizeModelText(result)

    return json({
      result,
      meta: {
        provider,
        model: resolvedModel,
        mode,
        elapsedMs: Date.now() - startedAt,
        promptChars,
        imageCount: resolvedImages.length,
      },
    })
  } catch (e) {
    return json({
      error: e.message,
      meta: {
        provider,
        model: resolvedModel,
        mode,
        elapsedMs: Date.now() - startedAt,
        promptChars,
        imageCount: resolvedImages.length,
      },
    }, e.status || 500)
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
    try {
      return await handleRequest(req, env)
    } catch (e) {
      // Top-level safety net: any uncaught throw must still carry CORS headers,
      // otherwise the browser reports a misleading "No Access-Control-Allow-Origin"
      // error instead of the real failure.
      return json({ error: '服务器内部错误：' + (e?.message || 'unknown') }, 500)
    }
  },
}

async function handleRequest(req, env) {
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
    const userId = user.sub

    if (path === '/api/board' && req.method === 'GET') return handleGetBoard(req, env, userId)
    if (path === '/api/board' && req.method === 'PUT') return handleSaveBoard(req, env, userId)
    if (path === '/api/upload' && req.method === 'POST') return handleUpload(req, env, userId)
    if (path === '/api/assets/cleanup' && req.method === 'POST') return handleCleanupAssets(req, env)
    if (path === '/api/ai' && req.method === 'POST') return handleAI(req, env)

    // Generated pages (Phase 2 durable persistence)
    if (path === '/api/generated/groups' && req.method === 'POST') return handleCreateGroup(req, env, userId)
    if (path === '/api/generated/pages' && req.method === 'POST') return handleCreatePage(req, env, userId)
    if (path === '/api/generated/versions' && req.method === 'POST') return handleCreateVersion(req, env, userId)

    let m
    if ((m = path.match(/^\/api\/generated\/versions\/([^/]+)\/content$/)) && req.method === 'GET') {
      return handleGetVersionContent(req, env, m[1], userId)
    }
    if ((m = path.match(/^\/api\/generated\/pages\/([^/]+)\/versions$/)) && req.method === 'GET') {
      return handleGetPageVersions(req, env, m[1], userId)
    }
    if ((m = path.match(/^\/api\/generated\/pages\/([^/]+)$/)) && req.method === 'DELETE') {
      return handleDeletePage(req, env, m[1], userId)
    }
    if ((m = path.match(/^\/api\/generated\/groups\/([^/]+)$/)) && req.method === 'DELETE') {
      return handleDeleteGroup(req, env, m[1], userId)
    }

    return json({ error: '未找到接口' }, 404)
}
