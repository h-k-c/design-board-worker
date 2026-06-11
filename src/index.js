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

async function softDeleteAsset(env, id, userId) {
  if (!env.DB || !id) return false
  const res = await env.DB.prepare(
    "UPDATE assets SET deleted_at = datetime('now') WHERE id = ? AND user_id = ?"
  ).bind(id, userId).run()
  return !!res?.meta?.changes
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

// ── AI call failure log ──────────────────────────────────────────────────────
// Only FAILED calls are persisted (success stores nothing). Self-bootstrapping:
// CREATE TABLE IF NOT EXISTS runs alongside the insert so it works even if the
// migration wasn't applied. Best-effort: never throws into the caller.
const AI_LOG_DDL = `CREATE TABLE IF NOT EXISTS ai_call_logs (
  id TEXT PRIMARY KEY, created_at TEXT NOT NULL, user_id TEXT, source TEXT,
  mode TEXT, component TEXT, instruction TEXT, error TEXT, raw_excerpt TEXT, context TEXT
)`
function clip(s, n) { s = (s == null ? '' : String(s)); return s.length > n ? s.slice(0, n) : s }

async function logAiFailure(env, userId, row = {}) {
  if (!env.DB) return
  try {
    await env.DB.batch([
      env.DB.prepare(AI_LOG_DDL),
      env.DB.prepare(
        `INSERT INTO ai_call_logs (id, created_at, user_id, source, mode, component, instruction, error, raw_excerpt, context)
         VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        crypto.randomUUID(), userId || null, clip(row.source || 'worker', 16),
        clip(row.mode, 40), clip(row.component, 60), clip(row.instruction, 500),
        clip(row.error, 1000), clip(row.rawExcerpt, 4000),
        row.context ? clip(JSON.stringify(row.context), 2000) : null,
      ),
    ])
  } catch (e) {
    console.error('[ai-log] insert failed:', e?.message || e)
  }
}

// POST /api/logs — client reports a failed AI call (fire-and-forget).
async function handleLogAi(req, env, userId) {
  let body = {}
  try { body = await req.json() } catch { /* ignore */ }
  await logAiFailure(env, userId, {
    source: 'client', mode: body.mode, component: body.component,
    instruction: body.instruction, error: body.error, rawExcerpt: body.rawExcerpt,
    context: body.context,
  })
  return json({ ok: true })
}

// GET /api/logs?limit=50 — read recent failures for this user.
async function handleGetLogs(req, env, userId) {
  if (!env.DB) return json({ logs: [] })
  const url = new URL(req.url)
  const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200)
  try {
    await env.DB.prepare(AI_LOG_DDL).run()
    const { results } = await env.DB.prepare(
      `SELECT id, created_at, source, mode, component, instruction, error, raw_excerpt, context
       FROM ai_call_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`
    ).bind(userId, limit).all()
    return json({ logs: results || [] })
  } catch (e) {
    return json({ logs: [], error: e?.message || 'query failed' })
  }
}

function mergeProviderSettings(existing = {}, incoming = {}) {
  const current = existing && typeof existing === 'object' ? existing : {}
  const next = incoming && typeof incoming === 'object' ? incoming : {}
  const provider = next.provider || current.provider || 'modelscope'
  const apiKeys = {
    ...(current.apiKeys && typeof current.apiKeys === 'object' ? current.apiKeys : {}),
  }
  const incomingKeys = next.apiKeys && typeof next.apiKeys === 'object' ? next.apiKeys : {}
  for (const [key, value] of Object.entries(incomingKeys)) {
    if (typeof value === 'string' ? value.trim() : value) apiKeys[key] = value
  }
  const activeKey = typeof next.apiKey === 'string' ? next.apiKey.trim() : next.apiKey
  if (activeKey) apiKeys[provider] = activeKey

  // Dedicated fill-model role (self-contained url+key+model). Take incoming when
  // provided, else keep existing — never let an absent field wipe it.
  const fillModel = (next.fillModel && typeof next.fillModel === 'object')
    ? next.fillModel
    : (current.fillModel && typeof current.fillModel === 'object' ? current.fillModel : undefined)
  const visionModel = (next.visionModel && typeof next.visionModel === 'object')
    ? next.visionModel
    : (current.visionModel && typeof current.visionModel === 'object' ? current.visionModel : undefined)

  // Guard against an un-hydrated client wiping configured lists/models: an EMPTY
  // incoming object/string must NOT overwrite an existing non-empty DB value.
  // (This caused the user's model dropdown to vanish when settings were saved
  // before they had been hydrated from the server.)
  const hasKeys = (o) => o && typeof o === 'object' && Object.keys(o).length > 0
  const keepObj = (key) => hasKeys(next[key]) ? next[key] : (current[key] ?? next[key])
  const keepStr = (key) => (typeof next[key] === 'string' && next[key].trim()) ? next[key] : (current[key] ?? next[key])

  return {
    ...current,
    ...next,
    provider,
    apiKeys,
    apiKey: apiKeys[provider] || current.apiKey || '',
    modelOptions: keepObj('modelOptions'),
    baseUrlOptions: keepObj('baseUrlOptions'),
    llmModel: keepStr('llmModel'),
    vlModel: keepStr('vlModel'),
    model: keepStr('model'),
    ...(fillModel ? { fillModel } : {}),
    ...(visionModel ? { visionModel } : {}),
  }
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

    async function readKey(key, required = false) {
      if (!key) return { text: '', missing: required }
      const object = await env.ASSETS.get(key)
      if (!object) return { text: '', missing: required }
      return { text: await object.text(), missing: false }
    }

    const [htmlPart, cssPart, jsPart] = await Promise.all([
      readKey(row.html_r2_key, true),
      readKey(row.css_r2_key),
      readKey(row.js_r2_key),
    ])
    if (htmlPart.missing) {
      return json({ error: 'Generated version content missing', versionId: id }, 404)
    }
    return json({ html: htmlPart.text, css: cssPart.text, js: jsPart.text })
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
    const screenshots = await loadJsonSetting(env, userId, 'screenshots') || []

    const mapped = cards.results.map(row => {
      const content = JSON.parse(row.content)
      const card = { id: row.id, type: row.type, x: row.x, y: row.y, w: row.w, h: row.h, ...content }
      if (row.linked_to) card.linkedTo = row.linked_to
      return card
    })

    return json({ cards: mapped, transform, settings, uiSettings, screenshots })
  } catch (e) {
    return json({ cards: [], transform: { x: 0, y: 0, scale: 1 } })
  }
}

async function handleSaveBoard(req, env, userId) {
  const { cards, transform, settings, uiSettings, screenshots } = await req.json()

  try {
    // Per-user board_state: update the user's row, insert it if absent.
    const upd = await env.DB.prepare('UPDATE board_state SET transform = ? WHERE user_id = ?')
      .bind(JSON.stringify(transform), userId).run()
    if (!upd.meta?.changes) {
      await env.DB.prepare('INSERT INTO board_state (user_id, transform) VALUES (?, ?)')
        .bind(userId, JSON.stringify(transform)).run()
    }
    const existingSettings = await loadJsonSetting(env, userId, 'provider_settings')
    await saveJsonSetting(env, userId, 'provider_settings', mergeProviderSettings(existingSettings, settings))
    await saveJsonSetting(env, userId, 'ui_settings', uiSettings)
    if (screenshots) await saveJsonSetting(env, userId, 'screenshots', screenshots)

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

async function handleDeleteAsset(req, env, id, userId) {
  const ok = await softDeleteAsset(env, id, userId)
  return json({ ok })
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

async function handleAI(req, env, userId) {
  const startedAt = Date.now()
  const body = await req.json()
  // D1 is the source of truth for AI settings. The frontend may have stale
  // localStorage/request-body values, so model calls read the authenticated
  // user's saved provider_settings directly from the database.
  const dbSettings = (userId && await loadJsonSetting(env, userId, 'provider_settings')) || {}
  const provider = dbSettings.provider || 'qwen'
  // Per-provider token: use this provider's own saved key, so a key set for a
  // different provider (e.g. a Groq gsk_ token) is never sent to ModelScope.
  const apiKey = (dbSettings.apiKeys && dbSettings.apiKeys[provider]) || dbSettings.apiKey || ''
  const model = dbSettings.llmModel || dbSettings.model || ''
  const vlModel = dbSettings.vlModel || ''
  const baseUrl = dbSettings.baseUrl || ''
  const {
    mode = 'single',
    imageUrl,
    images = [],
    analyses = [],
    notes = [],
    context,
    lmstudioUrl,
    ollamaUrl,
    // Reference-driven page generation fields
    target = '',
    platform = 'miniprogram',
    maxPages = 5,
    referenceMode = 'strict',
    generationScope = 'core',
    appName = '',
    designIntent = '',
    globalStyle = null,
    designSystem = null,       // screen-generate/variants: full M3 theme
    variantOptions = null,     // screen-variants: {variantCount,creativeRange,aspects}
    globalNav = null,
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
  } = body
  // Reasoning is provider/model-specific. No frontend global toggle. Enabled by
  // default where it helps quality (analysis / planning / explosion), but turned
  // OFF for the code-emitting page steps: thinking there mostly burns tokens and
  // latency without improving the HTML, so disabling it noticeably speeds up
  // page generation. (Revisit per-mode if a step's quality regresses.)
  const NO_REASONING_MODES = new Set(['page-generate', 'page-edit', 'page-block-edit', 'component-fill', 'page-skeleton', 'page-restyle', 'spec-draft', 'spec-extract', 'screen-generate', 'screen-variants'])
  // NOTE: a component edit stays no-reasoning. Enabling reasoning_effort:'high'
  // burned the token budget and truncated the small props JSON → parse failure.
  // The big model + an explicit edit prompt is enough without thinking.
  const enableReasoning = !NO_REASONING_MODES.has(mode)

  // Platform → concrete layout / viewport constraints injected into prompts.
  function platformSpec(p) {
    if (p === 'app') return {
      label: 'App 移动端（iOS/Android 原生风格）',
      rules: '画布按移动端竖屏设计，固定设计视口 390px 宽；根容器 width:100%、min-height:100vh，铺满当前视口；不要再写更小的 max-width 居中壳；触控友好（点击区 ≥44px）；底部 tabbar / 顶部 navbar 按需要；不要桌面多列布局。',
    }
    if (p === 'web') return {
      label: 'Web 网页（桌面优先，响应式）',
      rules: '桌面优先并响应式；内容容器 max-width 960–1200px 居中；可用多列/栅格布局；适配窄屏断点。',
    }
    // 默认（含空串/未知/未选）= 微信小程序，绝不默认 web。
    return {
      label: '微信小程序',
      rules: '画布按微信小程序设计，固定设计视口 375px 宽；根容器 width:100%、min-height:100vh，铺满当前视口；不要再写更小的 max-width 居中壳；可表现小程序顶部导航语义，但不要画手机边框/刘海/浏览器外壳；卡片化、圆角、留白克制；触控友好；不要桌面多列布局、不要浏览器地址栏式元素。',
    }
  }
  const pf = platformSpec(platform)
  // Platform-derived viewport. The explicit `platform` is authoritative — only
  // honour uiContract.viewport when it matches (avoids a stale 'web' viewport
  // baked into an old contract overriding a freshly-picked App/小程序 platform).
  const platformViewport = platform === 'app'
    ? { platform, width: 390, height: 844 }
    : platform === 'web'
      ? { platform: 'web', width: 1280, height: 720 }
      : { platform: 'miniprogram', width: 375, height: 812 }
  const viewport = (uiContract?.viewport && uiContract.viewport.platform === platform)
    ? uiContract.viewport
    : platformViewport
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
- 色彩类：先用一句话描述你在图中实际看到的颜色（如"偏暖的砖红""低饱和的灰蓝"），再给出对应的十六进制色号（如 #1A1A2E、#E8E3D9），并说明用在哪里（背景/文字/强调/边框），给出主色、辅色、点缀色。
- 【取色必须逐一核对，颜色名与 hex 必须一致】每给一个色值，都要回头确认它和你在图中看到的那块颜色是同一个颜色：说"红色"就必须配红色系 hex（如 #C0392B），绝不能"红色"配出蓝色/绿色 hex。label 和 reason 里写的颜色名，必须与该条 prompt 里的十六进制在色相上完全一致（红↔红、蓝↔蓝、暖灰↔暖灰）。如果不确定某个具体色值，就以你看到的颜色名为准、给出最接近的 hex，宁可保守也不要张冠李戴。
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
    const imageUrls = imageUrl
      ? [imageUrl]
      : images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildPolishPrompt() {
    return {
      systemPrompt: '你是一名资深设计文案编辑。请润色用户提供的文案，保留原始结构和内容，让表达更流畅自然。',
      userPrompt: context || '',
      imageUrls: [],
    }
  }

  function buildPagePlanPrompt() {
  // ── Product spec engine ──────────────────────────────────────────────────
  // Turns a one-liner (spec-draft) or a pasted doc (spec-extract) into ONE shared
  // structured spec JSON. The spec is the "骨肉" (what/which pages/what data),
  // parallel to the aesthetic DNA (the "脸"). Page list here is authoritative.
  // Page-centric spec: `pages` is the required heart (the user mostly cares about
  // "what functional pages exist"). entities is OPTIONAL data-grounding; modules/
  // flows are OPTIONAL extras — only when the doc/idea warrants them.
  const SPEC_SHAPE = `{
  "appName": "产品名（简体中文）",
  "tagline": "一句话定位",
  "pages": [ { "id": "kebab-唯一", "title": "页面中文名", "purpose": "这页给谁用、解决什么", "navKey": "底栏tab键名，子页面留空", "functions": ["这页的功能点1","功能点2"], "keyContent": ["该页要呈现的关键内容/区块"] } ],
  "entities": [ { "name": "数据实体名（如 商品/订单/课程，可选）", "fields": [ { "name": "字段名", "type": "text|number|date|enum|image|bool", "example": "示例值" } ] } ]
}`
    const SPEC_RULES = `规则：
- 核心是 pages（功能页面清单），必须给且尽量完整；entities 可选——文档里涉及具体数据时才给，用于让列表/详情有据可依，不强求。modules/flows 不需要。
- 全部面向人阅读的文本一律简体中文；只有 id/navKey 这类技术标识用 kebab 英文。
- pages 要覆盖完整体验：既有底栏主页面（navKey 非空），也要有子页面/详情页（navKey 留空），别只列导航级页面。
- functions 写这页能做什么（动作/能力）；keyContent 写这页要呈现什么内容，都要实打实、贴产品领域，不要泛泛（"一些内容"）。
- 若给了 entities，字段要具体真实（如电商：商品名/价格/库存/销量），不要占位。
- 严格只返回一个 JSON 对象，无解释/thought/markdown。`

    function buildSpecDraftPrompt() {
      const oneLiner = body.specPrompt || target || appName || ''
      const systemPrompt = `你是资深产品经理。根据用户给的一句话产品想法，起草一份结构化「产品规格」。你要合理补全这个产品应有的功能模块、数据实体与页面清单，使其成为一个可信、完整的产品蓝图。\n输出严格符合以下结构：\n${SPEC_SHAPE}\n${SPEC_RULES}`
      const userPrompt = `目标平台：${pf.label}\n产品想法（一句话）："${oneLiner}"\n\n请据此起草完整的产品规格 JSON。`
      return { systemPrompt, userPrompt, imageUrls: [] }
    }

    function buildSpecExtractPrompt() {
      const doc = String(body.docText || '').slice(0, 12000)
      const systemPrompt = `你是资深产品分析师。用户会给你一份产品文档（PRD/功能清单/需求稿，markdown 或纯文本）。你要把它**抽取并归一**成结构化「产品规格」，忠于文档内容：文档里明确写了的就照搬，没写但该产品显然需要的可合理补全，但不要凭空发明与文档相悖的功能。\n输出严格符合以下结构：\n${SPEC_SHAPE}\n${SPEC_RULES}`
      const userPrompt = `目标平台：${pf.label}\n\n【产品文档原文】\n${doc || '（空）'}\n\n请抽取成产品规格 JSON。`
      return { systemPrompt, userPrompt, imageUrls: [] }
    }

    if (mode === 'spec-draft') return buildSpecDraftPrompt()
    if (mode === 'spec-extract') return buildSpecExtractPrompt()

    // Spec-fused page plan: pages come from the spec (authoritative), the aesthetic
    // DNA provides the visual baseline (globalStyle). The model fleshes each page
    // into sections/components/contentHints but does NOT invent or reorder pages.
    const specPages = Array.isArray(body.specPages) && body.specPages.length ? body.specPages : null
    if (specPages && mode === 'page-plan') {
      const pagesList = specPages.map((p, i) => {
        const fn = (Array.isArray(p.functions) ? p.functions : []).join('；')
        const kc = (Array.isArray(p.keyContent) ? p.keyContent : []).join('；')
        return `${i + 1}. id="${p.id || `page-${i + 1}`}" title="${p.title || ''}" navKey="${p.navKey || ''}" purpose="${p.purpose || ''}" 功能：${fn} 关键内容：${kc}`
      }).join('\n')
      const specAppName = body.appName || ''
      const specHeader = `产品规格（权威页面清单，必须逐页生成，不要增删改）：
${pagesList}`

      // The raw aesthetic DNA is the PRIMARY visual input. Put it first and
      // be explicit about what to extract.
      const rawDNA = String(body.aestheticDNA || '').slice(0, 3500)
      const dnaBlock = rawDNA
        ? `【⚠️ 审美画像——这是本页面规划的视觉宪法，globalStyle 必须严格从中逐字提取每一个具体数值，禁止凭空发明】
• 从中直接复制以下内容到 globalStyle 对应字段：palette 里的十六进制色值列表（含中文角色名）、typography 字体族/字号/字重、radius 圆角值、shadow 阴影参数、spacing 间距值、gradients 渐变
• 从 design-bubbles 里提取 componentRules（组件规则）、motionRules（动效规则）、avoid（禁止项）→ 填入 globalStyle 对应数组
• feel 对象（spacing/fontBase/cardStyle/shadowLevel/border/iconStyle/gradientHeader/accentBar/glass）也必须与 DNA 一致
• 不要把"保留品牌色相"当成可以写别的颜色——DNA 里给了具体 #RRGGBB 你就照抄到 palette
--------
${rawDNA}
--------

${context ? `【辅助语义证据（补充）】\n${String(context).slice(0, 1500)}` : ''}`
        : `【审美画像辅助证据】\n${String(context || '').slice(0, 3000)}`

      const systemPrompt = `你是一名资深产品设计总监。你将根据一份「产品规格」（权威页面清单）和「审美画像」（视觉宪法，含精确的色值/字体/圆角/阴影/间距等具体数值），为一个 ${pf.label} 产品规划页面结构。
要求：
- 【页面集权威】上面的产品规格里的 N 个页面就是你本次必须规划的全部页面，**一页不能少、一页不能多、不能改名、不能改 id**。逐页生成，保持给定顺序。
- 【视觉从画像来、不从凭空造】globalStyle 里的每一项都必须能从上面的审美画像中找到出处：palette 里的十六进制色值一个字不改地照抄过来；typography/radius/shadow/spacing/gradients 里的所有数值全部从画像中提取，不要自己编。签名法则 signature 数组也全部从画像中照搬。
- 每个给定页面的 sections 必须根据该页的"功能"与"关键内容"来编排：把功能和内容拆成具体的区块/区域，每个区块写明要用的组件（如 Banner/TagChips/CardGrid/ListFeed/StatGrid/SectionHeader/SearchBar/DetailHeader/KeyValueList/MediaCard/Timeline/NoticeBar/ProductCard/CellGroup/ProfileHeader/Steps/Progress/ReviewList/BottomNav）、变体、内容要点（contentHints：实打实的文案方向，让后续小模型有据可依）。
- 【子页面】navKey 为空的页面是子页面/详情页，也要完整规划 sections。
- 【底栏导航必须对齐】bottomNav.items 必须正好由规格里 **navKey 非空的那些页面**构成：每个 item 的 key **必须等于**对应页面的 navKey、label=该页中文名、icon 选语义合适的英文图标名（home/list/search/user/grid/book/star/bell/settings 等）；顺序与这些 tab 页一致，2-5 项。navKey 为空的子页面不进 bottomNav。**key 与页面 navKey 不一致会导致底栏失效，务必逐字对齐。**
- 目标平台为「${pf.label}」，规划必须贴合该平台的形态：${pf.rules}
- 只输出页面规划的设计层信息，绝对不要输出任何 HTML / CSS / JS 代码。
- **语言：所有面向人阅读的文本一律用简体中文**。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要额外说明文字。`
      const userPrompt = `${dnaBlock}

${specHeader}

产品名：${specAppName || '（从规格提取）'}
目标平台（platform）：${pf.label}

请输出严格符合下面结构的 JSON：
{
  "appName": "${specAppName || ''}",
  "designIntent": "",
  "globalStyle": {
    "layout": "",
    "palette": [],
    "typography": "",
    "radius": "",
    "shadow": "",
    "spacing": "",
    "gradients": [],
    "signature": [],
    "componentRules": [],
    "motionRules": [],
    "avoid": [],
    "feel": { "spacing": 16, "fontBase": 14, "cardStyle": "shadow", "shadowLevel": "soft", "border": "hairline", "iconStyle": "tint", "gradientHeader": true, "accentBar": false, "glass": false }
  },
  "bottomNav": { "items": [ { "key": "...", "icon": "iconName", "label": "..." } ] },
  "sharedComponents": [],
  "pages": [ { "id": "...", "title": "...", "route": "...", "navKey": "..." 或 "", "purpose": "...", "sections": [ { "slug": "kebab", "component": "组件名", "variant": "变体", "contentHints": ["文案方向1","文案方向2"] } ] } ]
}

请严格按规格页面清单逐页输出 pages 数组，不要增删改。`
      return { systemPrompt, userPrompt, imageUrls: [] }
    }

    const systemPrompt = `你是一名资深产品设计总监。你将根据已有的 style-group / aesthetic DNA 与 design-bubbles（大爆炸）具体因子，为一个 ${pf.label} 产品规划页面结构。
要求：
- **尽量用满页面预算：目标就规划 ${effectivePageLimit} 个页面**（除非产品确实极简，否则不要少于 ${Math.max(1, Math.min(effectivePageLimit, 4))} 个）。不要只生成几个底栏 tab 页就草草收场。
- **必须覆盖完整体验，包含"子页面/详情页"，不要只有导航级页面**：典型如 列表页→详情页、搜索页→结果页、首页→专题/文章详情、个人中心→子页（设置/收藏/消息）、表单/流程页。底栏 tab 是主页面，子页面是从主页面点进去的二级页面。
- 这些**子页面 navKey 留空**（它们不对应底栏的某一项），但仍要规划出来、用满页面数。
- 当前生成范围：${planScope === 'single' ? '单页探索，只规划 1 个最关键页面。' : '核心流程，规划能闭环的关键页面 + 关键子页面。'}
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
    "radius": "",
    "shadow": "",
    "spacing": "",
    "gradients": [],
    "signature": [],
    "componentRules": [],
    "motionRules": [],
    "avoid": [],
    "feel": {
      "spacing": 16,
      "fontBase": 14,
      "cardStyle": "shadow",
      "shadowLevel": "soft",
      "border": "hairline",
      "iconStyle": "tint",
      "gradientHeader": true,
      "accentBar": false,
      "glass": false
    }
  },
  "globalNav": {
    "type": "bottom-tab",
    "items": [ { "key": "home", "label": "首页", "icon": "home" } ]
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
- 页面数量必须在 1-${effectivePageLimit} 个之间，${planScope === 'single' ? '只能输出 1 个页面。' : `**优先用满到 ${effectivePageLimit} 个**；不要为了精简而砍掉有价值的子页面/详情页。`}
- appName / designIntent 用简洁中文概括产品与设计意图。
- **globalStyle 是这个 app 唯一的、完整的结构化设计系统**，后续每个页面都只靠它来落地视觉（不会再读原始 DNA 长文），所以你必须把设计 DNA / 大爆炸因子里的**全部可落地数值都搬进来、一个不漏**：
  - palette：5-7 条，每条形如 "#C8102E 主色/强调" 这样"十六进制 + 中文角色"，覆盖主色 primary、辅助色 secondary、第三强调 tertiary、accent、正文/中性、背景/表面；来自多张素材的不同色相要分角色保留，禁止把所有颜色合并成一个粉/红/蓝主色。
  - 色彩用法要写进 componentRules/signature：primary 只给主 CTA/激活态/核心标题；secondary 给分类 chip/筛选/图标淡底；tertiary/accent 给角标、计数、进度、价格/风险/新内容等小面积强调；中性色和背景只做承托。页面必须能看见至少 3 个色彩家族，但比例要克制。
  - typography：字体族 + 各级字号字重，如 "标题 Plus Jakarta 700 22px / 正文 Inter 400 15px/1.6 / 标签 13px 500"。
  - radius：圆角体系，如 "卡片 16、按钮 12、标签 999"。
  - shadow：完整 box-shadow 配方，如 "0 8px 24px rgba(0,0,0,.08)"。
  - spacing：间距阶，如 "4/8/12/16/24/32"。
  - gradients：签名渐变(如有)，每条写完整 CSS。
  - signature：3-6 条**最有辨识度的细节处理**(毛玻璃、特定卡片质感、强调色用法、图标风格等)，确保高级感不丢。
  - componentRules：卡片/按钮/标签/列表的具体处理规则。
  - **feel：把审美画像的"气质"蒸馏成组件模板能直接吃的 token**（后续组件化渲染的关键，必须给）。**严格按大爆炸维度对齐填写**：
    - 〔布局空间维度〕spacing：基准间距 px(6-32)，密集风格给小、疏朗给大。
    - 〔字体文本维度〕fontBase：基准字号 px(12-18)，由正文字号定。
    - 〔材质质感/CSS参数维度〕cardStyle："shadow"(投影卡)|"outline"(描边卡)|"flat"(扁平)|"glass"(毛玻璃)。
    - 〔材质质感维度〕shadowLevel："flat"(无影)|"soft"(柔和)|"elevated"(强浮起)，看 DNA 阴影强弱。
    - 〔材质质感维度〕border："none"(无边)|"hairline"(发丝边)。
    - 〔色彩光影/材质维度〕iconStyle："tint"(主色淡底线性图标)|"solid"(主色实底白图标)|"plain"(纯线性无底)。
    - 〔材质质感维度〕gradientHeader：横幅是否渐变(true/false)，看 DNA 有无签名渐变。
    - 〔构图层级维度〕accentBar：卡片/列表是否加主色强调条(true/false)，权威/厚重可开。
    - 〔材质质感维度〕glass：是否毛玻璃(true/false)，看 signature 有无玻璃感。
  这一步等于"先建设计系统"，宁可写满也不要含糊——精度全靠它锁住。
- **globalNav 是整个 app 唯一的一份共享导航，定一次、全页通用**：type 取 bottom-tab / top-nav / sidebar / none；items 是 2-5 个导航项，每项含 key（英文标识）、label（简体中文）、icon（英文图标名，如 home/list/search/user）。所有页面都必须复用**完全相同**的这套 items，绝不允许某些页面多一项少一项或改名。
- 每个 page 用 navKey 标注它对应 globalNav 里哪一项被激活（navKey 必须等于某个 globalNav.items[].key）；不需要导航的页面（如登录/详情）navKey 留空、type 仍按全局。
- 图像提示词、图片描述、单图 AI 分析只能帮助理解产品语义和氛围，不得作为主要视觉规范。
- globalStyle.layout 要体现 ${pf.label} 的形态约束。
- 每个 page 的 sections / components / states 用具体的**简体中文**短语数组（例如「顶部横幅」「错题卡片列表」「批量管理」），不要用英文短语。
- 每个 page 必须输出 layoutIr：它是给前端绘制“页面正在被画出来”的轻量蓝图，不是最终代码。regions 只描述 5-10 个主要视觉区块的位置、尺寸、类型、中文标签和意图，坐标必须使用当前固定视口像素：x/y/w/h 都是数字。移动端宽度必须贴合 ${viewport.width}px；Web 可按 ${viewport.width}px 设计视口。type 可用 header、hero、tabs、grid、list、card、chart、form、tabbar、action、text、media 等。layoutIr 不要输出 HTML/CSS，不要写长文。
- 再次强调：除 id / route / navKey / slug / CSS 值外，所有词条文本必须是简体中文。
- 不要输出任何代码。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  // Consistency-by-construction: derive a deterministic shared "chrome" (color
  // tokens + the exact nav markup) from globalStyle/globalNav so every page reuses
  // identical chrome instead of the model re-inventing it per page. This is what
  // keeps the whole app visually unified even with a fast/cheap model.
  function buildSharedChrome(gs, nav, activeNavKey) {
    const hexes = []
    try {
      const s = JSON.stringify(gs || {})
      const re = /#[0-9a-fA-F]{6}\b/g
      let m
      while ((m = re.exec(s)) && hexes.length < 8) {
        const h = m[0].toUpperCase()
        if (!hexes.includes(h)) hexes.push(h)
      }
    } catch {}
    const primary = hexes[0] || '#111111'
    const hexList = hexes.join('、')

    // Inline line-icons keyed by common icon names (Tailwind CDN has no icon font).
    const ICONS = {
      home: '<path d="M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10"/>',
      list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
      category: '<path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/>',
      grid: '<path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/>',
      search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>',
      user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
      profile: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
      mine: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
      bell: '<path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 01-3.4 0"/>',
      star: '<path d="M12 3l2.9 5.9 6.5.9-4.7 4.6 1.1 6.5L12 18l-5.8 3 1.1-6.5L2.6 9.8l6.5-.9z"/>',
      heart: '<path d="M12 21s-7-4.5-9.5-9A5 5 0 0112 5a5 5 0 019.5 7c-2.5 4.5-9.5 9-9.5 9z"/>',
      settings: '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 00-.1-1l2-1.5-2-3.4-2.3 1a7 7 0 00-1.7-1l-.3-2.5h-4l-.3 2.5a7 7 0 00-1.7 1l-2.3-1-2 3.4 2 1.5a7 7 0 000 2l-2 1.5 2 3.4 2.3-1a7 7 0 001.7 1l.3 2.5h4l.3-2.5a7 7 0 001.7-1l2.3 1 2-3.4-2-1.5c.1-.3.1-.7.1-1z"/>',
    }
    const iconSvg = (name) => {
      const inner = ICONS[(name || '').toLowerCase()] || '<circle cx="12" cy="12" r="9"/>'
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="w-[22px] h-[22px]">${inner}</svg>`
    }
    const items = (nav && Array.isArray(nav.items)) ? nav.items.filter(it => it && it.label) : []
    const navType = nav?.type || 'none'
    let navHtml = ''
    if (items.length && navType !== 'none') {
      const lis = items.map(it => {
        const active = it.key && it.key === activeNavKey
        const cls = active
          ? `text-[${primary}] font-semibold`
          : `text-neutral-400`
        return `    <button data-nav-key="${it.key || ''}" class="flex-1 flex flex-col items-center gap-1 py-2 ${cls}">
      ${iconSvg(it.icon)}
      <span class="text-[11px] leading-none">${it.label}</span>
    </button>`
      }).join('\n')
      if (navType === 'bottom-tab') {
        navHtml = `<nav data-block="global-nav" data-block-label="底部导航" class="fixed bottom-0 left-0 right-0 z-30 flex bg-white/95 backdrop-blur border-t border-black/5 px-2">
${lis}
  </nav>`
      } else if (navType === 'top-nav') {
        navHtml = `<nav data-block="global-nav" data-block-label="顶部导航" class="sticky top-0 z-30 flex bg-white/95 backdrop-blur border-b border-black/5 px-2">
${lis}
  </nav>`
      } else if (navType === 'sidebar') {
        const sideLis = items.map(it => {
          const active = it.key && it.key === activeNavKey
          const cls = active ? `bg-[${primary}]/10 text-[${primary}] font-semibold` : `text-neutral-500`
          return `      <button data-nav-key="${it.key || ''}" class="w-full text-left px-3 py-2 rounded-lg ${cls}">${it.label}</button>`
        }).join('\n')
        navHtml = `<nav data-block="global-nav" data-block-label="侧边导航" class="w-[120px] shrink-0 flex flex-col gap-1 p-2 border-r border-black/5">
${sideLis}
  </nav>`
      }
    }
    return { hexList, navHtml, navType, primary, hexCount: hexes.length }
  }

  function buildPageGeneratePrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle, null, 2) : '（无，按 designIntent 自行合理推断）'
    const contractStr = uiContract ? JSON.stringify(uiContract, null, 2) : '（无）'
    const pageStr = page ? JSON.stringify(page, null, 2) : '（无）'
    const navStr = globalNav && Array.isArray(globalNav.items) && globalNav.items.length
      ? JSON.stringify(globalNav)
      : ''
    const navRule = navStr
      ? `全局共享导航（globalNav，全 app 唯一）：${navStr}\n当前页 navKey：${page?.navKey || '（无）'}\n如果 globalNav.type 不是 none，本页必须输出一个导航区块，**逐字复用 globalNav.items 的 label/顺序/数量，绝不增删改名**；只把 navKey 对应的那一项设为激活态。type=bottom-tab 放底部、top-nav 放顶部、sidebar 放侧边。`
      : '本页没有全局导航约束，按 page 规划自行决定是否需要导航。'
    if (directHtml) {
      const chrome = buildSharedChrome(globalStyle, globalNav, page?.navKey)
      const chromeRule = [
        chrome.hexList
          ? `## 强制统一配色（全 app 共享，直接用这些十六进制值）\n- 全 app 唯一的配色就是这几个值：${chrome.hexList}。**主色是 ${chrome.primary}**，但主色不是唯一强调色。\n- 用 Tailwind 任意值**直接写十六进制**：\`bg-[${chrome.primary}]\` \`text-[${chrome.primary}]\` \`border-[${chrome.primary}]\`，**不要用 var() 变量、不要自创其它色值**。\n- **本页必须按角色分配多色，而不是全页只用主色**：primary 用于主 CTA/当前激活态/最重要标题；palette 中的 secondary/tertiary/accent 用于分类 chip、图标淡底、角标、计数、进度、价格/风险/新内容等小面积强调。每页正文至少可见 primary + 一个辅助/强调色 + 中性/表面色。避免标题、图标、chip、按钮全部染成同一个粉/红/蓝。`
          : '',
        chrome.navHtml
          ? `## 强制共享导航（必须原样粘贴，全 app 逐字一致）\n- 本页必须包含下面这段导航区块 HTML，**原样粘贴，不要增删改导航项的文字/数量/顺序/图标**，只允许保留我已设好的当前页激活态：\n\`\`\`html\n${chrome.navHtml}\n\`\`\`\n- ${chrome.navType === 'bottom-tab' ? '它是固定底部栏，请给页面主内容底部留出 pb-20 的空间避免被遮挡。' : chrome.navType === 'top-nav' ? '它是顶部栏，放在页面最上方。' : '它是侧边栏，与主内容左右并排（外层用 flex）。'}`
          : '',
      ].filter(Boolean).join('\n\n')
      const systemPrompt = `你是世界顶级的产品 UI 设计师兼前端工程师，作品达到 Dribbble / Mobbin 精选水准。你将为「${pf.label}」产品的单个页面，直接产出一份自包含、可立即预览、视觉精致的前端代码（HTML + 内联 CSS + 必要 JS）。不要线框图、不要示意稿，要像真实上线产品的第一屏。

## 用 Tailwind（重要）
- 预览环境**已加载 Tailwind CSS（Play CDN，含 forms / container-queries 插件）**。请**直接用 Tailwind 工具类写 HTML**，不要手写大段 CSS。
- 把 globalStyle 的具体值用 Tailwind **任意值语法**落地：\`bg-[#C8102E]\` \`text-[#1a1a1a]\` \`text-[15px]\` \`font-semibold\` \`rounded-[16px]\` \`shadow-[0_8px_24px_rgba(0,0,0,0.08)]\` \`p-4\` \`gap-3\` 等。颜色/圆角/阴影/字号一律用 globalStyle 里的真实值。
- 间距/字阶/圆角优先用 Tailwind 标准刻度（p-4=16px 等），需要精确值时用任意值。
- \`css\` 字段**只放 Tailwind 做不到的东西**（如 @keyframes 自定义动画、复杂渐变背景），通常很短或为空字符串。

## 平台约束
- ${pf.rules}
- 固定设计视口 ${viewport.width}x${viewport.height}。移动端根容器 w-full、min-h-screen 铺满，禁止更小的 max-width 居中壳导致左右留白；Web 才可用居中容器。

## 视觉依据（最重要）
- **globalStyle 是这个 app 完整的结构化设计系统（已从设计 DNA 蒸馏好），是你落地视觉的唯一主依据**：必须严格复用它的 palette / typography / radius / shadow / spacing / gradients / signature 的**具体值**，一个都不要改，并把它们落进 :root token。
- 下方 context 只是少量补充语义/内容方向，**不承载完整视觉**；视觉一切以 globalStyle 为准。
- ${referenceRule}

${chromeRule || ''}

## 设计系统纪律（决定"高级感"，必须严格遵守）
1. **统一令牌**：所有颜色/圆角/阴影/字号都来自 globalStyle 的具体值，用 Tailwind 任意值表达，全页一致，不要随手编新值。
2. **间距用 8pt 体系**：4/8/12/16/24/32/48/64（对应 p-1/p-2/p-3/p-4/p-6/p-8/p-12/p-16）。同组元素间距一致，区块之间留白要慷慨、有呼吸感。
3. **字阶有明确层级**：至少 4 级字号 + 字重对比（如 13/15/20/28，weight 400/500/700），正文行高 1.5–1.7，标题更紧。一屏内信息层级 ≥3 层。
4. **色彩必须有角色分工（关键，别做成单色皮肤）**：克制 ≠ 只用一个主色。主色（globalStyle 第一个色值）要出现在主 CTA/激活态/最重要标题，但不能包办所有强调；globalStyle 里的 secondary/tertiary/accent 必须落到分类 chip、图标淡底、角标、计数、进度、价格/风险/新内容等小面积位置。每页至少可见 3 个色彩家族：中性/表面色 + primary + secondary/tertiary/accent。比例约 60–70% 表面与正文、20–30% primary、10–15% 辅助/强调色。避免标题、图标、chip、按钮全部同色，也避免彩虹乱喷。对比度达到 WCAG AA。
5. **一个视觉焦点**：首屏有明确主视觉/主操作，其余元素服从它，不要平铺堆砌。
6. **组件细节**：圆角统一、阴影柔和有层次（避免生硬黑边）、边框用低对比分隔线、交互元素有 hover/active/focus 态。
7. **真实内容**：所有文案、数字、列表项、标签都是贴合产品的具体中文内容。严禁 Lorem ipsum、"示例标题"、"暂无内容"、大面积灰色占位块。没有真实图片时用 CSS 渐变、内联 SVG 图标、纯 CSS 插画/数据可视化形状替代。
8. **状态完整**：覆盖 page.states，至少实现 hover / active / selected / empty / loading / error 中的 4 种。

## 内容要求
- 必须实现 page.sections / page.components，整页 8–14 个具体内容单元，不同 pageType 要有不同构图（详情页强调阅读区、列表页强调浏览、表单页强调流程、概览页强调数据）。
- 必须建立可见的 design system：导航/标题区、内容容器、卡片、按钮、标签、列表/图表至少覆盖 5 类。

## 块级可编辑结构（强制，供后续局部编辑 + 逐块揭示动画）
- 每个 page.sections 逻辑分区包成 \`<section data-block="<kebab-slug>" data-block-label="<简短中文标签>" class="<tailwind 类>"> ... </section>\`，slug 页面内唯一、语义化（如 hero / category-nav / article-body），不嵌套块、不漏分区。

## 技术约束
- 自包含、可直接渲染在沙箱 iframe 内。Tailwind 已由预览环境注入，你只写工具类即可。
- JS 只为必要交互（标签切换、展开等），写在 js 字段，**不要自己引入任何外部脚本/CDN**（除 Tailwind 外的外链脚本会被安全策略剥离）。可用 https 图片 URL、data-uri、内联 SVG。
- 用语义化 HTML + Tailwind 工具类（flex/grid 用 flex/grid 类）。
- 严格只返回一个 JSON 对象，不要 Markdown 代码块、不要解释、不要 thinking。`
      const userPrompt = `产品名（appName）：${appName || ''}
设计意图（designIntent）：${designIntent || ''}
目标平台（platform）：${pf.label}

结构化设计系统（globalStyle，唯一主视觉依据，严格复用其具体值）：
${styleStr}

${navRule}

补充语义（context，仅内容方向，不承载视觉）：
${context || '（无）'}

当前要生成的页面（page）：
${pageStr}

请输出严格符合下面结构的 JSON（字段名必须完全一致）：
{
  "pageId": "${page?.id || 'home'}",
  "title": "页面中文标题",
  "html": "完整页面 body 内 HTML，用 Tailwind 工具类组织，按上面块级结构包 section",
  "css": "通常为空字符串；只在 Tailwind 做不到时放少量自定义 CSS（如 @keyframes）",
  "js": "必要交互 JS，可为空字符串",
  "notes": ["2-4 条 globalStyle 到 Tailwind 类的映射，简短中文"]
}

约束：
- pageId 与 page.id 一致；title 用简洁中文。
- html 不要包含 <html>/<head>/<body> 外壳，只输出 body 内部内容（页面级 wrapper 可有）。
- 严格复用 globalStyle 的具体数值（颜色/字体/圆角/阴影/间距/渐变/签名细节）；遵守 globalStyle.avoid。
- 若有 globalNav 约束：导航区块的项必须**逐字复用 globalNav.items**（label/顺序/数量完全一致），只改激活项，不要自由增删改名。
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
      const systemPrompt = `你是世界顶级的产品 UI 设计师兼前端工程师，作品达到 Dribbble / Mobbin 精选水准。为「${pf.label}」生成一个视觉精致、可直接预览的单页界面。你必须按 NDJSON 区块协议输出，让浏览器收到一个完整区块就立刻渲染一块——所以区块顺序就是页面从上到下被"画"出来的顺序。

## 平台与视口
- ${pf.rules}
- 固定视口 ${viewport.width}x${viewport.height}；移动端根内容 width:100%，不要写更小 max-width 居中壳。

## 视觉依据（最重要）
- **globalStyle 是这个 app 完整的结构化设计系统（已从设计 DNA 蒸馏好），是你落地视觉的唯一主依据**：必须严格复用它的 palette / typography / radius / shadow / spacing / gradients / signature 里的**具体值**，一个都不要改。
- 下方 context 只是少量补充语义/内容方向，**不承载完整视觉**，不要指望它给设计；视觉一切以 globalStyle 为准。
- ${referenceRule}

## 设计系统纪律（决定高级感，严格遵守）
- **令牌化**：page-base 区块的 CSS 里把 globalStyle 的值落成 :root token（colors/spacing/radius/shadow/font/gradients），后续区块只引用 token。
- **signature 细节必须体现**：globalStyle.signature 里那几条辨识度细节要真正落到对应组件上，别只做通用卡片。
- **8pt 间距体系**(4/8/12/16/24/32/48)，同组间距一致，区块之间留白慷慨。
- **字阶分明**：≥4 级字号 + 字重对比，正文行高 1.5–1.7；一屏 ≥3 层信息层级。
- **克制配色**：DNA 主色 + 中性灰阶，强调色只给关键 CTA/选中态，对比度达 AA。
- **一个视觉焦点**，其余服从它；圆角统一、阴影柔和分层、交互元素有 hover/active 态。
- **真实内容**：所有文案/数字/列表项都是贴合产品的具体中文，禁止灰色占位块、Lorem ipsum、示例标题、空白卡片。无图片时用 CSS 渐变、内联 SVG、纯 CSS 图形替代。

## 输出协议
- 每个区块必须是完整 outerHTML，最外层必须有 data-block="slug" 和 data-block-label="中文标签"，且自身完整闭合。
- 每个区块 CSS 只负责自己；选择器尽量以 [data-block="slug"] 开头。:root/全局基础样式只放在 page-base 区块。
- 不要 Markdown、解释、thought、XML 标签或普通文本。只输出 NDJSON：每一行是一个完整 JSON 对象，不要把一个对象拆成多行。`
      const userPrompt = `appName: ${appName || ''}
designIntent: ${designIntent || ''}
platform: ${pf.label}

高置信设计证据：
${context || '（无）'}

globalStyle:
${styleStr}

${navRule}

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
- 如果有 globalNav 约束，导航区块的项必须**逐字复用 globalNav.items**（label/顺序/数量完全一致），只改激活项；不要自由增删改名。导航作为独立区块输出（底部 order 靠后、顶部 order 靠前）。
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

  // ── screen-generate: M3-design-system-driven whole-page generate ──────────
  // Accepts a full designSystem (roles + typography + spacing from Phase 0/1)
  // and instructs the model to write semantic Tailwind classes referencing the
  // injected named colors (bg-surface / text-on-primary / …) + Material Symbols
  // icons.  No hex colours, no bare CSS variables — the palette is the injected
  // tailwind.config colors (§2.8).
  function buildScreenGeneratePrompt() {
    const ds = designSystem || {}
    const roles = ds.roles || {}
    const typo = ds.typography || {}
    const spacing = ds.spacing || {}

    const colorRolesList = Object.entries(roles)
      .map(([k, v]) => `  ${k} → ${v}`)
      .join('\n')
    const typoList = Object.entries(typo)
      .map(([level, t]) => `  ${level}: ${t.fontFamily} ${t.fontSize}/${t.lineHeight} w${t.fontWeight}${t.letterSpacing ? ' tracking[' + t.letterSpacing + ']' : ''}`)
      .join('\n')
    const spacingList = Object.entries(spacing)
      .map(([k, v]) => `  ${k}: ${v}`)
      .join('\n')

    const hf = ds.headlineFont || 'Source Serif 4'
    const bf = ds.bodyFont || 'Literata'
    const lf = ds.labelFont || 'Inter'
    const rn = ds.roundness || 12
    const persona = ds.brandPersona || designIntent || ''
    const pageStr = page ? JSON.stringify(page, null, 2) : '（无）'

    // Nav: unlike page-generate (which pastes a hex-based shared chrome), the M3
    // screen MUST keep the named-colour discipline — so we DESCRIBE the nav and
    // let the model build it with M3 named classes, not paste raw hex HTML.
    const navItems = globalNav && Array.isArray(globalNav.items) && globalNav.items.length ? globalNav.items : null
    const navType = globalNav?.type || 'bottom-tab'
    const chromeRule = navItems
      ? `## 共享导航（用 M3 具名色自建，不要用 hex）
- 导航类型：${navType}（bottom-tab=固定底栏 / top-nav=顶栏 / sidebar=侧栏）。
- 导航项（逐字复用 label/顺序/数量，当前页 navKey=${page?.navKey || '（无）'} 设为激活态）：${navItems.map(i => i.label).join(' / ')}。
- 用 Material Symbols 图标 + 具名色：未激活 \`text-on-surface-variant\`，激活 \`text-primary\`；底栏背景 \`bg-surface-container\` + \`border-t border-outline-variant\`。**禁止 hex / bg-white / text-neutral**。
- bottom-tab 时给正文底部留 \`pb-20\` 避免遮挡。`
      : '按页面需要自建底部 tab 栏（用 M3 具名色 + Material Symbols 图标）。'

    const systemPrompt = `你是世界顶级的产品 UI 设计师兼前端工程师。你将为「${pf.label}」产品的一个页面直接产出**一份自包含、可立即预览、视觉精致的前端代码**（HTML + 内联 CSS + 必要 JS）。

## 设计系统（你的视觉宪法）
你**只被允许使用下面列出的具名颜色、字体、圆角和间距**。这是注入的 Tailwind 配置的全部内容，禁止使用这些名称之外的任何颜色值：
### 颜色语义角色（47 个，全部可用）
${colorRolesList}

### 排版刻度（8 级，字号/字重/行高必须从这里面取）
${typoList}
- 标题用 \`font-headline\`、正文用 \`font-body\`、标签/小字用 \`font-label\`

### 间距刻度
${spacingList}

### 字体
- 标题(headline): ${hf}  |  正文(body): ${bf}  |  标签(label): ${lf}
- 图标：用 Material Symbols 字体，写成 \`<span class="material-symbols-outlined">home</span>\`

### 圆角
- 默认圆角 ${rn}px，用 Tailwind rounded 对应档位

### 品牌人格
${persona || '（未设定，按内容自行揣摩气质）'}

## 页面规则
- ${pf.rules}
- 固定视口 ${viewport.width}x${viewport.height}；移动端 w-full、min-h-screen 铺满，禁止更小的 max-width 居中壳。
${chromeRule ? '\n' + chromeRule + '\n' : ''}
## 用 Tailwind 语义类（铁律）
1. **颜色只准用上面列出的具名角色**：\`bg-surface\`、\`text-on-primary-container\`、\`border-outline-variant\` 等。**禁止裸 hex、禁止 var()、禁止 bg-[#xxx]**。
2. **颜色必须按语义分工，不允许整页只用 primary 一个色系**：
   - primary / on-primary / primary-container：只用于主 CTA、当前激活态、最重要的标题强调。
   - secondary / secondary-container：用于分类 chip、筛选、次级按钮、图标淡底块。
   - tertiary / tertiary-container / dna-accent-*：用于角标、计数、进度、价格/风险/新内容等小面积强调。
   - surface / surface-container / outline：用于页面背景、卡片、分隔线和输入区。
   - 每个页面至少要可见 3 个色彩家族：中性/表面色 + primary + secondary/tertiary/accent。比例大致为 60–70% 表面与正文、20–30% primary、10–15% secondary/tertiary/accent。不要把标题、图标、chip、按钮全部染成同一个粉色/红色。
   - **严禁白底黑线框半成品**，但也严禁“全页面一个品牌色”。
3. 字体：\`font-headline\` / \`font-body\` / \`font-label\`。
4. 图标：Material Symbols 字体。
5. 圆角用 Tailwind 标准档位映射（${rn}px→rounded-lg 等），间距用上面刻度。

## 内容要求
- 页面规划：${pageStr}
- 整页 8–14 个具体内容单元，中文真实内容。无真实图片时用 CSS 渐变/SVG 占位。
- 每节包成 \`<section data-block="slug" data-block-label="中文标签">\`
- 覆盖 hover/active/selected/empty/loading/error 中≥4 种状态。`

    const userPrompt = `请生成完整的 HTML 页面代码。直接输出 HTML（从 <!DOCTYPE html> 或 <html> 开始），**不要包裹在 markdown 代码块里**。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  // ── screen-variants: generate 2–3 layout/style variants of the same page ──
  function buildScreenVariantsPrompt() {
    const base = buildScreenGeneratePrompt()
    const vOpts = variantOptions || {}
    const count = Math.max(1, Math.min(5, Number.parseInt(vOpts.variantCount, 10) || 3))
    const creativeRange = vOpts.creativeRange || 'EXPLORE'
    const aspects = Array.isArray(vOpts.aspects) && vOpts.aspects.length
      ? vOpts.aspects.join(', ')
      : 'LAYOUT, COLOR_SCHEME, TEXT_FONT'

    const rangeMap = {
      REFINE: '做**微调**——在原版基础上做小幅度变化，保留最初的设计意图和结构',
      EXPLORE: '做**探索**——变化布局、配色或排版，但保持整体调性一致',
      REIMAGINE: '做**重新构想**——可以大胆改变结构、风格，挑战原有设计',
    }
    const rangeRule = rangeMap[creativeRange] || rangeMap.EXPLORE

    const variantSystem = `## 变体生成模式
- 生成 **${count}** 个不同变体。
- 变体范围：${rangeRule}。
- 重点变化的方面：**${aspects}**（其他方面尽量保持不变）。
- 每个变体是完整、自包含的HTML页面。
- 用 \`<!-- variant: <描述> -->\` 分隔每个变体。`
    return { ...base, systemPrompt: variantSystem + '\n\n' + base.systemPrompt }
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
- palette：5-7 个基础色（不是色阶渐变），每个含 name（如 Primary/Secondary/Tertiary/Neutral/Text/Surface）、role（只能是 primary/secondary/tertiary/accent/neutral/text/background/surface 之一）、hex（标准 #RRGGBB）。
- palette 必须覆盖：主色 primary、至少 1 个 secondary 或 tertiary、至少 1 个 accent、正文/深色 text 或 neutral、背景/浅色 background 或 surface。不要把相近红/粉全部合并成一个色；如果 DNA/图片里有低饱和背景、深色文字、暖色点缀、冷色点缀，都要各自保留为独立基础色。
- 优先**直接复用** DNA 文本里出现的具体十六进制色值；色值不足时再合理推断补齐，但总数保持 5-7 个。
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
- palette 含 5-7 个基础色，必须覆盖 primary、secondary/tertiary、accent、text/neutral、background/surface，优先复用 DNA 中出现的具体十六进制色值。
- radius 为 px 数值（number）。
- shadow 为合法 CSS box-shadow 字符串。
- 只返回 JSON 对象本身，不要代码块、不要解释。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  // ---- Component Protocol v1 (see frontend docs/component-protocol.md) ----
  // Catalog kept compact + in sync with the frontend REGISTRY. The skeleton step
  // (big model) only picks components + layout + contentHints; the fill step
  // (small model) only outputs props JSON matching one component's schema.
  const COMPONENT_CATALOG = {
    Banner:        { use: '页面顶部品牌横幅/主视觉', layout: 'span:full', vr: 'solid|gradient|minimal|aurora|split|overlay', props: '{ "title": str, "subtitle": str?, "carouselDots": 0-5?, "variant": "solid|gradient|minimal|aurora|split|overlay", "accent": "primary|accent2|accent3" }（solid/gradient=图片打底+品牌色罩，minimal=浅底大字，aurora=深底柔光，split=左文右图卡片式，overlay=整图+底部文字沉浸式）' },
    SectionHeader: { use: '区块小标题（带可选“更多”）', layout: '-', props: '{ "title": str, "moreLabel": str?, "icon": iconName? }（icon 可选：标题前的小图标）' },
    TagChips:      { use: '分类/筛选标签胶囊', layout: '-', vr: 'pill|underline|outline', props: '{ "variant": "pill|underline|outline", "items": [ { "label": str, "active": bool?, "icon": iconName? } ] }（2-8个；icon 可选，取自图标枚举）' },
    CardGrid:      { use: '并列卡片网格（专题/分类入口/书影音/人物）', layout: 'cols:2|3', vr: 'icon-tile|plain|list|cover|cover-tall|avatar', props: '{ "title": str?, "variant": "icon-tile|plain|list|cover|cover-tall|avatar", "items": [ { "icon": iconName, "title": str, "desc": str?, "accent": "primary|accent2|accent3|neutral", "badge": str? } ] }（2-8张；list=横向行，cover=顶部封面图，cover-tall=竖封面海报(书/影/专辑)，avatar=圆形头像(作者/用户)；badge 可选角标如“新”“热”）' },
    ListFeed:      { use: '信息流/长内容列表/榜单', layout: 'span:full', vr: 'thumb|minimal|card|thumb-right|rank|cover', props: '{ "title": str?, "variant": "thumb|minimal|card|thumb-right|rank|cover", "items": [ { "icon": iconName?, "title": str, "desc": str?, "tag": str?, "meta": str?, "trailing": str? } ] }（2-12条；thumb=缩略图左，thumb-right=缩略图右，card=每条独立卡片，rank=带名次序号的排行榜，cover=每条顶部宽封面图；trailing 可选：行右侧数值/状态）' },
    SearchBar:     { use: '搜索框（可带最近搜索）', layout: 'span:full', props: '{ "placeholder": str, "recent": [str]? }' },
    DetailHeader:  { use: '详情页标题头', layout: 'span:full', props: '{ "title": str, "subtitle": str?, "meta": [str]?, "tags": [str]?, "icon": iconName? }（icon 可选：标题前图标）' },
    KeyValueList:  { use: '键值/档案信息表', layout: 'span:full', vr: 'default|striped|cards', props: '{ "title": str?, "variant": "default|striped|cards", "rows": [ { "key": str, "value": str, "icon": iconName? } ] }（striped=斑马纹，cards=每对成卡；每行 icon 可选）' },
    StatGrid:      { use: '数据指标网格（大数字+标签，用于概览/统计）', layout: 'cols:2|3', vr: 'default|plain|bar|ring|trend', props: '{ "title": str?, "variant": "default|plain|bar|ring|trend", "items": [ { "value": str, "unit": str?, "label": str, "icon": iconName?, "trend": str? } ] }（2-6个；plain=无卡格，bar=横向条，ring=环形进度(value最好是百分比数)，trend=大数+涨跌胶囊+迷你柱(配合trend字段)；trend 可选涨跌如“+12%”/“-3%”自动绿涨红跌；icon 可选）' },
    MediaCard:     { use: '特性大图卡（顶部图片+标题描述，用于专题/功能推荐）', layout: 'span:full', vr: 'default|horizontal|overlay', props: '{ "title": str?, "variant": "default|horizontal|overlay", "items": [ { "icon": iconName, "title": str, "desc": str?, "tag": str?, "accent": "primary|accent2|accent3|neutral", "badge": str? } ] }（2-4张；default=顶部封面图，horizontal=左图右文，overlay=文字压在大图上沉浸式；badge 可选图区角标）' },
    Timeline:      { use: '时间线（历程/进度/动态，按时间排列）', layout: 'span:full', vr: 'default|cards', props: '{ "title": str?, "variant": "default|cards", "items": [ { "time": str?, "title": str, "desc": str?, "icon": iconName?, "tag": str? } ] }（2-8条；cards=每条成卡；icon 可选：节点图标；tag 可选：标题旁小标记）' },
    NoticeBar:     { use: '公告条（单行通知/提示）', layout: 'span:full', props: '{ "text": str, "icon": iconName?, "tag": str? }' },
    ProductCard:   { use: '商品/课程/付费内容卡（图+名+价格+标签），电商/课程/会员场景', layout: 'cols:2', vr: 'grid|list', props: '{ "title": str?, "variant": "grid|list", "items": [ { "title": str, "desc": str?, "price": str?, "origPrice": str?, "tag": str?, "meta": str? } ] }（2-8件；grid=2列带图卡，list=横向行；price 带货币符如 ¥39，origPrice 原价(划线)，meta 如 月销2k/4.8分）' },
    CellGroup:     { use: '功能菜单/设置项行组（图标+标题+右值/箭头），用于"我的"/设置/账户页', layout: 'span:full', vr: 'default|inset', props: '{ "title": str?, "variant": "default|inset", "rows": [ { "icon": iconName?, "label": str, "desc": str?, "value": str?, "badge": str?, "arrow": bool? } ] }（3-8行；value=右侧值如 已开启/v2.1，badge=未读小红点上的数字或极短状态(如 "3" "99+" "NEW")，没有就省略，**绝不要把"红点数字"这四个字本身当内容填**，arrow 默认 true 显示右箭头，纯展示项给 false）' },
    ProfileHeader: { use: '个人中心头部（头像+昵称+签名+统计数字），用户主页/我的页顶部', layout: 'span:full', vr: 'default|cover', props: '{ "variant": "default|cover", "name": str, "bio": str?, "stats": [ { "value": str, "label": str } ] }（cover=带背景封面图；stats 2-4 个如 关注/粉丝/获赞，value 是数字字符串）' },
    Steps:         { use: '步骤条/流程进度（注册引导、订单状态、闯关进度）', layout: 'span:full', vr: 'horizontal|vertical', props: '{ "title": str?, "variant": "horizontal|vertical", "current": number, "items": [ { "title": str, "desc": str? } ] }（3-6步；current=当前步(从0起)；horizontal 适合≤4步短标题，vertical 适合带描述的流程）' },
    Progress:      { use: '进度/完成度列表（标签+进度条+百分比），目标/任务/技能/容量', layout: 'span:full', props: '{ "title": str?, "items": [ { "label": str, "value": number, "caption": str? } ] }（2-6条；value=0-100 百分比数字；caption 可替代百分比文字，如 “8/10 本”）' },
    ReviewList:    { use: '用户评价/评论列表（头像+昵称+星级+内容）', layout: 'span:full', props: '{ "title": str?, "items": [ { "name": str, "rating": number?, "text": str, "meta": str? } ] }（2-8条；rating=0-5 星；meta 如 日期/已购/版本）' },
  }
  const ICON_NAMES = 'home list category grid search user bell star heart settings globe book file shield clock chart tag bookmark'

  function buildPageSkeletonPrompt() {
    const styleStr = globalStyle ? JSON.stringify(globalStyle) : '（无）'
    const catalog = Object.entries(COMPONENT_CATALOG)
      .map(([name, d]) => `- ${name}：${d.use}${d.layout !== '-' ? `（布局参数 ${d.layout}）` : ''}${d.vr ? `【可选变体 variant：${d.vr}】` : ''}`).join('\n')
    const systemPrompt = `你是移动端页面的版面设计师。你只做"版面设计 + 组件落位"决策，绝不写任何 HTML/CSS。工作分两步：先设计整页布局（这页该怎么组织、分几个区、谁主谁次），再据此把每个区落成组件块——是"设计版式"，不是"堆组件"。
规则：
- 只能使用下列已注册组件，不许发明新组件：
${catalog}
- 【第一步：先设计布局，再落组件】先在 layout 字段做版面设计：① 判定页面原型 archetype（见下条）；② 把这页拆成有序的内容分区 regions，每区写 role（区的角色，如 主视觉/核心内容/分类导航/数据概览/操作区）+ intent（这区要解决什么、放什么）；③ 用 rhythm 一句话说明主次与节奏。然后 blocks 必须逐一落在这些 region 内、实现该布局，每个 block 用 region 字段标注它属于哪个区。**严禁脱离 layout 直接拼组件**——blocks 是对 layout 的实现，不是另起炉灶。
- 输出的每块是"选择题"：选 component + 布局参数（cols/span/variant）+ region + contentHints（2-5 条简短中文内容要点）。
- 【contentHints 必须具体、贴该产品领域】后续会有一个小模型只看 contentHints 来填内容，所以要点必须写"实打实的文案方向"，让它有据可依：先判断这是什么产品（看产品名+设计意图），再写出该领域**真实的栏目名、具体条目主题、真实的指标/标签字样**。例如新闻类不要写"放几条新闻"，要写"放 4 条今日要闻：含一条时政、一条财经、一条体育，每条带来源与发布时间"；电商类不要写"商品列表"，要写"4 张商品卡：标明品名（如某品牌耳机）、价格区间、销量/评分标签"。给出数量、条目主题、每条包含的字段，但不要写死具体 props 值。
- 严禁泛泛而谈或占位式要点（如"几条内容""一些卡片""示例标题"），也禁止跟产品无关的话题。
- 不要写组件的具体 props、不要写样式、不要写颜色十六进制。颜色一律用枚举名（primary/accent2/accent3/neutral）。同页不同区块要轮换辅助色，避免所有 block 都默认 primary。
- icon 名只能取：${ICON_NAMES}。
- 一页 4-8 个块，主视觉靠前、次要靠后，符合移动端竖屏浏览节奏。
- 【⚠️ 先符合页面原型，再谈丰富——别发散】先判断这页是什么"类型"，套用该类型的常规形态，不要为了花哨乱选组件。常见原型 → 主体组件：
  · 设置/偏好/账户/隐私/通知管理 → 主体一定是 CellGroup（行式：图标+名称+右侧开关值/箭头，一项一行）；**绝不要**用 CardGrid 卡片网格去堆设置项。
  · 个人中心/我的 → 顶部 ProfileHeader，下面若干 CellGroup 分组（可夹一个 StatGrid 概览）。
  · 纯列表/信息流/消息/通知列表 → ListFeed。
  · 排行榜/热度榜 → ListFeed 的 rank。
  · 商品/课程/会员/付费内容列表 → ProductCard。
  · 详情页 → 以 DetailHeader 开头，配 KeyValueList/Timeline/ReviewList/Progress。
  · 流程/引导/订单状态/进度 → Steps（+ Progress）。
  · 数据看板/概览/统计 → StatGrid 为主。
  · 首页/发现/频道 → Banner + CardGrid/MediaCard + ListFeed 的组合。
  设置就该像设置、列表就该像列表——形态对了才允许在其内部追求变体丰富。
- 【主动变换 variant，避免单调】凡是带"可选变体"的组件，都要为它选一个最贴合该内容的 variant 填进块的 "variant" 字段；并且同一页里尽量让相邻/同类块用不同变体（比如这页 CardGrid 用 cover、列表用 card、数据用 bar），让整页有节奏、不要每块都长一样。根据内容语义选：入口/专题→cover 或 icon-tile，书影音/海报封面→cover-tall，作者/用户/人物→avatar，新闻流→card 或 thumb-right，排行榜/热度榜→ListFeed 的 rank，带封面的长内容→ListFeed 的 cover，对比数据→bar，占比/完成度→ring，关键指标+涨跌→trend，档案→striped/cards，历程→cards，沉浸主视觉→Banner 的 overlay 或 split。商品/课程/付费内容→ProductCard，"我的"/设置/账户菜单→CellGroup，个人主页顶部→ProfileHeader，流程/引导/订单状态→Steps，目标/任务/技能完成度→Progress，用户评价/评论→ReviewList。
- 严格只返回一个 JSON 对象，无任何解释/thought/markdown。`
    const pgTitle = page?.title || page?.id || ''
    const pgNav = page?.navKey ? `底栏主页（navKey=${page.navKey}）` : '子页/详情页（无底栏）'
    const pgPurpose = page?.purpose || ''
    const pgFns = Array.isArray(page?.functions) ? page.functions.join('；') : (page?.functions || '')
    const pgKey = Array.isArray(page?.keyContent) ? page.keyContent.join('；') : (page?.keyContent || '')
    const pgSections = (Array.isArray(page?.sections) ? page.sections : [])
      .map(s => s && (s.component || s.slug || s.title)).filter(Boolean).join('、')
    const pageBlock = page ? `【本页信息——务必先据此判定原型与布局，再落组件】
- 页面：${pgTitle}（${pgNav}）
- 功能/目的：${pgPurpose || '（未给出，按标题与产品推断）'}
- 能做什么：${pgFns || '（无）'}
- 关键内容：${pgKey || '（无）'}${pgSections ? `\n- 规格建议区块（参考，可按布局调整/增删）：${pgSections}` : ''}` : '本页：首页'
    const userPrompt = `产品名：${appName || ''}
设计意图：${designIntent || ''}
目标平台：${pf.label}
设计系统 globalStyle：${styleStr}

${pageBlock}

先读上面【本页信息】判断这页的功能与原型，再设计 layout，最后让 blocks 实现它。只返回如下结构 JSON：
{
  "pageId": "${page?.id || 'home'}",
  "title": "页面中文标题",
  "layout": {
    "archetype": "页面原型，如 settings-list / profile / feed / detail / dashboard / product-list / flow / home-discover",
    "type": "scroll",
    "gap": "md",
    "regions": [
      { "id": "kebab-区id", "role": "区角色(主视觉/核心内容/分类导航/数据概览/操作区…)", "intent": "这区解决什么、放什么" }
    ],
    "rhythm": "一句话说明主次与浏览节奏"
  },
  "blocks": [
    { "id": "kebab-唯一", "region": "所属区id", "component": "组件名", "order": 1, "span": "full", "cols": 2, "variant": "可选", "contentHints": ["要点1","要点2"] }
  ]
}`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  function buildComponentFillPrompt() {
    const comp = String(body.component || '')
    const def = COMPONENT_CATALOG[comp]
    const hints = Array.isArray(body.contentHints) ? body.contentHints.join('；') : (body.contentHints || '')
    const palette = (globalStyle && Array.isArray(globalStyle.palette)) ? globalStyle.palette.join('、') : ''
    const systemPrompt = `你为单个 UI 组件产出"渲染数据 props"，是结构化 JSON，不是代码。绝不写 HTML/CSS。
规则：
- 严格符合给定 props schema 的字段；多余字段不要，缺的用合理中文内容补齐。
- 颜色只用枚举名 primary/accent2/accent3/neutral，不写十六进制。尺寸/变体只用 schema 列出的枚举；列表/网格的多条 item 尽量在 primary/accent2/accent3 之间轮换，不要全填 primary。
- icon 名只能取：${ICON_NAMES}。
- 【内容必须紧扣产品主题】所有文本必须围绕给定的产品名、设计意图与 contentHints 展开，是该产品所在真实领域里**具体、可信、有信息量**的中文内容。先从产品名+设计意图判断这是什么领域（如外卖/健身/理财/招聘/在线课程/民宿预订…），再据此推断该组件该放什么真实内容。
- 【严禁占位与无关内容】绝对禁止任何占位符、示例数据、通用默认或与产品主题无关的内容：禁止出现 zhangsan、lisi、John Doe、Jane、Lorem ipsum、张三、李四、王五、赵六、王二麻子、"示例标题/示例内容/测试/占位/标题1/卡片1/选项A"，也禁止跟产品无关的随机学科或话题（如理财产品里冒出"一次函数""学 Python""唐诗鉴赏"）。**更不要把 props schema 里的字段说明/示例词当成真实内容直接填**（如把"红点数字""未读数字""主标题""一句话描述"原样写进去）。人名一律用真实自然的中文姓名(如 林岚、周屿、苏晓桐 这类，彼此各异不重复)，品牌名、商品名、栏目名、数字指标都要换成该领域里说得通的真实具体写法。
- 数字、价格、日期、评分、标签等要符合该领域常识与量级，不要写明显假的占位数字。
- 所有面向人阅读的文本一律简体中文，且要贴合内容要点、具体真实，禁止“示例/占位/Lorem”。
- 严格只返回一个 JSON 对象（即 props 本体），无解释/thought/markdown。`
    const curProps = body.currentProps && typeof body.currentProps === 'object' ? JSON.stringify(body.currentProps, null, 2) : ''

    // ── EDIT PATH ── instruction present → make the edit the PRIMARY task, with
    // current props front-and-center, so the model applies a targeted change
    // instead of regenerating the whole component.
    if (body.instruction) {
      const editSystem = `你在对一个已有 UI 组件做"定向编辑"。你会收到该组件当前的 props（结构化 JSON）和一条用户修改指令。你的任务：理解指令意图，在当前 props 基础上做**最小必要的改动**，输出修改后的完整 props JSON。
规则：
- 这是"改"不是"重做"：以当前 props 为基底，只动与指令相关的字段，其余字段一律原样保留（包括已有的真实文案、数字、icon）。
- 严格符合该组件的 props schema：字段名、枚举值（颜色只用 primary/accent2/accent3/neutral；尺寸/变体只用 schema 列出的枚举；icon 只能取：${ICON_NAMES}）。
- 认真领会指令的真实意图再改。例如"增强标题层级"=放大/加粗标题或调整其 size/weight 枚举；"减弱边框"=调 border/卡片样式枚举往更轻；"换个图标"=改 icon 名；"文案更专业"=改写对应文本但保持同领域同主题。
- 若指令要求的改动该 schema 根本不支持（如该组件没有"隐藏文字只留图标"的字段），则在 schema 允许范围内做最接近的合理调整，不要凭空加字段。
- 不要把已有真实内容替换成占位/示例/空白，也不要跑题到与产品无关的话题。
- 只返回一个完整的 props JSON 对象，无解释/thought/markdown。`
      const editUser = `产品名：${appName || '（未给出）'}
产品设计意图：${designIntent || '（无）'}
所属页面：${body.pageTitle || '（未给出）'}
组件：${comp}（用途：${def ? def.use : ''}）
props schema：${def ? def.props : '{}'}
配色板：${palette}

【当前 props】
${curProps || '（无，按 schema 合理生成）'}

【用户修改指令】
"${body.instruction}"

请在当前 props 基础上执行上述修改，输出修改后的完整 props JSON 对象（只返回 JSON）。`
      return { systemPrompt: editSystem, userPrompt: editUser, imageUrls: [] }
    }

    const userPrompt = `产品名：${appName || '（未给出，从下方设计意图与内容要点推断领域）'}
产品设计意图：${designIntent || '（无）'}
所属页面：${body.pageTitle || '（未给出）'}
组件：${comp}
用途：${def ? def.use : ''}
props schema：${def ? def.props : '{}'}
配色板（供你理解 primary/accent2/accent3 等枚举对应的真实色，但你输出仍用枚举名）：${palette}
内容要点 contentHints：${hints || '（无：请严格按产品名+设计意图所属领域 + 本组件用途，填充该领域真实具体的中文内容，绝不要用占位/示例/无关话题）'}

请确保每条文案都能直接放进这个真实产品里、并紧扣"产品名+设计意图+所属页面"的主题，读起来像该领域的真实数据。只返回符合该 schema 的 props JSON 对象。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  // Re-skin: adjust the design tokens per a style instruction (content unchanged).
  function buildPageRestylePrompt() {
    const gs = globalStyle ? JSON.stringify(globalStyle, null, 2) : '{}'
    const systemPrompt = `你是 UI 设计系统的 token 调优器。给定当前设计 token 和一句"样式调整指令"，你只微调**视觉 token**，输出调整后的 JSON。
规则：
- 绝不改内容、不写 HTML/CSS；只动视觉 token。
- 只调与指令相关的字段，其余尽量保留原值。
- 除非指令明确要求换色，**保持品牌主色的色相不变**（可调饱和度/明度）。
- 严格只返回一个 JSON 对象，结构如下（字段都要给）：
{
  "palette": ["#RRGGBB 角色", ...],   // 4-6 条，十六进制+中文角色；保持主色相
  "radius": "卡片 16、按钮 12、标签 999",
  "feel": {
    "spacing": 16, "fontBase": 14,
    "cardStyle": "shadow|outline|flat|glass",
    "shadowLevel": "flat|soft|elevated",
    "border": "none|hairline",
    "iconStyle": "tint|solid|plain",
    "gradientHeader": true, "accentBar": false, "glass": false
  }
}
调优指南：
- "更高级"：增大留白(spacing↑)、精致克制的阴影(shadowLevel:soft/elevated 二选其一更精致)、发丝边框(border:hairline)、降低饱和度、cardStyle 倾向 outline 或 soft-shadow、去掉花哨渐变(gradientHeader:false 视情况)、提升层级对比。
- "更克制"：去渐变(gradientHeader:false)、去强调条(accentBar:false)、降阴影(shadowLevel:flat/soft)、cardStyle:flat/outline、palette 降饱和。
- "增强层级"：拉开字号/字重对比(fontBase 可微调)、可加 accentBar:true 强调标题。
- "减少饱和度"：把 palette 各色相饱和度明显降低，保持色相与可读性。
- "强化参考 DNA"：更忠实复用原 token，不要发明新风格。`
    const userPrompt = `产品名：${appName || ''}
设计意图：${designIntent || ''}
当前设计 token（globalStyle）：
${gs}

样式调整指令："${instruction || ''}"

请输出调整后的 token JSON（只含 palette / radius / feel 三个键）。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  const prompt = mode === 'page-restyle' ? buildPageRestylePrompt() : mode === 'polish' ? buildPolishPrompt() : mode === 'video-explosion' ? buildVideoExplosionPrompt() : mode === 'text-explosion' ? buildTextExplosionPrompt() : mode === 'design-explosion' ? buildDesignExplosionPrompt() : mode === 'group' ? buildGroupPrompt() : (mode === 'page-plan' || mode === 'spec-draft' || mode === 'spec-extract') ? buildPagePlanPrompt() : mode === 'page-skeleton' ? buildPageSkeletonPrompt() : mode === 'component-fill' ? buildComponentFillPrompt() : mode === 'page-generate' ? buildPageGeneratePrompt() : mode === 'screen-generate' ? buildScreenGeneratePrompt() : mode === 'screen-variants' ? buildScreenVariantsPrompt() : mode === 'page-edit' ? buildPageEditPrompt() : mode === 'page-block-edit' ? buildPageBlockEditPrompt() : mode === 'design-tokens' ? buildDesignTokensPrompt() : buildSinglePrompt()

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
    groq:       { vl: 'meta-llama/llama-4-scout-17b-16e-instruct', llm: 'llama-3.3-70b-versatile' },
  }
  const defaults = MODEL_DEFAULTS[provider] || MODEL_DEFAULTS.modelscope
  // Vision tasks (image-based 大爆炸 / group analysis) MUST use a vision-capable
  // model. Never fall back to the user's text `model` for these — a text model
  // can't see the images and will hallucinate colors (e.g. blue for red refs).
  // Dedicated "fill model" role: component-fill runs MANY small parallel calls,
  // so it can point at a fully independent endpoint (own url+key+model, e.g. a
  // separate account/platform) to get its own concurrency quota, away from the
  // big model's rate limit. Self-contained; resolved straight from DB settings.
  const fillCfg = (dbSettings.fillModel && typeof dbSettings.fillModel === 'object') ? dbSettings.fillModel : null
  // A fill endpoint only needs url + model — local endpoints (LM Studio) have NO
  // API key, so don't require one (else component-fill silently falls back to the
  // big model and hammers it).
  // Bulk content-fill (no instruction) → small fill model for parallel speed.
  // A TARGETED EDIT (instruction present) → keep it on the BIG llm: edits are
  // one-at-a-time and need real instruction comprehension, which the tiny fill
  // model lacks (it was "完全没理解" the edit ask). Quality > speed here.
  const useFill = mode === 'component-fill' && !body.instruction && fillCfg && fillCfg.baseUrl && fillCfg.model
  // Dedicated, FULLY SEPARATE vision role: vision tasks (大爆炸/图片分析) point at
  // their own self-contained endpoint (url+key+model), independent of the text
  // LLM. So setting the LLM to a local text model never drags vision onto it.
  const visionCfg = (dbSettings.visionModel && typeof dbSettings.visionModel === 'object') ? dbSettings.visionModel : null
  const useVision = needsVision && visionCfg && visionCfg.baseUrl && visionCfg.model
  const resolvedModel = useVision
    ? visionCfg.model
    : useFill
      ? fillCfg.model
      : needsVision
        ? (vlModel || defaults.vl)
        : (model || defaults.llm)

  // Resolve Worker image URLs to data URLs so external APIs can fetch them
  const resolvedImages = await Promise.all(
    prompt.imageUrls.map(url => resolveImageUrl(url, env))
  )

  try {
    let result = ''

    async function callOpenAICompat(apiUrl, apiKey, modelName, onDelta, opts = {}) {
      if (!apiKey) {
        const err = new Error('缺少接口密钥，请在设置中填写。')
        err.status = 400
        throw err
      }
      // Local endpoints (LM Studio / Ollama) run models like qwen3 that "think"
      // by default — on long JSON tasks the reasoning eats the token budget and
      // the JSON gets truncated → unparseable. qwen3 honors a `/no_think` hint;
      // it's harmless to other models. Inject it for local/role endpoints.
      const noThink = (provider === 'lmstudio' || provider === 'ollama' || useFill || useVision) ? ' /no_think' : ''
      const baseText = `${prompt.systemPrompt}\n\n${prompt.userPrompt}${noThink}`
      const content = needsVision
        ? [
            { type: 'text', text: baseText },
            ...resolvedImages.map(url => ({ type: 'image_url', image_url: { url } })),
          ]
        : baseText
      // Explosion + page modes return JSON — force JSON output format
      const wantsJson = !streamPreview && ['text-explosion', 'video-explosion', 'design-explosion', 'page-plan', 'page-generate', 'page-edit', 'page-block-edit', 'design-tokens', 'spec-draft', 'spec-extract'].includes(mode)
      const needsStableJson = !streamPreview && ['page-plan', 'page-generate', 'page-edit', 'page-block-edit'].includes(mode)
      const body = {
        model: modelName,
        messages: [{ role: 'user', content }],
        // page-plan bumped to 8192: Gemini 2.5/3.x "thinking" models spend part
        // of the budget reasoning, so a 4096 cap could truncate the JSON before
        // the plan is emitted → unparseable result.
        max_tokens: (mode === 'page-generate' && fastMode) ? 6144 : (mode === 'page-generate' || mode === 'screen-generate' || mode === 'screen-variants' || mode === 'page-edit' || mode === 'page-plan' || mode === 'spec-draft' || mode === 'spec-extract') ? 8192 : (mode === 'page-block-edit') ? 4096 : mode === 'design-tokens' ? 2048 : mode === 'component-fill' ? 2048 : wantsJson ? 4096 : (mode === 'group' || mode === 'polish') ? 2048 : 1024,
        // Always stream. Non-streaming long generations get killed by idle
        // timeouts on proxies / providers (DeepSeek etc) → "no response".
        stream: true,
      }
      // Reasoning/"thinking" control. There is no global frontend switch because
      // each provider exposes a different knob, and unknown params 400 on some
      // endpoints. Enable it where supported and strip unsupported params below.
      if (provider === 'qwen' || provider === 'modelscope') {
        body.enable_thinking = !!enableReasoning
      } else if (provider === 'deepseek') {
        // DeepSeek's OpenAI-compatible API accepts reasoning_effort; 'none' skips thinking.
        body.reasoning_effort = enableReasoning ? 'high' : 'none'
      }
      // Many OpenAI-compatible third-party endpoints either reject
      // response_format or handle large JSON worse when it is enabled. Page
      // generation/edit prompts already require strict JSON and the frontend
      // parser is tolerant, so only force response_format for smaller JSON jobs.
      // EXCEPTION: Gemini (google) handles json_object mode reliably and tends
      // to otherwise wrap output in prose / markdown / thinking — which makes
      // the page-plan/generate result unparseable. Force JSON mode for Gemini
      // on every JSON task.
      // Local OpenAI-compatible servers (LM Studio / Ollama) often reject
      // response_format (esp. for VL models) → 400. Never send it to them.
      const localEndpoint = provider === 'lmstudio' || provider === 'ollama' || useVision || useFill
      if (wantsJson && !localEndpoint && (provider === 'google' || !needsStableJson)) {
        body.response_format = { type: 'json_object' }
      }
      if (provider === 'google' && !enableReasoning && ['page-plan', 'page-generate', 'page-edit', 'page-block-edit', 'design-tokens'].includes(mode)) {
        body.reasoning_effort = /gemini-2\.5/i.test(String(modelName || '')) ? 'none' : 'minimal'
      }
      const timeoutMs = (mode === 'page-generate' || mode === 'screen-generate' || mode === 'page-edit' || mode === 'page-block-edit') ? 280000
        // Big-model layout planning (skeleton) is as heavy as page-plan → give it
        // the same headroom; component-fill is small but a local model can be slow.
        : (mode === 'page-plan' || mode === 'page-skeleton') ? 150000
        : mode === 'component-fill' ? 120000
        : 70000
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
        // Strip params the endpoint rejects, then retry once. Covers local
        // servers (LM Studio) that 400 on response_format / reasoning_effort.
        if (!res.ok && (body.reasoning_effort || body.response_format)) {
          const clone = await res.clone().text().catch(() => '')
          if (/reasoning_effort|response_format|unsupported|unknown|unrecognized|extra|invalid|not support/i.test(clone)) {
            delete body.reasoning_effort
            delete body.response_format
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
      // Raw passthrough: hand the upstream SSE stream straight back to the caller
      // without parsing it. The worker then does ~zero per-token CPU work, which
      // is what prevents "Worker exceeded CPU time limit" on large page streams.
      if (opts.rawStream) return res
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
      // Self-contained role endpoints (independent of the LLM provider). The user
      // supplies the full OpenAI-compatible base (to /v1); we just append the path.
      if (useVision) {
        return { apiUrl: `${String(visionCfg.baseUrl).replace(/\/$/, '')}/chat/completions`, key: visionCfg.apiKey || 'lm-studio', model: visionCfg.model }
      }
      if (useFill) {
        return { apiUrl: `${String(fillCfg.baseUrl).replace(/\/$/, '')}/chat/completions`, key: fillCfg.apiKey || 'lm-studio', model: fillCfg.model }
      }
      switch (provider) {
        case 'qwen': return { apiUrl: `${compatBase('https://dashscope.aliyuncs.com/compatible-mode/v1')}/chat/completions`, key: apiKey || env.QWEN_API_KEY, model: resolvedModel }
        case 'deepseek': return { apiUrl: `${compatBase('https://api.deepseek.com/v1')}/chat/completions`, key: apiKey || env.DEEPSEEK_API_KEY, model: resolvedModel }
        case 'zhipu': return { apiUrl: `${compatBase('https://open.bigmodel.cn/api/paas/v4')}/chat/completions`, key: apiKey || env.ZHIPU_API_KEY, model: resolvedModel }
        case 'modelscope': return { apiUrl: `${(baseUrl || env.MODELSCOPE_BASE_URL || 'https://api-inference.modelscope.cn/v1').replace(/\/$/, '')}/chat/completions`, key: apiKey || env.MODELSCOPE_API_KEY, model: resolvedModel }
        case 'mi': return { apiUrl: `${compatBase('https://api.mimo-v2.com/v1')}/chat/completions`, key: apiKey || env.MI_API_KEY, model: resolvedModel }
        case 'google': return { apiUrl: `${compatBase('https://generativelanguage.googleapis.com/v1beta/openai')}/chat/completions`, key: apiKey || env.GOOGLE_API_KEY, model: resolvedModel }
        case 'groq': return { apiUrl: `${compatBase('https://api.groq.com/openai/v1')}/chat/completions`, key: apiKey || env.GROQ_API_KEY, model: resolvedModel }
        case 'lmstudio': return { apiUrl: `${(baseUrl || lmstudioUrl || 'http://localhost:1234').replace(/\/$/, '')}/v1/chat/completions`, key: 'lm-studio', model: resolvedModel || model || 'default' }
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
      // Pass-through: pipe the upstream SSE body straight to the browser. The
      // worker no longer parses every token frame, so it does ~zero per-token CPU
      // work and never hits the Cloudflare CPU time limit on large page streams.
      // The frontend (readAiStream) parses the SSE frames instead.
      let upstream
      try {
        upstream = await callOpenAICompat(ep.apiUrl, ep.key, ep.model, null, { rawStream: true })
      } catch (e) {
        return json({
          error: e.message || 'AI 请求失败',
          meta: { provider, model: resolvedModel, mode, elapsedMs: Date.now() - startedAt, promptChars },
        }, e.status || 500)
      }
      console.log(`[AI] stream-start mode=${mode} provider=${provider} model=${resolvedModel} promptChars=${promptChars} reasoning=${enableReasoning} connectMs=${Date.now() - startedAt}`)
      return new Response(upstream.body, {
        headers: {
          'Content-Type': 'text/event-stream; charset=utf-8',
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
    let m

    if (path === '/api/board' && req.method === 'GET') return handleGetBoard(req, env, userId)
    if (path === '/api/board' && req.method === 'PUT') return handleSaveBoard(req, env, userId)
    if (path === '/api/upload' && req.method === 'POST') return handleUpload(req, env, userId)
    if ((m = path.match(/^\/api\/assets\/([^/]+)$/)) && req.method === 'DELETE') {
      return handleDeleteAsset(req, env, m[1], userId)
    }
    if (path === '/api/assets/cleanup' && req.method === 'POST') return handleCleanupAssets(req, env)
    if (path === '/api/ai' && req.method === 'POST') return handleAI(req, env, userId)
    if (path === '/api/logs' && req.method === 'POST') return handleLogAi(req, env, userId)
    if (path === '/api/logs' && req.method === 'GET') return handleGetLogs(req, env, userId)

    // Generated pages (Phase 2 durable persistence)
    if (path === '/api/generated/groups' && req.method === 'POST') return handleCreateGroup(req, env, userId)
    if (path === '/api/generated/pages' && req.method === 'POST') return handleCreatePage(req, env, userId)
    if (path === '/api/generated/versions' && req.method === 'POST') return handleCreateVersion(req, env, userId)

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
