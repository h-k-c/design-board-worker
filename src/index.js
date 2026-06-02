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

    const mapped = cards.results.map(row => {
      const content = JSON.parse(row.content)
      const card = { id: row.id, type: row.type, x: row.x, y: row.y, w: row.w, h: row.h, ...content }
      if (row.linked_to) card.linkedTo = row.linked_to
      return card
    })

    return json({ cards: mapped, transform })
  } catch (e) {
    return json({ cards: [], transform: { x: 0, y: 0, scale: 1 } })
  }
}

async function handleSaveBoard(req, env) {
  const { cards, transform } = await req.json()

  try {
    await env.DB.prepare('UPDATE board_state SET transform = ? WHERE id = 1')
      .bind(JSON.stringify(transform)).run()

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
  } = await req.json()

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
    const systemPrompt = `你是一名资深 UI 设计分析师。用户会用文字描述一个让他印象深刻的设计、界面、或产品体验。请根据描述拆解出极其具体的设计因子——必须包含可直接写入 CSS 的数值，禁止模糊形容词。`
    const userPrompt = `用户描述：
"${context || ''}"

请根据这段文字描述，提取 14-18 个**极其具体**的设计因子。要求：
- 色彩类：具体十六进制色号（如 #1A1A2E），说明用在哪个元素上
- 字体类：字体族名、字号（px）、字重、行高、字间距
- 结构类：间距（px）、圆角（px）、栅格、最大宽度
- 质感类：具体 CSS 值 — box-shadow、backdrop-filter、渐变色值
- 组件类：组件尺寸、颜色、圆角、间距的具体数值
- 动效类：缓动函数、时长、动画属性
- 高级感类：具体实现手法而非抽象感受

禁止"简洁""现代""高级""优雅"等模糊词。每条必须可直接写 CSS。

尽量只返回 JSON 数组，不要长段落。
格式：
[
  {"category":"色彩","label":"深灰主文字 #1A1A2E","reason":"正文用深灰而非纯黑，降低对比度疲劳","prompt":"正文颜色 color: #1A1A2E，标题 #111111，次要信息 #8C8C8C。"},
  {"category":"质感","label":"8px柔光投影","reason":"卡片浮起感来自低扩散阴影","prompt":"box-shadow: 0 2px 8px rgba(0,0,0,0.06), 0 8px 24px rgba(0,0,0,0.04); border-radius: 16px。"}
]
category 只能是：色彩、结构、组件、质感、字体、动效、高级感。
label 必须 2-8 个中文词（色彩类带色号、字体类带参数），适合显示在小气泡里。
prompt 必须是可直接复制为 CSS/代码的实现指令，包含具体数值。
即使描述抽象，也必须推断出具体数值。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  function buildVideoExplosionPrompt() {
    const systemPrompt = `你是一名资深交互与动效设计分析师。用户提供了一段界面录屏的关键帧截图，请拆解出极其具体的设计因子——每条必须包含可直接写入 CSS/JS 的数值，禁止模糊形容词。`
    const userPrompt = `${context ? `用户补充说明："${context}"\n\n` : ''}以下是从一段界面录屏中提取的关键帧。请提取 14-18 个**极其具体**的因子，重点关注动效和质感：
- 转场：具体 CSS transition/animation 属性、时长（ms）、缓动函数（cubic-bezier 值）
- 动画：具体 keyframes、transform 值、opacity 变化范围
- 交互反馈：hover/active/focus 的具体样式变化（scale 值、颜色变化、阴影变化）
- 视觉节奏：具体延迟间隔（stagger delay）、动画编排顺序
- 色彩/质感：具体十六进制色号、backdrop-filter 值、box-shadow 值、渐变色值

禁止"流畅""自然""优雅"等模糊词。每条必须可直接写 CSS/JS。

尽量只返回 JSON 数组，不要长段落。
格式：
[
  {"category":"动效","label":"300ms弹性页面转场","reason":"页面切换有弹性回弹感","prompt":"transition: transform 300ms cubic-bezier(0.34, 1.56, 0.64, 1); 页面进入时 translateX(100%) → translateX(0)。"},
  {"category":"质感","label":"20px毛玻璃 rgba(255,255,255,0.72)","reason":"多层半透明叠加营造深度","prompt":"backdrop-filter: blur(20px) saturate(1.2); background: rgba(255,255,255,0.72); border: 1px solid rgba(255,255,255,0.3)。"}
]
category 只能是：色彩、结构、组件、质感、字体、动效、高级感。
label 必须 2-8 个中文词（带关键数值），适合显示在小气泡里。
prompt 必须是可直接复制为 CSS/JS 代码的实现指令。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  function buildDesignExplosionPrompt() {
    const systemPrompt = `你是一名资深 UI 设计分析师。请把图片拆解成极其具体的设计因子，每条必须包含可直接写入 CSS 的数值，禁止模糊形容词。`
    const userPrompt = `${context ? `用户补充说明："${context}"\n\n` : ''}请把这个素材拆成 14-18 个**极其具体**的设计因子。要求：
- 色彩类：具体十六进制色号（如 #1A1A2E、#E8E3D9），说明用在哪里（背景/文字/强调/边框），给出主色、辅色、点缀色
- 字体类：字体族名（如 SF Pro、思源黑体）、字号（如 14px/28px）、字重（如 400/600/700）、行高（如 1.5）、字间距（如 0.02em）
- 结构类：间距（如 padding 16px 20px）、圆角（如 border-radius 16px）、栅格列数、内容最大宽度
- 质感类：具体 CSS 值 — 阴影（如 box-shadow: 0 4px 24px rgba(0,0,0,0.08)）、模糊度、透明度、渐变方向和色值
- 组件类：按钮尺寸/圆角/颜色、卡片间距/边框、导航高度/布局
- 动效类：缓动函数（如 cubic-bezier(0.4, 0, 0.2, 1)）、时长（如 200ms）、属性（transform/opacity）
- 高级感类：具体实现手法而非抽象感受

禁止使用"简洁"、"现代"、"高级"、"优雅"等模糊形容词。每个因子必须具体到可以直接写 CSS。

只返回 JSON 数组，不要其他文字。
格式：
[
  {"category":"色彩","label":"深灰主文字 #1A1A2E","reason":"正文用深灰而非纯黑，降低对比度疲劳","prompt":"正文颜色 color: #1A1A2E，标题 #111111，次要信息 #8C8C8C。"},
  {"category":"字体","label":"SF Pro 16/24 W500","reason":"正文 16px 配 1.5 行高，medium 字重保证可读性","prompt":"font-family: 'SF Pro Display', -apple-system; font-size: 16px; line-height: 24px; font-weight: 500。"},
  {"category":"质感","label":"8px柔光投影","reason":"卡片浮起感来自低扩散阴影","prompt":"box-shadow: 0 2px 8px rgba(0,0,0,0.06), 0 8px 24px rgba(0,0,0,0.04); border-radius: 16px。"}
]
category 只能是：色彩、结构、组件、质感、字体、动效、高级感。
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

  const prompt = mode === 'polish' ? buildPolishPrompt() : mode === 'video-explosion' ? buildVideoExplosionPrompt() : mode === 'text-explosion' ? buildTextExplosionPrompt() : mode === 'design-explosion' ? buildDesignExplosionPrompt() : mode === 'group' ? buildGroupPrompt() : buildSinglePrompt()

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
      // Explosion modes return JSON arrays — force JSON output format
      const wantsJson = ['text-explosion', 'video-explosion', 'design-explosion'].includes(mode)
      const body = {
        model: modelName,
        messages: [{ role: 'user', content }],
        max_tokens: wantsJson ? 4096 : (mode === 'group' || mode === 'polish') ? 2048 : 1024,
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
    if (path === '/api/ai' && req.method === 'POST') return handleAI(req, env)
    return json({ error: '未找到接口' }, 404)
  }
}
