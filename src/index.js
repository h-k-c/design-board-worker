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

  await env.DB.prepare(
    'INSERT INTO images (id, data, filename, content_type) VALUES (?,?,?,?)'
  ).bind(id, data, filename, contentType || 'image/jpeg').run()

  return json({ url: `/api/images/${id}` })
}

async function handleGetImage(req, env, id) {
  const row = await env.DB.prepare('SELECT data, content_type FROM images WHERE id = ?').bind(id).first()
  if (!row) return new Response('未找到图片', { status: 404, headers: CORS })

  const match = row.data.match(/^data:(.+?);base64,(.+)$/)
  if (!match) return new Response('图片格式无效', { status: 400, headers: CORS })

  const binaryStr = atob(match[2])
  const bytes = new Uint8Array(binaryStr.length)
  for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i)

  return new Response(bytes, {
    headers: { 'Content-Type': row.content_type || match[1], ...CORS }
  })
}

// Resolve Worker image URLs to data URLs so external APIs can access them
async function resolveImageUrl(imageUrl, env) {
  const match = imageUrl.match(/\/api\/images\/([^/?#]+)/)
  if (!match) return imageUrl
  const row = await env.DB.prepare('SELECT data FROM images WHERE id = ?').bind(match[1]).first()
  return row?.data || imageUrl
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
    const systemPrompt = `你是一名资深 UI 设计分析师。用户会用文字描述一个让他印象深刻的设计、界面、或产品体验。请根据描述拆解出设计因子。`
    const userPrompt = `用户描述：
"${context || ''}"

请根据这段文字描述，提取 10-14 个设计因子。尽量只返回 JSON 数组，不要长段落。
格式：
[
  {"category":"色彩","label":"冷白背景","reason":"背景干净，降低视觉噪音","prompt":"使用冷白或低饱和浅色背景承载页面，避免脏灰。"},
  {"category":"结构","label":"宽松留白","reason":"空间感强，内容更高级","prompt":"在主要内容、卡片和操作区之间保留充足留白。"}
]
category 只能是：色彩、结构、组件、质感、字体、动效、高级感。
label 必须 2-8 个中文词，适合显示在小气泡里。
prompt 是这个因子给 Codex/Claude Code 生成 UI 时可直接使用的实现指令。
即使用户的描述比较抽象（如"整体色调好"、"层次感好"），也要尽量拆解成具体的可执行因子。`
    return { systemPrompt, userPrompt, imageUrls: [] }
  }

  function buildVideoExplosionPrompt() {
    const systemPrompt = `你是一名资深交互与动效设计分析师。用户提供了一段界面录屏的关键帧截图，请重点分析其中的动效、转场、交互反馈和视觉节奏。`
    const userPrompt = `${context ? `用户补充说明："${context}"\n\n` : ''}以下是从一段界面录屏中提取的关键帧。请重点分析：
- 页面之间的转场方式（滑动、淡入、缩放…）
- 元素的出现/消失动画
- 交互反馈（点击、滑动、长按的视觉响应）
- 动效的节奏感（快慢、缓动曲线的感觉）
- 整体的动态氛围

请拆解为 10-14 个设计因子。尽量只返回 JSON 数组，不要长段落。
格式：
[
  {"category":"动效","label":"弹性缓入转场","reason":"页面切换有弹性回弹感，增加活力","prompt":"页面切换使用 spring easing（如 cubic-bezier(0.34, 1.56, 0.64, 1)），让转场有弹性回弹感。"},
  {"category":"质感","label":"毛玻璃层叠","reason":"多层半透明叠加营造深度","prompt":"使用 backdrop-filter: blur(20px) 配合半透明背景色实现毛玻璃效果。"}
]
category 只能是：色彩、结构、组件、质感、字体、动效、高级感。
label 必须 2-8 个中文词，适合显示在小气泡里。
prompt 是这个因子给 Codex/Claude Code 生成 UI 时可直接使用的实现指令。
请特别关注「动效」和「质感」类目，因为用户提供的是录屏而非静态截图。`
    const imageUrls = images.map(img => img.imageUrl || img).filter(Boolean).slice(0, 8)
    return { systemPrompt, userPrompt, imageUrls }
  }

  const prompt = mode === 'video-explosion' ? buildVideoExplosionPrompt() : mode === 'text-explosion' ? buildTextExplosionPrompt() : mode === 'group' ? buildGroupPrompt() : buildSinglePrompt()

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
      const res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: modelName,
          messages: [{ role: 'user', content }],
          max_tokens: mode === 'group' ? 2048 : 1024,
          enable_thinking: false,
        })
      })
      const data = await res.json().catch(() => ({}))
      console.log(`[AI] ${apiUrl} status=${res.status}`)
      if (!res.ok) {
        const errMsg = data.error?.message || data.error?.code || data.message || `HTTP ${res.status}`
        return `AI 请求失败: ${errMsg}`
      }
      const text = data.choices?.[0]?.message?.content
      if (!text) {
        console.log(`[AI] Empty response: ${JSON.stringify(data).slice(0, 300)}`)
        return `AI 返回为空: ${JSON.stringify(data).slice(0, 200)}`
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
