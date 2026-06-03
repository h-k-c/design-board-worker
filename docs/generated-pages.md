# Generated Pages — Worker API & Storage

Backend for the frontend "reference-driven page generation" feature. Full feature doc: `design-board/docs/reference-driven-page-generation.md`.

## AI modes (`/api/ai`, in `handleAI`)
Pure-LLM modes (no images unless passed). Forced JSON output. Provider routing shared with existing modes.

| mode | payload | max_tokens | output |
|---|---|---|---|
| `page-plan` | `target, platform, maxPages, referenceMode, generationScope, context` | 4096 | plan JSON (appName, designIntent, globalStyle, pages[]) |
| `page-generate` | `appName, designIntent, globalStyle, platform, referenceMode, page, context` | 8192 | one page `{html,css,js,...}` |
| `page-edit` | + `current:{html,css,js}, instruction` | 8192 | full-replacement page JSON |

- `platform` ∈ `web|app|miniprogram` → injects viewport/container rules (`platformSpec`).
- `context` = merged generation evidence. UI page generation treats style-group / aesthetic DNA and design-bubbles (`大爆炸`) concrete factors as the **highest-priority** visual spec (reuse hex/font/radius/shadow/spacing/motion values verbatim when present).
- Image prompts / image descriptions / single-image AI analysis are downgraded to auxiliary semantic evidence: useful for content meaning and atmosphere, but they must not override concrete DNA or `大爆炸` visual values.
- `design-explosion`, `text-explosion`, and `video-explosion` are expected to produce fuller design-bubble factors across: context/purpose, subject/content, composition/hierarchy, layout/grid/space, color/light/contrast, typography/text, components/states, material/texture/quality, motion/interaction, transferable CSS parameters, and negative constraints.
- Page count: AI decides inside a hard user cap (`maxPages`, 1-8; `generationScope=single` forces 1).
- `referenceMode=strict|balanced` controls whether prompts demand direct reuse of DNA values or allow more target-product adaptation.
- Page generation `notes` should include DNA-to-code mappings so weak/generic outputs are easier to spot.

## Persistence endpoints (`/api/generated/*`, behind authMiddleware)
- `POST /groups` `{cardId,title,promptCardId}` → `{id}`
- `POST /pages` `{groupId,slug,title,routePath,sortOrder,parentPageId}` → `{id}`
- `POST /versions` `{pageId,html,css,js,sourcePrompt,editInstruction,summary}` → `{versionId,versionNo}` — writes 3 R2 objects, bumps `generated_pages.current_version_id`, logs `page_edit_events`.
- `GET /versions/:id/content` → `{html,css,js}` (reads R2)
- `GET /pages/:id/versions` → `{versions:[...]}` (newest first)
- `DELETE /pages/:id` → soft-delete one generated page
- `DELETE /groups/:id` → soft-delete group + its pages

## Storage
- D1 tables: `migrations/0003_generated_pages.sql` → `generated_page_groups`, `generated_pages`, `generated_page_versions`, `page_edit_events` (all `IF NOT EXISTS`).
- R2 (`ASSETS`): `generated/{groupId}/{pageId}/v{n}/index.html|styles.css|script.js`. Private; served only via authed Worker GET.
- Cleanup: `scheduled` cron hard-deletes soft-deleted pages/groups (rows + R2 objects) after a **7-day** grace — same grace as `cleanupAssets`.

## Apply migration
`npx wrangler d1 migrations apply design-board --remote` (0003 applied to prod 2026-06-03).
