# Generated Pages — Worker API & Storage

Backend for the frontend "reference-driven page generation" feature. Full feature doc: `design-board/docs/reference-driven-page-generation.md`.

## AI modes (`/api/ai`, in `handleAI`)
Pure-LLM modes (no images unless passed). Forced JSON output. Provider routing shared with existing modes.

| mode | payload | max_tokens | output |
|---|---|---|---|
| `page-plan` | `target, platform, context` | 4096 | plan JSON (appName, designIntent, globalStyle, pages[]) |
| `page-generate` | `appName, designIntent, globalStyle, platform, page, context` | 8192 | one page `{html,css,js,...}` |
| `page-edit` | + `current:{html,css,js}, instruction` | 8192 | full-replacement page JSON |

- `platform` ∈ `web|app|miniprogram` → injects viewport/container rules (`platformSpec`).
- `context` = the source style-group's design DNA; prompts treat it as the **highest-priority** visual spec (reuse its hex/font/radius/shadow values verbatim).
- Page count: AI decides (no max).

## Persistence endpoints (`/api/generated/*`, behind authMiddleware)
- `POST /groups` `{cardId,title,promptCardId}` → `{id}`
- `POST /pages` `{groupId,slug,title,routePath,sortOrder,parentPageId}` → `{id}`
- `POST /versions` `{pageId,html,css,js,sourcePrompt,editInstruction,summary}` → `{versionId,versionNo}` — writes 3 R2 objects, bumps `generated_pages.current_version_id`, logs `page_edit_events`.
- `GET /versions/:id/content` → `{html,css,js}` (reads R2)
- `GET /pages/:id/versions` → `{versions:[...]}` (newest first)
- `DELETE /groups/:id` → soft-delete group + its pages

## Storage
- D1 tables: `migrations/0003_generated_pages.sql` → `generated_page_groups`, `generated_pages`, `generated_page_versions`, `page_edit_events` (all `IF NOT EXISTS`).
- R2 (`ASSETS`): `generated/{groupId}/{pageId}/v{n}/index.html|styles.css|script.js`. Private; served only via authed Worker GET.
- Cleanup: `scheduled` cron hard-deletes soft-deleted groups (rows + R2 objects) after a **7-day** grace — same grace as `cleanupAssets`.

## Apply migration
`npx wrangler d1 migrations apply design-board --remote` (0003 applied to prod 2026-06-03).
