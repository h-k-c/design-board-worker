# R2 Asset Storage

This Worker stores new design-board images in Cloudflare R2 and keeps only
asset metadata in D1. Existing D1-backed `/api/images/:id` images remain
served for backwards compatibility.

## Cloudflare Setup

1. Create the bucket:

```sh
wrangler r2 bucket create design-board-assets
```

2. Apply the asset metadata migration:

```sh
wrangler d1 migrations apply design-board --remote
```

3. Configure public asset access.

Use a custom domain for production R2 public access. Cloudflare's `r2.dev`
public URL is useful for development but is not the production path.

Set the Worker variable after the bucket domain is active:

```toml
ASSET_PUBLIC_BASE_URL = "https://assets.example.com"
```

This is not a secret; it can be stored in `wrangler.toml` or in the
Cloudflare dashboard variables UI.

4. Configure R2 CORS for the frontend domain. Canvas-based flows such as crop,
OCR, matting, and image resizing need cross-origin reads to work.

Example policy:

```json
[
  {
    "AllowedOrigins": [
      "https://your-frontend-domain.example.com",
      "http://localhost:5173"
    ],
    "AllowedMethods": ["GET"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["Content-Type"],
    "MaxAgeSeconds": 3600
  }
]
```

## Runtime Behavior

- `POST /api/upload`
  - With `env.ASSETS`: decodes the uploaded data URL, writes the bytes to R2,
    inserts an `assets` row, and returns a public `url` plus `assetId` and
    `imageKey`.
  - Without `env.ASSETS`: falls back to the legacy D1 `images` table.

- `GET /api/assets/:assetId`
  - Serves an R2 object through the Worker. This is a fallback for development
    or missing `ASSET_PUBLIC_BASE_URL`; production display should use the R2
    public/custom-domain URL directly.

- `GET /api/images/:imageId`
  - Legacy D1 image serving only. Keep this route until old cards are migrated.

- `POST /api/ai`
  - Resolves `/api/assets/:assetId`, configured public R2 URLs, and legacy
    `/api/images/:imageId` into data URLs before sending images to vision
    providers.

## Old Image Migration

The legacy `images.card_id` relationship is unreliable because current uploads
insert only `id`, `data`, `filename`, and `content_type`, while card deletion
tries to delete by `card_id`.

Migration should scan card JSON instead of trusting `images.card_id`:

1. Read every legacy `images` row.
2. Decode `images.data` and upload it to R2 using a stable key such as
   `images/legacy/<imageId>.<ext>`.
3. Insert an `assets` row with `source_image_id = images.id`.
4. Scan `cards.content` for `/api/images/<imageId>` references.
5. Rewrite those card JSON references to the new public R2 URL and add
   `assetId` / `imageKey`.
6. Keep `/api/images/:id` available until the rewritten board has been loaded,
   verified, and saved successfully.
