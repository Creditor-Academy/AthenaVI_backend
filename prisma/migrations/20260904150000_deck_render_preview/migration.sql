-- Deck previews are now live-rendered by the frontend renderer, so per-slide JPEG snapshots
-- are gone. What remains is one captured cover per deck, tracked on the project.

-- Cover capture timestamp: `Project.updatedAt` moves on unrelated writes and cannot answer
-- "is the thumbnail stale relative to slide 1". The Project model has no @@map, so the
-- table name is the quoted, case-sensitive model name.
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "thumbnail_updated_at" TIMESTAMP(3);

-- Snapshot bookkeeping for the retired Puppeteer rasterizer.
ALTER TABLE "slides" DROP COLUMN IF EXISTS "preview_s3_key";
ALTER TABLE "slides" DROP COLUMN IF EXISTS "preview_hash";
ALTER TABLE "slides" DROP COLUMN IF EXISTS "preview_status";
