-- Align with existing production columns if an older migration only partially landed.
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "preview_s3_key" TEXT;
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "preview_hash" TEXT;
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "preview_status" TEXT;

-- Drop unused timestamp column if a prior attempt created it.
ALTER TABLE "slides" DROP COLUMN IF EXISTS "preview_updated_at";
