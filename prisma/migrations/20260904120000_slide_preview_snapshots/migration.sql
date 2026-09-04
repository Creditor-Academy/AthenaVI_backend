ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "preview_s3_key" TEXT;
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "preview_updated_at" TIMESTAMP(3);
