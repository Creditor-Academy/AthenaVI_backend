-- AlterTable
ALTER TABLE "slides" ADD COLUMN "preview_s3_key" TEXT;
ALTER TABLE "slides" ADD COLUMN "preview_hash" TEXT;
ALTER TABLE "slides" ADD COLUMN "preview_status" TEXT;
