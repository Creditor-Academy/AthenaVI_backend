-- AlterTable
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "elements" JSONB;
