-- AlterEnum TemplateType
DO $$ BEGIN
  ALTER TYPE "TemplateType" ADD VALUE 'DECK_PACK';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- CreateTable workspace_brand_kits
CREATE TABLE IF NOT EXISTS "workspace_brand_kits" (
    "id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "is_default" BOOLEAN NOT NULL DEFAULT false,
    "data" JSONB NOT NULL,
    "created_by" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "workspace_brand_kits_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "workspace_brand_kits_workspace_id_is_default_idx"
  ON "workspace_brand_kits"("workspace_id", "is_default");

-- CreateTable brand_kit_media
CREATE TABLE IF NOT EXISTS "brand_kit_media" (
    "id" TEXT NOT NULL,
    "brand_kit_id" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "role" TEXT,
    "name" TEXT,
    "asset_id" TEXT,
    "s3_key" TEXT NOT NULL,
    "mime_type" TEXT,
    "sort_order" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "brand_kit_media_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "brand_kit_media_brand_kit_id_kind_idx"
  ON "brand_kit_media"("brand_kit_id", "kind");

ALTER TABLE "workspace_brand_kits"
  DROP CONSTRAINT IF EXISTS "workspace_brand_kits_workspace_id_fkey";
ALTER TABLE "workspace_brand_kits"
  ADD CONSTRAINT "workspace_brand_kits_workspace_id_fkey"
  FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "brand_kit_media"
  DROP CONSTRAINT IF EXISTS "brand_kit_media_brand_kit_id_fkey";
ALTER TABLE "brand_kit_media"
  ADD CONSTRAINT "brand_kit_media_brand_kit_id_fkey"
  FOREIGN KEY ("brand_kit_id") REFERENCES "workspace_brand_kits"("id") ON DELETE CASCADE ON UPDATE CASCADE;
