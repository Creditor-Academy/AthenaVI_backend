-- CreateEnum
CREATE TYPE "GraphicType" AS ENUM ('decorative', 'illustration', 'icon', 'abstract', 'pattern');

-- CreateEnum
CREATE TYPE "GraphicColorMode" AS ENUM ('recolorable', 'fixed');

-- CreateEnum
CREATE TYPE "GraphicStatus" AS ENUM ('draft', 'published', 'archived');

-- CreateTable
CREATE TABLE "graphic_asset" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "file_url" TEXT NOT NULL,
    "s3_key" TEXT NOT NULL,
    "preview_url" TEXT NOT NULL,
    "preview_s3_key" TEXT,
    "type" "GraphicType" NOT NULL,
    "category" TEXT NOT NULL,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "style" TEXT,
    "moods" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "usage" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "color_mode" "GraphicColorMode" NOT NULL,
    "contains_text" BOOLEAN NOT NULL DEFAULT false,
    "status" "GraphicStatus" NOT NULL DEFAULT 'draft',
    "created_by" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "graphic_asset_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "graphic_asset_status_type_idx" ON "graphic_asset"("status", "type");

-- CreateIndex
CREATE INDEX "graphic_asset_status_category_idx" ON "graphic_asset"("status", "category");

-- CreateIndex
CREATE INDEX "graphic_asset_created_at_idx" ON "graphic_asset"("created_at");

-- CreateIndex (GIN for tag containment / keyword search)
CREATE INDEX "graphic_asset_tags_gin_idx" ON "graphic_asset" USING GIN ("tags");
