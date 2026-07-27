-- CreateEnum
CREATE TYPE "ProjectType" AS ENUM ('VIDEO', 'PRESENTATION');

-- CreateEnum
CREATE TYPE "TemplateType" AS ENUM ('VIDEO_SCENE', 'DECK_LAYOUT');

-- AlterEnum InboxNotificationType (Postgres <15 compatible)
DO $$ BEGIN
  ALTER TYPE "InboxNotificationType" ADD VALUE 'PRESENTATION_EXPORT_COMPLETED';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TYPE "InboxNotificationType" ADD VALUE 'PRESENTATION_EXPORT_FAILED';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TYPE "InboxNotificationType" ADD VALUE 'PRESENTATION_GENERATION_COMPLETED';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TYPE "InboxNotificationType" ADD VALUE 'PRESENTATION_GENERATION_FAILED';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- AlterTable Project
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "type" "ProjectType" NOT NULL DEFAULT 'VIDEO';
CREATE INDEX IF NOT EXISTS "Project_type_idx" ON "Project"("type");

-- CreateTable decks
CREATE TABLE IF NOT EXISTS "decks" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "themeTokens" JSONB NOT NULL,
    "outline" JSONB,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "aspectRatio" TEXT NOT NULL DEFAULT '16:9',
    "locale" TEXT NOT NULL DEFAULT 'en',
    "promptBundleVersion" TEXT,
    "generationMetrics" JSONB,
    "partial" BOOLEAN NOT NULL DEFAULT false,
    "creditsChargedSoFar" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "decks_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "decks_projectId_key" ON "decks"("projectId");
CREATE INDEX IF NOT EXISTS "decks_status_idx" ON "decks"("status");

-- CreateTable slides
CREATE TABLE IF NOT EXISTS "slides" (
    "id" TEXT NOT NULL,
    "deckId" TEXT NOT NULL,
    "order" INTEGER NOT NULL,
    "contentType" TEXT,
    "layoutId" TEXT,
    "content" JSONB,
    "imageRef" JSONB,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "manuallyEdited" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "slides_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "slides_deckId_order_idx" ON "slides"("deckId", "order");

-- CreateTable templates
CREATE TABLE IF NOT EXISTS "templates" (
    "id" TEXT NOT NULL,
    "type" "TemplateType" NOT NULL,
    "name" TEXT NOT NULL,
    "contentType" TEXT,
    "variant" TEXT,
    "schema" JSONB NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "templates_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "templates_type_contentType_isActive_idx" ON "templates"("type", "contentType", "isActive");

-- CreateTable slide_generation_jobs
CREATE TABLE IF NOT EXISTS "slide_generation_jobs" (
    "id" TEXT NOT NULL,
    "slideId" TEXT NOT NULL,
    "jobType" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "requestHash" TEXT NOT NULL,
    "promptVersion" TEXT,
    "model" TEXT,
    "usage" JSONB,
    "visionScore" DOUBLE PRECISION,
    "error" TEXT,
    "creditCharged" BOOLEAN NOT NULL DEFAULT false,
    "latencyMs" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "slide_generation_jobs_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "slide_generation_jobs_requestHash_key" ON "slide_generation_jobs"("requestHash");
CREATE INDEX IF NOT EXISTS "slide_generation_jobs_slideId_jobType_idx" ON "slide_generation_jobs"("slideId", "jobType");

-- CreateTable deck_exports
CREATE TABLE IF NOT EXISTS "deck_exports" (
    "id" TEXT NOT NULL,
    "deckId" TEXT NOT NULL,
    "format" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "s3Key" TEXT,
    "error" TEXT,
    "creditCharged" BOOLEAN NOT NULL DEFAULT false,
    "creditsCharged" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "deck_exports_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "deck_exports_deckId_status_idx" ON "deck_exports"("deckId", "status");

-- CreateTable presentation_image_cache
CREATE TABLE IF NOT EXISTS "presentation_image_cache" (
    "id" TEXT NOT NULL,
    "briefHash" TEXT NOT NULL,
    "s3Key" TEXT NOT NULL,
    "url" TEXT,
    "source" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "presentation_image_cache_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "presentation_image_cache_briefHash_key" ON "presentation_image_cache"("briefHash");

-- FKs
DO $$ BEGIN
  ALTER TABLE "decks" ADD CONSTRAINT "decks_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "slides" ADD CONSTRAINT "slides_deckId_fkey" FOREIGN KEY ("deckId") REFERENCES "decks"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "slide_generation_jobs" ADD CONSTRAINT "slide_generation_jobs_slideId_fkey" FOREIGN KEY ("slideId") REFERENCES "slides"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "deck_exports" ADD CONSTRAINT "deck_exports_deckId_fkey" FOREIGN KEY ("deckId") REFERENCES "decks"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
