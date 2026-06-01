-- Folder metadata
ALTER TABLE "Folder" ADD COLUMN "updatedBy" TEXT;
ALTER TABLE "Folder" ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX "Folder_updatedBy_idx" ON "Folder"("updatedBy");

-- Project metadata + storage
ALTER TABLE "Project" ADD COLUMN "updatedBy" TEXT;
ALTER TABLE "Project" ADD COLUMN "storageBytes" INTEGER NOT NULL DEFAULT 0;
CREATE INDEX "Project_updatedBy_idx" ON "Project"("updatedBy");

UPDATE "Project" SET "updatedBy" = "createdBy" WHERE "updatedBy" IS NULL;

-- S3 row file sizes
ALTER TABLE "HeygenResponse" ADD COLUMN "fileSizeBytes" INTEGER;
ALTER TABLE "project_renders" ADD COLUMN "fileSizeBytes" INTEGER;
ALTER TABLE "scene_render_caches" ADD COLUMN "fileSizeBytes" INTEGER;
