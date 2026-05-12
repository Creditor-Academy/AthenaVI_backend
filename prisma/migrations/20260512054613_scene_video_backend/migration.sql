-- AlterTable
ALTER TABLE "HeygenResponse" ADD COLUMN     "folderId" TEXT;

-- CreateTable
CREATE TABLE "project_renders" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "folderId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "triggeredBy" TEXT,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "progress" INTEGER NOT NULL DEFAULT 0,
    "s3Key" TEXT,
    "outputUrl" TEXT,
    "inputSnapshot" JSONB,
    "sceneHashes" JSONB,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),

    CONSTRAINT "project_renders_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scene_render_caches" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "folderId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "sceneId" TEXT NOT NULL,
    "sceneHash" TEXT NOT NULL,
    "s3Key" TEXT NOT NULL,
    "outputUrl" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scene_render_caches_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "project_renders_workspaceId_projectId_idx" ON "project_renders"("workspaceId", "projectId");

-- CreateIndex
CREATE INDEX "scene_render_caches_workspaceId_projectId_idx" ON "scene_render_caches"("workspaceId", "projectId");

-- CreateIndex
CREATE UNIQUE INDEX "scene_render_caches_projectId_sceneId_sceneHash_key" ON "scene_render_caches"("projectId", "sceneId", "sceneHash");

-- AddForeignKey
ALTER TABLE "project_renders" ADD CONSTRAINT "project_renders_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "project_renders" ADD CONSTRAINT "project_renders_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scene_render_caches" ADD CONSTRAINT "scene_render_caches_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scene_render_caches" ADD CONSTRAINT "scene_render_caches_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
