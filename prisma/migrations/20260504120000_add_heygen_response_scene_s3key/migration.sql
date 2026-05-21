-- AlterTable
ALTER TABLE "HeygenResponse" ADD COLUMN "sceneId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "HeygenResponse" ADD COLUMN "s3Key" TEXT;

-- CreateIndex
CREATE INDEX "HeygenResponse_projectId_workspaceId_idx" ON "HeygenResponse"("projectId", "workspaceId");
