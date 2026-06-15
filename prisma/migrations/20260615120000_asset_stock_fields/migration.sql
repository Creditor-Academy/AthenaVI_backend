-- AlterTable
ALTER TABLE "Asset" ADD COLUMN "source" TEXT NOT NULL DEFAULT 'upload',
ADD COLUMN "stockProvider" TEXT,
ADD COLUMN "stockExternalId" TEXT,
ADD COLUMN "stockMetadata" JSONB;

-- CreateIndex
CREATE UNIQUE INDEX "Asset_workspaceId_stockProvider_stockExternalId_key" ON "Asset"("workspaceId", "stockProvider", "stockExternalId");
