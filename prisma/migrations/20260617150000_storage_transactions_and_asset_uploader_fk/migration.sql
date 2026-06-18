-- Create storage ledger table
CREATE TABLE "storage_transactions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "amount_bytes" INTEGER NOT NULL,
    "type" TEXT NOT NULL,
    "tier_id" TEXT,
    "reference" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "storage_transactions_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "storage_transactions_userId_createdAt_idx" ON "storage_transactions"("userId", "createdAt");
CREATE INDEX "storage_transactions_type_idx" ON "storage_transactions"("type");

-- Add relation/indexes for asset uploader and workspace render library
CREATE INDEX "Asset_workspaceId_uploadedBy_idx" ON "Asset"("workspaceId", "uploadedBy");
CREATE INDEX "project_renders_workspaceId_status_completedAt_idx" ON "project_renders"("workspaceId", "status", "completedAt");

ALTER TABLE "storage_transactions"
ADD CONSTRAINT "storage_transactions_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "users"("id")
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "Asset"
ADD CONSTRAINT "Asset_uploadedBy_fkey"
FOREIGN KEY ("uploadedBy") REFERENCES "users"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
