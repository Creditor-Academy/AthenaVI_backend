-- AlterTable
ALTER TABLE "users" ADD COLUMN "credits" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "users" ADD COLUMN "is_platform_superadmin" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "credit_transactions" ADD COLUMN "scope" TEXT;
ALTER TABLE "credit_transactions" ADD COLUMN "idempotencyKey" TEXT;
ALTER TABLE "credit_transactions" ADD COLUMN "metadata" JSONB;
ALTER TABLE "credit_transactions" ALTER COLUMN "workspaceId" DROP NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "credit_transactions_idempotencyKey_key" ON "credit_transactions"("idempotencyKey");
CREATE INDEX "credit_transactions_scope_idx" ON "credit_transactions"("scope");

-- AlterTable
ALTER TABLE "HeygenResponse" ADD COLUMN "triggered_by_user_id" TEXT;
ALTER TABLE "HeygenResponse" ADD COLUMN "credits_charged" INTEGER;
ALTER TABLE "HeygenResponse" ADD COLUMN "billed_duration_sec" DOUBLE PRECISION;
ALTER TABLE "HeygenResponse" ADD COLUMN "billing_status" TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE "HeygenResponse" ADD COLUMN "billing_context" JSONB;

-- AlterTable
ALTER TABLE "project_renders" ADD COLUMN "credits_charged" INTEGER;
ALTER TABLE "project_renders" ADD COLUMN "billed_duration_sec" DOUBLE PRECISION;
ALTER TABLE "project_renders" ADD COLUMN "billing_status" TEXT NOT NULL DEFAULT 'pending';
