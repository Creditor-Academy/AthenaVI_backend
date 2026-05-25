-- AlterTable
ALTER TABLE "users" ADD COLUMN "deletion_requested_at" TIMESTAMP(3);
ALTER TABLE "users" ADD COLUMN "deletion_scheduled_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "users_deletion_scheduled_at_idx" ON "users"("deletion_scheduled_at");
