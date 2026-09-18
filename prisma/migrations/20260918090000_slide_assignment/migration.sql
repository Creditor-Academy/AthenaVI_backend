-- AlterEnum
ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'SLIDE_ASSIGNED';
ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'SLIDE_UNASSIGNED';

-- AlterTable
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "assigned_to_id" TEXT;
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "assigned_by_id" TEXT;
ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "assigned_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX IF NOT EXISTS "slides_assigned_to_id_idx" ON "slides"("assigned_to_id");

-- AddForeignKey
DO $$ BEGIN
  ALTER TABLE "slides" ADD CONSTRAINT "slides_assigned_to_id_fkey"
    FOREIGN KEY ("assigned_to_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  ALTER TABLE "slides" ADD CONSTRAINT "slides_assigned_by_id_fkey"
    FOREIGN KEY ("assigned_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;
