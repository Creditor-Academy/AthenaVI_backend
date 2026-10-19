-- AlterEnum
ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'PROJECT_ASSIGNED';
ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'PROJECT_UNASSIGNED';

-- AlterTable
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "assigned_to_id" TEXT;
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "assigned_by_id" TEXT;
ALTER TABLE "Project" ADD COLUMN IF NOT EXISTS "assigned_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX IF NOT EXISTS "Project_assigned_to_id_idx" ON "Project"("assigned_to_id");
CREATE INDEX IF NOT EXISTS "Project_workspaceId_assigned_to_id_idx" ON "Project"("workspaceId", "assigned_to_id");

-- AddForeignKey
DO $$ BEGIN
  ALTER TABLE "Project" ADD CONSTRAINT "Project_assigned_to_id_fkey"
    FOREIGN KEY ("assigned_to_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
  ALTER TABLE "Project" ADD CONSTRAINT "Project_assigned_by_id_fkey"
    FOREIGN KEY ("assigned_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;
