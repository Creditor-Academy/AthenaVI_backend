ALTER TABLE "project_comments" ADD COLUMN IF NOT EXISTS "resolved_at" TIMESTAMP(3);
ALTER TABLE "project_comments" ADD COLUMN IF NOT EXISTS "resolved_by" TEXT;
