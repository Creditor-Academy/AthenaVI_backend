ALTER TABLE "project_comments" ADD COLUMN IF NOT EXISTS "parent_id" TEXT;

CREATE INDEX IF NOT EXISTS "project_comments_parent_id_idx" ON "project_comments"("parent_id");

DO $$ BEGIN
  ALTER TABLE "project_comments" ADD CONSTRAINT "project_comments_parent_id_fkey"
    FOREIGN KEY ("parent_id") REFERENCES "project_comments"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
