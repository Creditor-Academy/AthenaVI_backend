-- CreateTable presentation_comments
CREATE TABLE IF NOT EXISTS "presentation_comments" (
    "id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "slide_id" TEXT,
    "parent_id" TEXT,
    "author_id" TEXT,
    "guest_session_id" TEXT,
    "guest_display_name" TEXT,
    "body" TEXT NOT NULL,
    "mentioned_user_ids" TEXT[],
    "resolved_at" TIMESTAMP(3),
    "resolved_by" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "presentation_comments_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "presentation_comments_project_id_slide_id_created_at_idx" ON "presentation_comments"("project_id", "slide_id", "created_at");
CREATE INDEX IF NOT EXISTS "presentation_comments_parent_id_idx" ON "presentation_comments"("parent_id");
CREATE INDEX IF NOT EXISTS "presentation_comments_workspace_id_idx" ON "presentation_comments"("workspace_id");
CREATE INDEX IF NOT EXISTS "presentation_comments_guest_session_id_idx" ON "presentation_comments"("guest_session_id");

-- AddForeignKey
DO $$ BEGIN
  ALTER TABLE "presentation_comments" ADD CONSTRAINT "presentation_comments_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "presentation_comments" ADD CONSTRAINT "presentation_comments_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- SET NULL, not CASCADE: a full deck regenerate deletes every slide row, and cascading
-- here would silently destroy the whole comment history. Orphaned threads stay readable
-- in the editor instead.
DO $$ BEGIN
  ALTER TABLE "presentation_comments" ADD CONSTRAINT "presentation_comments_slide_id_fkey" FOREIGN KEY ("slide_id") REFERENCES "slides"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "presentation_comments" ADD CONSTRAINT "presentation_comments_parent_id_fkey" FOREIGN KEY ("parent_id") REFERENCES "presentation_comments"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "presentation_comments" ADD CONSTRAINT "presentation_comments_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
