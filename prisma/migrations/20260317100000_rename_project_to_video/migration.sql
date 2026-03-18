-- Rename table projects to videos
ALTER TABLE "projects" RENAME TO "videos";

-- Rename column in scenes
ALTER TABLE "scenes" RENAME COLUMN "project_id" TO "video_id";

-- Rename foreign key constraint (optional, for clarity)
ALTER TABLE "scenes" RENAME CONSTRAINT "scenes_project_id_fkey" TO "scenes_video_id_fkey";

-- Rename indexes (optional, for clarity)
ALTER INDEX IF EXISTS "projects_workspace_id_idx" RENAME TO "videos_workspace_id_idx";
ALTER INDEX IF EXISTS "scenes_project_id_idx" RENAME TO "scenes_video_id_idx";
ALTER INDEX IF EXISTS "scenes_project_id_order_idx" RENAME TO "scenes_video_id_order_idx";
