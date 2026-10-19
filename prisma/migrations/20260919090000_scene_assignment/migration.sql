-- AlterEnum
-- Scene assignment lives inside Project.data.scenes[] (JSON), not a table — only the
-- notification enum needs a schema change here.
ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'SCENE_ASSIGNED';
ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'SCENE_UNASSIGNED';
