-- AlterEnum
ALTER TYPE "InboxNotificationType" ADD VALUE 'WORKSPACE_MEMBER_JOINED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'WORKSPACE_MEMBER_REMOVED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'WORKSPACE_ROLE_CHANGED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'VIDEO_EXPORT_COMPLETED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'VIDEO_EXPORT_FAILED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'CREDITS_PLATFORM_GRANT';
ALTER TYPE "InboxNotificationType" ADD VALUE 'CREDITS_PLATFORM_REVOKE';
ALTER TYPE "InboxNotificationType" ADD VALUE 'CREDITS_WORKSPACE_GRANT';
ALTER TYPE "InboxNotificationType" ADD VALUE 'CREDITS_ALLOCATED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'CREDITS_DEALLOCATED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'CREDITS_LOW_PERSONAL';
ALTER TYPE "InboxNotificationType" ADD VALUE 'CREDITS_LOW_WORKSPACE';
ALTER TYPE "InboxNotificationType" ADD VALUE 'STORAGE_PLATFORM_GRANT';
ALTER TYPE "InboxNotificationType" ADD VALUE 'STORAGE_PLATFORM_REVOKE';
ALTER TYPE "InboxNotificationType" ADD VALUE 'STORAGE_THRESHOLD_WARNING';
ALTER TYPE "InboxNotificationType" ADD VALUE 'STORAGE_UPLOAD_BLOCKED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'PLATFORM_HEYGEN_WALLET_LOW';

-- AlterTable user_settings
ALTER TABLE "user_settings" ADD COLUMN "video_export_alerts" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "user_settings" ADD COLUMN "workspace_video_export_alerts" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "user_settings" ADD COLUMN "credits_alerts" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "user_settings" ADD COLUMN "storage_alerts" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "user_settings" ADD COLUMN "workspace_team_alerts" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "user_settings" ADD COLUMN "platform_admin_alerts" BOOLEAN NOT NULL DEFAULT true;

-- AlterTable user_inbox_notifications
ALTER TABLE "user_inbox_notifications" ADD COLUMN "workspace_id" TEXT;
ALTER TABLE "user_inbox_notifications" ADD COLUMN "reference_id" TEXT;

-- CreateIndex
CREATE INDEX "user_inbox_notifications_user_id_workspace_id_idx" ON "user_inbox_notifications"("user_id", "workspace_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_inbox_notifications_user_id_type_reference_id_key" ON "user_inbox_notifications"("user_id", "type", "reference_id");
