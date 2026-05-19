-- CreateEnum
CREATE TYPE "InboxNotificationType" AS ENUM ('WORKSPACE_INVITATION');

-- CreateTable
CREATE TABLE "user_inbox_notifications" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "type" "InboxNotificationType" NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "read_at" TIMESTAMP(3),
    "metadata" JSONB,
    "invitation_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_inbox_notifications_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "user_inbox_notifications_user_id_read_at_idx" ON "user_inbox_notifications"("user_id", "read_at");

-- CreateIndex
CREATE INDEX "user_inbox_notifications_user_id_created_at_idx" ON "user_inbox_notifications"("user_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "user_inbox_notifications_user_id_invitation_id_key" ON "user_inbox_notifications"("user_id", "invitation_id");

-- AddForeignKey
ALTER TABLE "user_inbox_notifications" ADD CONSTRAINT "user_inbox_notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
