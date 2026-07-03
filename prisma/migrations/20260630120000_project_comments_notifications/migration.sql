-- AlterEnum
ALTER TYPE "InboxNotificationType" ADD VALUE 'PROJECT_COMMENT_ADDED';
ALTER TYPE "InboxNotificationType" ADD VALUE 'PROJECT_COMMENT_MENTION';

-- AlterTable
ALTER TABLE "user_settings" ADD COLUMN "last_weekly_digest_sent_at" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "project_comments" (
    "id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "author_id" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "mentioned_user_ids" TEXT[],
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "deleted_at" TIMESTAMP(3),

    CONSTRAINT "project_comments_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "project_comments_project_id_created_at_idx" ON "project_comments"("project_id", "created_at");

-- CreateIndex
CREATE INDEX "project_comments_workspace_id_idx" ON "project_comments"("workspace_id");

-- AddForeignKey
ALTER TABLE "project_comments" ADD CONSTRAINT "project_comments_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "project_comments" ADD CONSTRAINT "project_comments_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "project_comments" ADD CONSTRAINT "project_comments_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
