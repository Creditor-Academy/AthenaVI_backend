-- AlterTable
ALTER TABLE "user_settings" ADD COLUMN "push_notifications" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "user_settings" ADD COLUMN "comments_and_mentions" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "user_settings" ADD COLUMN "weekly_digest_email" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "user_settings" ADD COLUMN "product_emails" BOOLEAN NOT NULL DEFAULT false;
