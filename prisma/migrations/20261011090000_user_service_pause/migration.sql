-- Admin "pause service" for a user (nullable, so existing rows are unaffected).
ALTER TABLE "users" ADD COLUMN "paused_at" TIMESTAMP(3);
ALTER TABLE "users" ADD COLUMN "pause_reason" TEXT;
