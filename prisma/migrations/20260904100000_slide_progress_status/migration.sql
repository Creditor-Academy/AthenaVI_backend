-- Editor-set slide progress for reviewers (separate from generation status).
CREATE TYPE "SlideProgressStatus" AS ENUM ('TODO', 'IN_PROGRESS', 'COMPLETED');

ALTER TABLE "slides" ADD COLUMN IF NOT EXISTS "progress_status" "SlideProgressStatus";
