-- Add optional like/dislike and a hide timestamp. Existing rows stay unchanged.
ALTER TABLE "image_generations" ADD COLUMN "feedback" TEXT;
ALTER TABLE "image_generations" ADD COLUMN "deleted_at" TIMESTAMP(3);
