-- New enum for fixed-purpose share links (viewer vs reviewer).
CREATE TYPE "PresentationShareRole" AS ENUM ('VIEWER', 'REVIEWER');

-- Nullable until backfill completes in the next migration step.
ALTER TABLE "presentation_share_links" ADD COLUMN IF NOT EXISTS "role" "PresentationShareRole";

-- Map legacy access values to the new roles; tokens stay unchanged.
UPDATE "presentation_share_links"
SET "role" = CASE
  WHEN "access"::text = 'COMMENT' THEN 'REVIEWER'::"PresentationShareRole"
  ELSE 'VIEWER'::"PresentationShareRole"
END
WHERE "role" IS NULL;
