-- Finalize role column and dual-link schema.
ALTER TABLE "presentation_share_links" ALTER COLUMN "role" SET NOT NULL;

ALTER TABLE "presentation_share_links" DROP COLUMN IF EXISTS "expires_at";

ALTER TABLE "presentation_share_links" DROP COLUMN IF EXISTS "access";

DROP INDEX IF EXISTS "presentation_share_links_project_id_key";

CREATE UNIQUE INDEX IF NOT EXISTS "presentation_share_links_project_id_role_key"
  ON "presentation_share_links"("project_id", "role");

-- access column referenced the old enum; safe to drop once the column is gone.
DROP TYPE IF EXISTS "PresentationShareAccess";
