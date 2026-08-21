-- Persist raw share token so owners can copy the same URL on every GET.
-- Nullable: rows created before this column cannot recover a lost token (rotate once).
ALTER TABLE "presentation_share_links" ADD COLUMN IF NOT EXISTS "token" TEXT;
