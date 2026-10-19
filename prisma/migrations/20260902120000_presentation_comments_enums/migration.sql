-- Enum values land in their own migration: Postgres cannot use a value added by
-- ALTER TYPE ... ADD VALUE inside the same transaction that adds it.

-- Share links gain a COMMENT capability. Column default stays VIEW so every existing
-- link keeps its view-only behaviour until the owner opts in.
DO $$ BEGIN
  ALTER TYPE "PresentationShareAccess" ADD VALUE IF NOT EXISTS 'COMMENT';
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'PRESENTATION_COMMENT_ADDED';
ALTER TYPE "InboxNotificationType" ADD VALUE IF NOT EXISTS 'PRESENTATION_COMMENT_MENTION';
