-- CreateEnum (Postgres <15 compatible)
DO $$ BEGIN
  CREATE TYPE "PresentationShareAccess" AS ENUM ('VIEW');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- CreateTable presentation_share_links
CREATE TABLE IF NOT EXISTS "presentation_share_links" (
    "id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "token_prefix" TEXT NOT NULL,
    "access" "PresentationShareAccess" NOT NULL DEFAULT 'VIEW',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "expires_at" TIMESTAMP(3),
    "created_by" TEXT,
    "revoked_at" TIMESTAMP(3),
    "rotate_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "presentation_share_links_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "presentation_share_links_project_id_key" ON "presentation_share_links"("project_id");
CREATE UNIQUE INDEX IF NOT EXISTS "presentation_share_links_token_hash_key" ON "presentation_share_links"("token_hash");
CREATE INDEX IF NOT EXISTS "presentation_share_links_workspace_id_idx" ON "presentation_share_links"("workspace_id");
CREATE INDEX IF NOT EXISTS "presentation_share_links_created_by_idx" ON "presentation_share_links"("created_by");

-- CreateTable presentation_share_audits
CREATE TABLE IF NOT EXISTS "presentation_share_audits" (
    "id" TEXT NOT NULL,
    "share_id" TEXT NOT NULL,
    "actor_user_id" TEXT,
    "action" TEXT NOT NULL,
    "ip" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "presentation_share_audits_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "presentation_share_audits_share_id_created_at_idx" ON "presentation_share_audits"("share_id", "created_at");
CREATE INDEX IF NOT EXISTS "presentation_share_audits_actor_user_id_idx" ON "presentation_share_audits"("actor_user_id");

-- AddForeignKey
DO $$ BEGIN
  ALTER TABLE "presentation_share_links" ADD CONSTRAINT "presentation_share_links_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "presentation_share_links" ADD CONSTRAINT "presentation_share_links_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "presentation_share_links" ADD CONSTRAINT "presentation_share_links_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "presentation_share_audits" ADD CONSTRAINT "presentation_share_audits_share_id_fkey" FOREIGN KEY ("share_id") REFERENCES "presentation_share_links"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE "presentation_share_audits" ADD CONSTRAINT "presentation_share_audits_actor_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
