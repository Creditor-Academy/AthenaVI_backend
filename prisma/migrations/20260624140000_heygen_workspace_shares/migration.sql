CREATE TABLE "heygen_workspace_shares" (
    "id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "shared_by_user_id" TEXT NOT NULL,
    "resource_type" TEXT NOT NULL,
    "avatar_group_id" TEXT,
    "voice_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "heygen_workspace_shares_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "heygen_workspace_shares_workspace_id_resource_type_avatar_group_id_key"
ON "heygen_workspace_shares"("workspace_id", "resource_type", "avatar_group_id");

CREATE UNIQUE INDEX "heygen_workspace_shares_workspace_id_resource_type_voice_id_key"
ON "heygen_workspace_shares"("workspace_id", "resource_type", "voice_id");

CREATE INDEX "heygen_workspace_shares_workspace_id_idx" ON "heygen_workspace_shares"("workspace_id");
CREATE INDEX "heygen_workspace_shares_avatar_group_id_idx" ON "heygen_workspace_shares"("avatar_group_id");
CREATE INDEX "heygen_workspace_shares_voice_id_idx" ON "heygen_workspace_shares"("voice_id");

ALTER TABLE "heygen_workspace_shares"
ADD CONSTRAINT "heygen_workspace_shares_workspace_id_fkey"
FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id")
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "heygen_workspace_shares"
ADD CONSTRAINT "heygen_workspace_shares_shared_by_user_id_fkey"
FOREIGN KEY ("shared_by_user_id") REFERENCES "users"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
