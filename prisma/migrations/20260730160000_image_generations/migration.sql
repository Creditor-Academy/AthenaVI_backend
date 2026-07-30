-- CreateTable
CREATE TABLE IF NOT EXISTS "image_generations" (
    "id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "model_id" TEXT NOT NULL,
    "format_id" TEXT,
    "style_id" TEXT,
    "prompt" TEXT NOT NULL,
    "revised_prompt" TEXT,
    "request" JSONB,
    "parent_id" TEXT,
    "root_id" TEXT,
    "action" TEXT NOT NULL,
    "asset_id" TEXT,
    "s3_key" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "openai_size" TEXT,
    "export_width" INTEGER,
    "export_height" INTEGER,
    "credits_charged" INTEGER NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL DEFAULT 'SUCCEEDED',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "image_generations_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "image_generations_workspace_id_created_at_idx" ON "image_generations"("workspace_id", "created_at");
CREATE INDEX IF NOT EXISTS "image_generations_workspace_id_user_id_idx" ON "image_generations"("workspace_id", "user_id");
CREATE INDEX IF NOT EXISTS "image_generations_root_id_idx" ON "image_generations"("root_id");
CREATE INDEX IF NOT EXISTS "image_generations_asset_id_idx" ON "image_generations"("asset_id");

ALTER TABLE "image_generations" ADD CONSTRAINT "image_generations_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "image_generations" ADD CONSTRAINT "image_generations_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "image_generations" ADD CONSTRAINT "image_generations_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "Asset"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "image_generations" ADD CONSTRAINT "image_generations_parent_id_fkey" FOREIGN KEY ("parent_id") REFERENCES "image_generations"("id") ON DELETE SET NULL ON UPDATE CASCADE;
