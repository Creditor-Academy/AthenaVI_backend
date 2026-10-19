-- CreateTable
CREATE TABLE "image_gen_contexts" (
    "id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'READY',
    "inline_text" TEXT,
    "derived" JSONB NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "pinned_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "image_gen_contexts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "image_gen_context_files" (
    "id" TEXT NOT NULL,
    "context_id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "asset_id" TEXT,
    "name" TEXT NOT NULL,
    "mime_type" TEXT NOT NULL,
    "s3_key" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "extracted_text" TEXT,
    "image_summary" TEXT,

    CONSTRAINT "image_gen_context_files_pkey" PRIMARY KEY ("id")
);

-- AlterTable
ALTER TABLE "image_generations" ADD COLUMN "context_id" TEXT;

-- CreateIndex
CREATE INDEX "image_gen_contexts_workspace_id_created_at_idx" ON "image_gen_contexts"("workspace_id", "created_at");

-- CreateIndex
CREATE INDEX "image_gen_contexts_workspace_id_user_id_idx" ON "image_gen_contexts"("workspace_id", "user_id");

-- CreateIndex
CREATE INDEX "image_gen_contexts_expires_at_idx" ON "image_gen_contexts"("expires_at");

-- CreateIndex
CREATE INDEX "image_gen_context_files_context_id_idx" ON "image_gen_context_files"("context_id");

-- CreateIndex
CREATE INDEX "image_generations_context_id_idx" ON "image_generations"("context_id");

-- AddForeignKey
ALTER TABLE "image_gen_contexts" ADD CONSTRAINT "image_gen_contexts_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "image_gen_contexts" ADD CONSTRAINT "image_gen_contexts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "image_gen_context_files" ADD CONSTRAINT "image_gen_context_files_context_id_fkey" FOREIGN KEY ("context_id") REFERENCES "image_gen_contexts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "image_generations" ADD CONSTRAINT "image_generations_context_id_fkey" FOREIGN KEY ("context_id") REFERENCES "image_gen_contexts"("id") ON DELETE SET NULL ON UPDATE CASCADE;
