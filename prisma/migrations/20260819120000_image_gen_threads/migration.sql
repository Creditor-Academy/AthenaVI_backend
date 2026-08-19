ALTER TABLE "image_generations" ADD COLUMN IF NOT EXISTS "thread_id" TEXT;

CREATE TABLE IF NOT EXISTS "image_gen_threads" (
    "id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "folder_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "root_generation_id" TEXT NOT NULL,
    "head_generation_id" TEXT NOT NULL,
    "context_id" TEXT,
    "model_id" TEXT,
    "format_id" TEXT,
    "style_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "image_gen_threads_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "image_gen_threads_root_generation_id_key" ON "image_gen_threads"("root_generation_id");
CREATE INDEX IF NOT EXISTS "image_gen_threads_workspace_id_folder_id_updated_at_idx" ON "image_gen_threads"("workspace_id", "folder_id", "updated_at");
CREATE INDEX IF NOT EXISTS "image_gen_threads_workspace_id_user_id_idx" ON "image_gen_threads"("workspace_id", "user_id");
CREATE INDEX IF NOT EXISTS "image_gen_threads_folder_id_idx" ON "image_gen_threads"("folder_id");
CREATE INDEX IF NOT EXISTS "image_gen_threads_head_generation_id_idx" ON "image_gen_threads"("head_generation_id");
CREATE INDEX IF NOT EXISTS "image_gen_threads_context_id_idx" ON "image_gen_threads"("context_id");
CREATE INDEX IF NOT EXISTS "image_generations_thread_id_idx" ON "image_generations"("thread_id");

CREATE TABLE IF NOT EXISTS "image_gen_messages" (
    "id" TEXT NOT NULL,
    "thread_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "generation_id" TEXT,
    "credits_charged" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "image_gen_messages_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "image_gen_messages_thread_id_created_at_idx" ON "image_gen_messages"("thread_id", "created_at");
CREATE INDEX IF NOT EXISTS "image_gen_messages_generation_id_idx" ON "image_gen_messages"("generation_id");

ALTER TABLE "image_gen_threads" ADD CONSTRAINT "image_gen_threads_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "image_gen_threads" ADD CONSTRAINT "image_gen_threads_folder_id_fkey" FOREIGN KEY ("folder_id") REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "image_gen_threads" ADD CONSTRAINT "image_gen_threads_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "image_gen_threads" ADD CONSTRAINT "image_gen_threads_context_id_fkey" FOREIGN KEY ("context_id") REFERENCES "image_gen_contexts"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "image_gen_threads" ADD CONSTRAINT "image_gen_threads_root_generation_id_fkey" FOREIGN KEY ("root_generation_id") REFERENCES "image_generations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "image_gen_threads" ADD CONSTRAINT "image_gen_threads_head_generation_id_fkey" FOREIGN KEY ("head_generation_id") REFERENCES "image_generations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "image_generations" ADD CONSTRAINT "image_generations_thread_id_fkey" FOREIGN KEY ("thread_id") REFERENCES "image_gen_threads"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "image_gen_messages" ADD CONSTRAINT "image_gen_messages_thread_id_fkey" FOREIGN KEY ("thread_id") REFERENCES "image_gen_threads"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "image_gen_messages" ADD CONSTRAINT "image_gen_messages_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "image_gen_messages" ADD CONSTRAINT "image_gen_messages_generation_id_fkey" FOREIGN KEY ("generation_id") REFERENCES "image_generations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Backfill: one thread per generation chain, placed in an existing folder or a new "Images" folder.
DO $$
DECLARE
  chain RECORD;
  hop RECORD;
  target_folder_id TEXT;
  workspace_owner_id TEXT;
  new_thread_id TEXT;
  title_text TEXT;
  is_first BOOLEAN;
  hop_user_type TEXT;
  hop_user_content TEXT;
  hop_ts TIMESTAMP(3);
BEGIN
  FOR chain IN
    SELECT
      COALESCE(g.root_id, g.id) AS chain_root,
      MIN(g.created_at) AS first_at,
      MAX(g.created_at) AS last_at,
      (ARRAY_AGG(g.workspace_id ORDER BY g.created_at ASC))[1] AS workspace_id,
      (ARRAY_AGG(g.user_id ORDER BY g.created_at ASC))[1] AS user_id,
      (ARRAY_AGG(g.prompt ORDER BY g.created_at ASC))[1] AS prompt,
      (ARRAY_AGG(g.model_id ORDER BY g.created_at ASC))[1] AS model_id,
      (ARRAY_AGG(g.format_id ORDER BY g.created_at ASC))[1] AS format_id,
      (ARRAY_AGG(g.style_id ORDER BY g.created_at ASC))[1] AS style_id,
      (ARRAY_AGG(g.context_id ORDER BY g.created_at ASC))[1] AS context_id,
      (ARRAY_AGG(g.id ORDER BY g.created_at ASC))[1] AS first_id,
      (ARRAY_AGG(g.id ORDER BY g.created_at DESC))[1] AS head_id
    FROM image_generations g
    WHERE g.thread_id IS NULL
    GROUP BY COALESCE(g.root_id, g.id)
  LOOP
    SELECT f.id INTO target_folder_id
    FROM "Folder" f
    WHERE f."workspaceId" = chain.workspace_id
    ORDER BY f."createdAt" ASC
    LIMIT 1;

    IF target_folder_id IS NULL THEN
      SELECT w."owner_id" INTO workspace_owner_id FROM workspaces w WHERE w.id = chain.workspace_id;
      target_folder_id := gen_random_uuid()::text;
      INSERT INTO "Folder" ("id", "name", "workspaceId", "createdBy", "createdAt", "updatedAt", "updatedBy")
      VALUES (target_folder_id, 'Images', chain.workspace_id, COALESCE(workspace_owner_id, chain.user_id), NOW(), NOW(), COALESCE(workspace_owner_id, chain.user_id));
    END IF;

    title_text := TRIM(COALESCE(chain.prompt, ''));
    IF title_text = '' THEN
      title_text := 'Untitled image';
    ELSIF length(title_text) > 80 THEN
      title_text := left(title_text, 79) || '…';
    END IF;

    new_thread_id := gen_random_uuid()::text;
    INSERT INTO image_gen_threads (
      id, workspace_id, folder_id, user_id, title,
      root_generation_id, head_generation_id, context_id,
      model_id, format_id, style_id, created_at, updated_at
    ) VALUES (
      new_thread_id, chain.workspace_id, target_folder_id, chain.user_id, title_text,
      chain.first_id, chain.head_id, chain.context_id,
      chain.model_id, chain.format_id, chain.style_id, chain.first_at, chain.last_at
    );

    UPDATE image_generations AS ig
    SET thread_id = new_thread_id
    WHERE COALESCE(ig.root_id, ig.id) = chain.chain_root;

    is_first := TRUE;
    hop_ts := chain.first_at;
    FOR hop IN
      SELECT *
      FROM image_generations AS ig
      WHERE COALESCE(ig.root_id, ig.id) = chain.chain_root
      ORDER BY ig.created_at ASC
    LOOP
      IF is_first THEN
        hop_user_type := 'prompt';
        hop_user_content := COALESCE(hop.prompt, '');
        is_first := FALSE;
      ELSIF hop.action = 'regenerate' THEN
        hop_user_type := 'regenerate';
        hop_user_content := COALESCE(hop.prompt, 'Regenerate');
      ELSE
        hop_user_type := 'tweak';
        hop_user_content := COALESCE(hop.request->>'tweakInstruction', hop.prompt, 'Tweak');
      END IF;

      INSERT INTO image_gen_messages (
        id, thread_id, user_id, role, type, content, generation_id, credits_charged, created_at
      ) VALUES (
        gen_random_uuid()::text, new_thread_id, hop.user_id, 'user', hop_user_type, hop_user_content, NULL, 0, hop.created_at
      );

      hop_ts := hop.created_at + INTERVAL '1 millisecond';
      INSERT INTO image_gen_messages (
        id, thread_id, user_id, role, type, content, generation_id, credits_charged, created_at
      ) VALUES (
        gen_random_uuid()::text, new_thread_id, hop.user_id, 'assistant', hop_user_type, '', hop.id, hop.credits_charged, hop_ts
      );
    END LOOP;
  END LOOP;
END $$;
