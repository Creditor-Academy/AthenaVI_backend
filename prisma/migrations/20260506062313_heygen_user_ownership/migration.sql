-- CreateTable
CREATE TABLE "heygen_avatars" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "avatar_group_id" TEXT NOT NULL,
    "avatar_id" TEXT,
    "name" TEXT,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'processing',
    "raw" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "heygen_avatars_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "heygen_voices" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "voice_id" TEXT NOT NULL,
    "name" TEXT,
    "source" TEXT NOT NULL,
    "language" TEXT,
    "raw" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "heygen_voices_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "heygen_avatars_user_id_idx" ON "heygen_avatars"("user_id");

-- CreateIndex
CREATE INDEX "heygen_avatars_avatar_group_id_idx" ON "heygen_avatars"("avatar_group_id");

-- CreateIndex
CREATE UNIQUE INDEX "heygen_avatars_user_id_avatar_group_id_key" ON "heygen_avatars"("user_id", "avatar_group_id");

-- CreateIndex
CREATE UNIQUE INDEX "heygen_voices_voice_id_key" ON "heygen_voices"("voice_id");

-- CreateIndex
CREATE INDEX "heygen_voices_user_id_idx" ON "heygen_voices"("user_id");

-- AddForeignKey
ALTER TABLE "heygen_avatars" ADD CONSTRAINT "heygen_avatars_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "heygen_voices" ADD CONSTRAINT "heygen_voices_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
