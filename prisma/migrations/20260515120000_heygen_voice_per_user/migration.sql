-- Drop global unique on voice_id; each user may save the same HeyGen public voice id.
DROP INDEX IF EXISTS "heygen_voices_voice_id_key";

CREATE UNIQUE INDEX "heygen_voices_user_id_voice_id_key" ON "heygen_voices"("user_id", "voice_id");

CREATE INDEX "heygen_voices_voice_id_idx" ON "heygen_voices"("voice_id");
