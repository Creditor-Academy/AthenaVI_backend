-- CreateTable
CREATE TABLE "SpeechGeneration" (
    "id" TEXT NOT NULL,
    "workspaceId" TEXT NOT NULL,
    "folderId" TEXT,
    "projectId" TEXT NOT NULL,
    "sceneId" TEXT NOT NULL DEFAULT '',
    "voiceId" TEXT NOT NULL,
    "script" TEXT NOT NULL,
    "inputType" TEXT NOT NULL DEFAULT 'text',
    "speed" DOUBLE PRECISION NOT NULL DEFAULT 1,
    "locale" TEXT,
    "language" TEXT,
    "heygenAudioUrl" TEXT,
    "audioUrl" TEXT NOT NULL DEFAULT '',
    "s3Key" TEXT,
    "fileSizeBytes" INTEGER,
    "durationSec" DOUBLE PRECISION,
    "wordTimestamps" JSONB,
    "requestHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'completed',
    "rawResponse" JSONB,
    "triggered_by_user_id" TEXT,
    "credits_charged" INTEGER,
    "billed_duration_sec" DOUBLE PRECISION,
    "billing_status" TEXT NOT NULL DEFAULT 'pending',
    "billing_context" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SpeechGeneration_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "SpeechGeneration_requestHash_key" ON "SpeechGeneration"("requestHash");

-- CreateIndex
CREATE INDEX "SpeechGeneration_projectId_workspaceId_idx" ON "SpeechGeneration"("projectId", "workspaceId");

-- AddForeignKey
ALTER TABLE "SpeechGeneration" ADD CONSTRAINT "SpeechGeneration_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "workspaces"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SpeechGeneration" ADD CONSTRAINT "SpeechGeneration_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;
