-- CreateEnum
CREATE TYPE "RenderJobStatus" AS ENUM ('PENDING', 'RENDERING', 'COMPLETED', 'FAILED');

-- CreateTable
CREATE TABLE "render_jobs" (
    "id" TEXT NOT NULL,
    "video_id" TEXT NOT NULL,
    "workspace_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "status" "RenderJobStatus" NOT NULL DEFAULT 'PENDING',
    "output_url" TEXT,
    "error" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "render_jobs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "render_jobs_video_id_idx" ON "render_jobs"("video_id");

-- CreateIndex
CREATE INDEX "render_jobs_workspace_id_idx" ON "render_jobs"("workspace_id");

-- CreateIndex
CREATE INDEX "render_jobs_status_idx" ON "render_jobs"("status");
