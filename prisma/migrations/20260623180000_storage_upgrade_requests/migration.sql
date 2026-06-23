-- Storage upgrade requests (user-submitted; superadmin review)
CREATE TYPE "StorageUpgradeRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

CREATE TABLE "storage_upgrade_requests" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "requested_additional_gb" INTEGER NOT NULL,
    "requested_additional_bytes" INTEGER NOT NULL,
    "reason" TEXT NOT NULL,
    "urgency" TEXT NOT NULL,
    "current_used_bytes" INTEGER NOT NULL,
    "current_limit_bytes" INTEGER NOT NULL,
    "tier_id" TEXT,
    "tier_label" TEXT,
    "workspace_id" TEXT,
    "workspace_name" TEXT,
    "workspace_footprint_bytes" INTEGER,
    "status" "StorageUpgradeRequestStatus" NOT NULL DEFAULT 'PENDING',
    "reviewed_at" TIMESTAMP(3),
    "reviewed_by_user_id" TEXT,
    "review_note" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "storage_upgrade_requests_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "storage_upgrade_requests_user_id_created_at_idx" ON "storage_upgrade_requests"("user_id", "created_at");
CREATE INDEX "storage_upgrade_requests_user_id_status_idx" ON "storage_upgrade_requests"("user_id", "status");

ALTER TABLE "storage_upgrade_requests"
ADD CONSTRAINT "storage_upgrade_requests_user_id_fkey"
FOREIGN KEY ("user_id") REFERENCES "users"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
