-- Early access requests (public form submissions; superadmin review)
CREATE TYPE "EarlyAccessRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

CREATE TABLE "early_access_requests" (
    "id" VARCHAR(20) NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "email" VARCHAR(254) NOT NULL,
    "company" VARCHAR(150),
    "role" VARCHAR(100),
    "use_case" VARCHAR(100),
    "message" TEXT,
    "status" "EarlyAccessRequestStatus" NOT NULL DEFAULT 'PENDING',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reviewed_at" TIMESTAMP(3),
    "reviewer_id" VARCHAR(50),

    CONSTRAINT "early_access_requests_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "early_access_requests_email_key" ON "early_access_requests"("email");
CREATE INDEX "early_access_requests_status_created_at_idx" ON "early_access_requests"("status", "created_at");

ALTER TYPE "InboxNotificationType" ADD VALUE 'PLATFORM_EARLY_ACCESS_REQUEST';
