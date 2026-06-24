-- Widen byte-count columns to BIGINT so storage quotas can exceed 2 GiB (32-bit INTEGER max).

ALTER TABLE "users"
  ALTER COLUMN "storageLimit" SET DATA TYPE BIGINT,
  ALTER COLUMN "storageUsed" SET DATA TYPE BIGINT;

ALTER TABLE "storage_transactions"
  ALTER COLUMN "amount_bytes" SET DATA TYPE BIGINT;

ALTER TABLE "storage_upgrade_requests"
  ALTER COLUMN "requested_additional_bytes" SET DATA TYPE BIGINT,
  ALTER COLUMN "current_used_bytes" SET DATA TYPE BIGINT,
  ALTER COLUMN "current_limit_bytes" SET DATA TYPE BIGINT,
  ALTER COLUMN "workspace_footprint_bytes" SET DATA TYPE BIGINT;

ALTER TABLE "Project"
  ALTER COLUMN "storageBytes" SET DATA TYPE BIGINT;

ALTER TABLE "Asset"
  ALTER COLUMN "size" SET DATA TYPE BIGINT;

ALTER TABLE "HeygenResponse"
  ALTER COLUMN "fileSizeBytes" SET DATA TYPE BIGINT;

ALTER TABLE "SpeechGeneration"
  ALTER COLUMN "fileSizeBytes" SET DATA TYPE BIGINT;

ALTER TABLE "project_renders"
  ALTER COLUMN "fileSizeBytes" SET DATA TYPE BIGINT;

ALTER TABLE "scene_render_caches"
  ALTER COLUMN "fileSizeBytes" SET DATA TYPE BIGINT;
