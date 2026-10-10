-- Remove waitlist rows and table. Leave InboxNotificationType.PLATFORM_EARLY_ACCESS_REQUEST.
DELETE FROM "user_inbox_notifications"
WHERE "type" = 'PLATFORM_EARLY_ACCESS_REQUEST';

DROP TABLE "early_access_requests";
DROP TYPE "EarlyAccessRequestStatus";
