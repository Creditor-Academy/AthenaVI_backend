function formatBytes(bytes) {
  if (bytes == null) {
    return 'n/a';
  }

  const gb = (bytes / 1024 ** 3).toFixed(2);
  return `${Number(bytes).toLocaleString('en-US')} bytes (${gb} GB)`;
}

function formatTier(tierLabel, tierId) {
  if (!tierLabel && !tierId) {
    return 'n/a';
  }

  if (tierLabel && tierId) {
    return `${tierLabel} (${tierId})`;
  }

  return tierLabel || tierId;
}

function buildStorageUpgradeRequestEmail({
  userName,
  userEmail,
  userId,
  requestedAdditionalGb,
  requestedAdditionalBytes,
  urgency,
  reason,
  currentUsedBytes,
  currentLimitBytes,
  tierId,
  tierLabel,
  workspaceId,
  workspaceName,
  workspaceFootprintBytes,
  submittedAt,
  requestId,
}) {
  const workspaceSection =
    workspaceId || workspaceName || workspaceFootprintBytes != null
      ? `Workspace context (if any)
  Name: ${workspaceName || 'n/a'}
  ID:   ${workspaceId || 'n/a'}
  Footprint: ${formatBytes(workspaceFootprintBytes)}`
      : 'Workspace context: none';

  const text = `Storage upgrade request

User
  Name:   ${userName || 'n/a'}
  Email:  ${userEmail}
  User ID: ${userId}

Request
  Additional storage: ${requestedAdditionalGb} GB (${requestedAdditionalBytes} bytes)
  Urgency: ${urgency}  (flexible | week | urgent)
  Reason:
  ${reason}

Current quota (at time of request)
  Used:   ${formatBytes(currentUsedBytes)}
  Limit:  ${formatBytes(currentLimitBytes)}
  Tier:   ${formatTier(tierLabel, tierId)}

${workspaceSection}

Submitted: ${submittedAt}
Request ID: ${requestId}`;

  const subject = `[AthenaVI] Storage upgrade request — ${userEmail} — +${requestedAdditionalGb} GB`;

  return { subject, text };
}

module.exports = {
  buildStorageUpgradeRequestEmail,
  formatBytes,
};
