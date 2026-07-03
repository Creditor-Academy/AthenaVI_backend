const {
  brandName,
  escapeHtml,
  wrapEmailHtml,
  infoPanel,
  dataTable,
  formatSubmittedAt,
  sectionHeading,
  BRAND,
} = require('./emailLayout');

function formatGb(bytes) {
  if (bytes == null) {
    return 'n/a';
  }

  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

function formatTier(tierLabel, tierId) {
  if (tierLabel) {
    return tierLabel;
  }

  if (tierId) {
    return tierId;
  }

  return 'Not specified';
}

function formatUrgency(urgency) {
  const labels = {
    flexible: 'No rush',
    week: 'Needed within a week',
    urgent: 'Urgent',
  };

  return labels[urgency] || urgency;
}

function buildStorageUpgradeRequestEmail({
  userName,
  userEmail,
  requestedAdditionalGb,
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
  const displayName = userName?.trim() || userEmail;
  const planName = formatTier(tierLabel, tierId);
  const urgencyLabel = formatUrgency(urgency);
  const submittedLabel = formatSubmittedAt(submittedAt);
  const hasWorkspace = workspaceId || workspaceName || workspaceFootprintBytes != null;

  const workspaceText = hasWorkspace
    ? `Workspace: ${workspaceName || 'Unnamed workspace'} (${formatGb(workspaceFootprintBytes)} used in this workspace)`
    : 'Workspace: Not specified';

  const text = `Storage upgrade request

From: ${displayName} (${userEmail})

Requested: +${requestedAdditionalGb} GB additional storage
Priority: ${urgencyLabel}

Reason:
${reason}

Current usage: ${formatGb(currentUsedBytes)} used of ${formatGb(currentLimitBytes)} total
Current plan: ${planName}
${workspaceText}

Submitted: ${submittedLabel}
Reference: ${requestId}`;

  const subject = `[${brandName()}] Storage upgrade request — ${userEmail} — +${requestedAdditionalGb} GB`;

  const rows = [
    {
      label: 'From',
      valueHtml: `<strong>${escapeHtml(displayName)}</strong><br />
        <a href="mailto:${escapeHtml(userEmail)}" style="color:${BRAND.accent};text-decoration:none;">${escapeHtml(userEmail)}</a>`,
    },
    {
      label: 'Requested',
      valueHtml: `<strong style="font-size:18px;">+${escapeHtml(String(requestedAdditionalGb))} GB</strong>`,
    },
    { label: 'Priority', valueHtml: escapeHtml(urgencyLabel) },
    {
      label: 'Current usage',
      valueHtml: `${escapeHtml(formatGb(currentUsedBytes))} used of ${escapeHtml(formatGb(currentLimitBytes))}`,
    },
    { label: 'Current plan', valueHtml: escapeHtml(planName) },
  ];

  if (hasWorkspace) {
    rows.push({
      label: 'Workspace',
      valueHtml: `<strong>${escapeHtml(workspaceName || 'Unnamed workspace')}</strong><br />
        <span style="color:${BRAND.textMuted};">${escapeHtml(formatGb(workspaceFootprintBytes))} used in this workspace</span>`,
    });
  }

  rows.push({
    label: 'Submitted',
    valueHtml: escapeHtml(submittedLabel),
  });

  const bodyHtml = `
    ${sectionHeading('Request details', { align: 'left' })}
    ${dataTable(rows)}
    ${infoPanel({
      title: 'Reason',
      contentHtml: `<p style="margin:0;color:${BRAND.textPrimary};font-size:15px;line-height:1.6;white-space:pre-wrap;">${escapeHtml(reason)}</p>`,
    })}
    <p style="margin:0;color:${BRAND.textLight};font-size:11px;text-align:left;">
      Reference: ${escapeHtml(requestId)}
    </p>`;

  const html = wrapEmailHtml({
    preheader: `${userEmail} requested +${requestedAdditionalGb} GB storage (${urgencyLabel})`,
    title: 'Storage upgrade request',
    bodyHtml,
    variant: 'admin',
  });

  return { subject, text, html };
}

module.exports = {
  buildStorageUpgradeRequestEmail,
};
