function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

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

function formatSubmittedAt(isoString) {
  try {
    return new Date(isoString).toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  } catch {
    return isoString;
  }
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

  const subject = `[AthenaVI] Storage upgrade request — ${userEmail} — +${requestedAdditionalGb} GB`;

  const workspaceHtml = hasWorkspace
    ? `<tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Workspace</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">
            <strong>${escapeHtml(workspaceName || 'Unnamed workspace')}</strong><br />
            <span style="color:#4a5568;">${escapeHtml(formatGb(workspaceFootprintBytes))} used in this workspace</span>
          </td>
        </tr>`
    : '';

  const html = `
  <div style="background-color:#f4f6f8;padding:32px 16px;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:10px;padding:32px 28px;box-shadow:0 4px 12px rgba(0,0,0,0.08);">

      <p style="margin:0 0 8px;color:#2563eb;font-size:12px;font-weight:bold;letter-spacing:0.04em;text-transform:uppercase;">
        AthenaVI · Admin notification
      </p>
      <h2 style="color:#2d3748;margin:0 0 20px;font-size:22px;">
        Storage upgrade request
      </h2>

      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:20px;">
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;width:120px;">From</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">
            <strong>${escapeHtml(displayName)}</strong><br />
            <a href="mailto:${escapeHtml(userEmail)}" style="color:#2563eb;text-decoration:none;">${escapeHtml(userEmail)}</a>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Requested</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">
            <strong style="font-size:18px;">+${requestedAdditionalGb} GB</strong>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Priority</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">${escapeHtml(urgencyLabel)}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Current usage</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">
            ${escapeHtml(formatGb(currentUsedBytes))} used of ${escapeHtml(formatGb(currentLimitBytes))}
          </td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Current plan</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">${escapeHtml(planName)}</td>
        </tr>
        ${workspaceHtml}
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Submitted</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">${escapeHtml(submittedLabel)}</td>
        </tr>
      </table>

      <div style="background:#f7fafc;border-left:4px solid #2563eb;border-radius:6px;padding:16px 18px;margin-bottom:24px;">
        <p style="margin:0 0 8px;color:#718096;font-size:12px;font-weight:bold;text-transform:uppercase;letter-spacing:0.03em;">
          Reason
        </p>
        <p style="margin:0;color:#2d3748;font-size:15px;line-height:1.5;white-space:pre-wrap;">${escapeHtml(reason)}</p>
      </div>

      <p style="margin:0;color:#a0aec0;font-size:11px;">
        Reference: ${escapeHtml(requestId)}
      </p>
    </div>
  </div>`;

  return { subject, text, html };
}

module.exports = {
  buildStorageUpgradeRequestEmail,
};
