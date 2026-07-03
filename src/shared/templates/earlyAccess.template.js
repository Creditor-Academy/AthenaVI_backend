function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function firstName(name) {
  const trimmed = String(name || '').trim();
  if (!trimmed) {
    return 'there';
  }
  return trimmed.split(/\s+/)[0];
}

function formatOptionalLine(label, value) {
  if (!value) {
    return `${label}: —`;
  }
  return `${label}: ${value}`;
}

function formatSubmittedAt(isoString) {
  try {
    return new Date(isoString).toISOString();
  } catch {
    return isoString;
  }
}

function buildEarlyAccessSuperadminNotificationEmail({
  name,
  email,
  company,
  role,
  useCase,
  message,
  requestId,
  submittedAt,
}) {
  const submittedLabel = formatSubmittedAt(submittedAt);

  const text = `New Early Access Request
========================================

Name:     ${name}
Email:    ${email}
Company:  ${company || '—'}
Role:     ${role || '—'}
Use Case: ${useCase || '—'}

Message:
${message || '—'}

========================================
Request ID : ${requestId}
Submitted  : ${submittedLabel}
Source     : AthenaVI Early Access Form`;

  const subject = `Early Access Request - ${name}`;

  const html = `
  <div style="background-color:#f4f6f8;padding:32px 16px;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:10px;padding:32px 28px;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
      <p style="margin:0 0 8px;color:#2563eb;font-size:12px;font-weight:bold;letter-spacing:0.04em;text-transform:uppercase;">
        AthenaVI · Admin notification
      </p>
      <h2 style="color:#2d3748;margin:0 0 20px;font-size:22px;">New Early Access Request</h2>
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:20px;">
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;width:100px;">Name</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;"><strong>${escapeHtml(name)}</strong></td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Email</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">
            <a href="mailto:${escapeHtml(email)}" style="color:#2563eb;text-decoration:none;">${escapeHtml(email)}</a>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Company</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">${escapeHtml(company || '—')}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Role</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">${escapeHtml(role || '—')}</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#718096;font-size:14px;vertical-align:top;">Use Case</td>
          <td style="padding:8px 0;color:#2d3748;font-size:14px;">${escapeHtml(useCase || '—')}</td>
        </tr>
      </table>
      <div style="background:#f7fafc;border-left:4px solid #2563eb;border-radius:6px;padding:16px 18px;margin-bottom:24px;">
        <p style="margin:0 0 8px;color:#718096;font-size:12px;font-weight:bold;text-transform:uppercase;letter-spacing:0.03em;">Message</p>
        <p style="margin:0;color:#2d3748;font-size:15px;line-height:1.5;white-space:pre-wrap;">${escapeHtml(message || '—')}</p>
      </div>
      <p style="margin:0 0 4px;color:#a0aec0;font-size:11px;">Request ID: ${escapeHtml(requestId)}</p>
      <p style="margin:0 0 4px;color:#a0aec0;font-size:11px;">Submitted: ${escapeHtml(submittedLabel)}</p>
      <p style="margin:0;color:#a0aec0;font-size:11px;">Source: AthenaVI Early Access Form</p>
    </div>
  </div>`;

  return { subject, text, html };
}

function buildEarlyAccessConfirmationEmail({ name, email, company, role, useCase }) {
  const greetingName = firstName(name);

  const text = `Hi ${greetingName},

Thanks for requesting early access to Athena VI!

We've received your request and our team will personally review your details.
You'll hear back from us at ${email} within 1-3 business days.

What you submitted:
  ${formatOptionalLine('Company', company)}
  ${formatOptionalLine('Role', role)}
  ${formatOptionalLine('Use Case', useCase)}

In the meantime, feel free to explore:
  https://athenavi.com/products
  https://athenavi.com/use-cases

The Athena VI Team`;

  const subject = "You're on the Athena VI early access list";

  const html = `
  <div style="background-color:#f4f6f8;padding:32px 16px;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:10px;padding:32px 28px;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
      <h2 style="color:#2d3748;margin:0 0 16px;font-size:22px;">Hi ${escapeHtml(greetingName)},</h2>
      <p style="margin:0 0 16px;color:#2d3748;font-size:15px;line-height:1.6;">
        Thanks for requesting early access to Athena VI!
      </p>
      <p style="margin:0 0 16px;color:#2d3748;font-size:15px;line-height:1.6;">
        We've received your request and our team will personally review your details.
        You'll hear back from us at <strong>${escapeHtml(email)}</strong> within 1-3 business days.
      </p>
      <div style="background:#f7fafc;border-radius:6px;padding:16px 18px;margin-bottom:20px;">
        <p style="margin:0 0 8px;color:#718096;font-size:12px;font-weight:bold;text-transform:uppercase;">What you submitted</p>
        <p style="margin:0 0 4px;color:#2d3748;font-size:14px;">Company: ${escapeHtml(company || '—')}</p>
        <p style="margin:0 0 4px;color:#2d3748;font-size:14px;">Role: ${escapeHtml(role || '—')}</p>
        <p style="margin:0;color:#2d3748;font-size:14px;">Use Case: ${escapeHtml(useCase || '—')}</p>
      </div>
      <p style="margin:0 0 8px;color:#2d3748;font-size:15px;">In the meantime, feel free to explore:</p>
      <p style="margin:0 0 4px;font-size:14px;"><a href="https://athenavi.com/products" style="color:#2563eb;">https://athenavi.com/products</a></p>
      <p style="margin:0 0 20px;font-size:14px;"><a href="https://athenavi.com/use-cases" style="color:#2563eb;">https://athenavi.com/use-cases</a></p>
      <p style="margin:0;color:#718096;font-size:14px;">The Athena VI Team</p>
    </div>
  </div>`;

  return { subject, text, html };
}

const STATUS_EMAIL_COPY = {
  PENDING: {
    subject: 'Your Athena VI early access request is pending',
    headline: 'Request received',
    body:
      'Thanks for your interest in Athena VI. Your early access request is pending and queued for our team.',
  },
  UNDER_REVIEW: {
    subject: 'Your Athena VI early access request is under review',
    headline: 'Under review',
    body:
      'Our team has started reviewing your early access request. We will email you when the status changes again.',
  },
  IN_DISCUSSION: {
    subject: 'Your Athena VI early access request is in discussion',
    headline: 'In discussion',
    body:
      'Your early access request is being discussed with our team. We may reach out if we need more details.',
  },
  APPROVED: {
    subject: 'Your Athena VI early access request was approved',
    headline: 'Approved',
    body:
      'Great news — your early access request has been approved. You can now sign up and start using Athena VI.',
  },
  REJECTED: {
    subject: 'Update on your Athena VI early access request',
    headline: 'Not approved at this time',
    body:
      'Thank you for your interest in Athena VI. After review, we are unable to approve your early access request right now.',
  },
};

function buildEarlyAccessStatusUpdateEmail({ name, email, requestId, status }) {
  const dbStatus = String(status).toUpperCase().replace(/-/g, '_');
  const copy = STATUS_EMAIL_COPY[dbStatus] || STATUS_EMAIL_COPY.PENDING;
  const greetingName = firstName(name);
  const signupUrl = process.env.FRONTEND_URL || 'https://athenavi.com';
  const statusLabel = dbStatus.replace(/_/g, ' ').toLowerCase();

  const approvedExtra =
    dbStatus === 'APPROVED'
      ? `\n\nSign up here: ${signupUrl}/register`
      : '';

  const text = `Hi ${greetingName},

${copy.body}

Request ID: ${requestId}
Status: ${statusLabel}
${approvedExtra}

If you have questions, reply to this email.

The Athena VI Team`;

  const approvedHtml =
    dbStatus === 'APPROVED'
      ? `<p style="margin:16px 0 0;">
          <a href="${escapeHtml(`${signupUrl}/register`)}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:6px;font-size:14px;font-weight:bold;">
            Sign up to Athena VI
          </a>
        </p>`
      : '';

  const html = `
  <div style="background-color:#f4f6f8;padding:32px 16px;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:10px;padding:32px 28px;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
      <p style="margin:0 0 8px;color:#2563eb;font-size:12px;font-weight:bold;letter-spacing:0.04em;text-transform:uppercase;">
        Early access · ${escapeHtml(copy.headline)}
      </p>
      <h2 style="color:#2d3748;margin:0 0 16px;font-size:22px;">Hi ${escapeHtml(greetingName)},</h2>
      <p style="margin:0 0 16px;color:#2d3748;font-size:15px;line-height:1.6;">
        ${escapeHtml(copy.body)}
      </p>
      <div style="background:#f7fafc;border-radius:6px;padding:16px 18px;margin-bottom:8px;">
        <p style="margin:0 0 4px;color:#718096;font-size:12px;font-weight:bold;text-transform:uppercase;">Request ID</p>
        <p style="margin:0 0 12px;color:#2d3748;font-size:14px;">${escapeHtml(requestId)}</p>
        <p style="margin:0 0 4px;color:#718096;font-size:12px;font-weight:bold;text-transform:uppercase;">Status</p>
        <p style="margin:0;color:#2d3748;font-size:14px;text-transform:capitalize;">${escapeHtml(statusLabel)}</p>
      </div>
      ${approvedHtml}
      <p style="margin:20px 0 0;color:#718096;font-size:14px;">The Athena VI Team</p>
    </div>
  </div>`;

  return { subject: copy.subject, text, html };
}

module.exports = {
  buildEarlyAccessSuperadminNotificationEmail,
  buildEarlyAccessConfirmationEmail,
  buildEarlyAccessStatusUpdateEmail,
};
