const {
  escapeHtml,
  brandName,
  frontendUrl,
  exploreUrl,
  wrapEmailHtml,
  infoPanel,
  dataTable,
  primaryButton,
  secondaryLink,
  formatSubmittedAt,
  firstName,
  sectionHeading,
  bulletList,
  whyChooseUsSection,
  whyChooseUsText,
  sectionDivider,
  BRAND,
} = require('./emailLayout');

function formatOptionalLine(label, value) {
  if (!value) {
    return `${label}: —`;
  }
  return `${label}: ${value}`;
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
Source     : ${brandName()} Early Access Form`;

  const subject = `Early Access Request - ${name}`;

  const bodyHtml = `
    ${sectionHeading('New request details')}
    ${dataTable([
      { label: 'Name', valueHtml: `<strong>${escapeHtml(name)}</strong>` },
      {
        label: 'Email',
        valueHtml: `<a href="mailto:${escapeHtml(email)}" style="color:${BRAND.accent};text-decoration:none;">${escapeHtml(email)}</a>`,
      },
      { label: 'Company', valueHtml: escapeHtml(company || '—') },
      { label: 'Role', valueHtml: escapeHtml(role || '—') },
      { label: 'Use Case', valueHtml: escapeHtml(useCase || '—') },
    ])}
    ${infoPanel({
      title: 'Message',
      contentHtml: `<p style="margin:0;color:${BRAND.textPrimary};font-size:15px;line-height:1.6;white-space:pre-wrap;">${escapeHtml(message || '—')}</p>`,
    })}
    <p style="margin:0;color:${BRAND.textLight};font-size:11px;line-height:1.6;text-align:center;">
      Request ID: ${escapeHtml(requestId)} &bull; Submitted: ${escapeHtml(submittedLabel)}
    </p>`;

  const html = wrapEmailHtml({
    preheader: `New early access request from ${name} (${email})`,
    title: 'New Early Access Request',
    bodyHtml,
    variant: 'admin',
  });

  return { subject, text, html };
}

function buildEarlyAccessConfirmationEmail({ name, email, company, role, useCase }) {
  const greetingName = firstName(name);
  const home = frontendUrl();
  const explore = exploreUrl();

  const text = `Hello, ${greetingName}!

Your request is in good hands

We've received your request and our team will personally review your details.
You'll hear back from us at ${email} within 1-3 business days.

${whyChooseUsText()}

What you submitted:
  ${formatOptionalLine('Company', company)}
  ${formatOptionalLine('Role', role)}
  ${formatOptionalLine('Use Case', useCase)}

  • Personal review — our team reads every early access request.
  • Priority onboarding — approved members get guided setup and support.
  • Full platform access — AI avatars, workspaces, and studio-quality renders.

Open Virtual Studio: ${home}
Explore products: ${explore}

The ${brandName()} Team`;

  const subject = `You're on the ${brandName()} early access list`;

  const bodyHtml = `
    ${sectionHeading('Your request is in good hands', { align: 'left' })}
    <p style="margin:0 0 24px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
      We&rsquo;ve received your request and our team will personally review your details.
      You&rsquo;ll hear back from us at <strong>${escapeHtml(email)}</strong> within 1&ndash;3 business days.
    </p>
    ${whyChooseUsSection({ leading: true, equalHeight: true, cardHeight: 260 })}
    ${sectionDivider()}
    ${infoPanel({
      title: 'What you submitted',
      contentHtml: `
        <p style="margin:0 0 6px;color:${BRAND.textPrimary};font-size:14px;">Company: ${escapeHtml(company || '—')}</p>
        <p style="margin:0 0 6px;color:${BRAND.textPrimary};font-size:14px;">Role: ${escapeHtml(role || '—')}</p>
        <p style="margin:0;color:${BRAND.textPrimary};font-size:14px;">Use Case: ${escapeHtml(useCase || '—')}</p>`,
    })}
    ${bulletList([
      '<strong>Personal review</strong> &mdash; our team reads every early access request.',
      '<strong>Priority onboarding</strong> &mdash; approved members get guided setup and support.',
      '<strong>Full platform access</strong> &mdash; AI avatars, workspaces, and studio-quality renders.',
    ])}
    <p style="margin:16px 0 0;color:${BRAND.textMuted};font-size:14px;text-align:left;">
      Ready to explore? We&rsquo;d love to show you around.
    </p>
    ${primaryButton({ href: home, label: `Open ${brandName()}`, fullWidth: true })}
    ${secondaryLink({ href: explore, label: 'Explore products & use cases' })}`;

  const html = wrapEmailHtml({
    preheader: `We received your early access request and will reply within 1-3 business days.`,
    heroGreeting: `Hello, ${escapeHtml(greetingName)}!`,
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
  });

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
