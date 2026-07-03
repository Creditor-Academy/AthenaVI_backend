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
  disclaimerText,
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

function getStatusEmailCopy(dbStatus) {
  const brand = brandName();
  const copies = {
    PENDING: {
      subject: `Your ${brand} early access request is pending`,
      headline: 'Request received',
      body: `Thanks for your interest in ${brand}. Your early access request is pending and queued for our team.`,
    },
    UNDER_REVIEW: {
      subject: `Your ${brand} early access request is under review`,
      headline: 'Under review',
      body: 'Our team has started reviewing your early access request. We will email you when the status changes again.',
    },
    IN_DISCUSSION: {
      subject: `Your ${brand} early access request is in discussion`,
      headline: 'In discussion',
      body: 'Your early access request is being discussed with our team. We may reach out if we need more details.',
    },
    APPROVED: {
      subject: `Your ${brand} early access request was approved`,
      headline: 'Approved',
      body: `Great news — your early access request has been approved. You can now sign up and start using ${brand}.`,
    },
    REJECTED: {
      subject: `Update on your ${brand} early access request`,
      headline: 'Not approved at this time',
      body: `Thank you for your interest in ${brand}. After review, we are unable to approve your early access request right now.`,
    },
  };
  return copies[dbStatus] || copies.PENDING;
}

function buildEarlyAccessStatusUpdateEmail({ name, email, requestId, status }) {
  const dbStatus = String(status).toUpperCase().replace(/-/g, '_');
  const copy = getStatusEmailCopy(dbStatus);
  const greetingName = firstName(name);
  const signupUrl = `${frontendUrl()}/register`;
  const statusLabel = dbStatus.replace(/_/g, ' ').toLowerCase();
  const brand = brandName();

  const approvedExtra =
    dbStatus === 'APPROVED' ? `\n\nSign up here: ${signupUrl}` : '';

  const text = `Hi ${greetingName},

${copy.body}

Request ID: ${requestId}
Status: ${statusLabel}
${approvedExtra}

If you have questions, reply to this email.

The ${brand} Team`;

  const approvedButton =
    dbStatus === 'APPROVED'
      ? primaryButton({ href: signupUrl, label: `Sign up to ${brand}`, fullWidth: true })
      : '';

  const bodyHtml = `
    ${sectionHeading(copy.headline, { align: 'left' })}
    <p style="margin:0 0 24px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
      ${escapeHtml(copy.body)}
    </p>
    ${infoPanel({
      title: 'Request details',
      contentHtml: `
        <p style="margin:0 0 6px;color:${BRAND.textPrimary};font-size:14px;">Request ID: ${escapeHtml(requestId)}</p>
        <p style="margin:0;color:${BRAND.textPrimary};font-size:14px;text-transform:capitalize;">Status: ${escapeHtml(statusLabel)}</p>`,
    })}
    ${approvedButton}
    ${disclaimerText('If you have questions, reply to this email.')}`;

  const html = wrapEmailHtml({
    preheader: `${copy.headline} — your early access request status has been updated.`,
    heroGreeting: `Hi ${escapeHtml(greetingName)},`,
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
  });

  return { subject: copy.subject, text, html };
}

module.exports = {
  buildEarlyAccessSuperadminNotificationEmail,
  buildEarlyAccessConfirmationEmail,
  buildEarlyAccessStatusUpdateEmail,
};
