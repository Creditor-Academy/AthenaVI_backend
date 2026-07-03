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

module.exports = {
  buildEarlyAccessSuperadminNotificationEmail,
  buildEarlyAccessConfirmationEmail,
};
