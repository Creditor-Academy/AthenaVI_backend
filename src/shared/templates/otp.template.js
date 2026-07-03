const {
  brandName,
  escapeHtml,
  frontendUrl,
  wrapEmailHtml,
  infoPanel,
  disclaimerText,
  primaryButton,
  sectionHeading,
  bulletList,
  whyChooseUsSection,
  whyChooseUsText,
  sectionDivider,
  BRAND,
} = require('./emailLayout');

function buildOtpEmail(otp) {
  const subject = 'Verify your email';
  const home = frontendUrl();

  const text = `Welcome to ${brandName()}!

${whyChooseUsText()}

Use the One-Time Password below to complete your verification:

${otp}

This OTP will expire in 5 minutes.

If you did not request this email, you can safely ignore it.

— ${brandName()}`;

  const bodyHtml = `
    ${whyChooseUsSection({ leading: true })}
    ${sectionDivider()}
    ${sectionHeading('Verify your email')}
    <p style="margin:0 0 16px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:center;">
      Use the One-Time Password below to complete your registration and start creating.
    </p>
    ${infoPanel({
      title: 'Your verification code',
      centered: true,
      contentHtml: `
        <span class="otp-code" style="font-size:32px;letter-spacing:7px;font-weight:700;color:${BRAND.headerBg};font-family:Consolas,'Courier New',monospace;">
          ${escapeHtml(otp)}
        </span>`,
    })}
    <p style="margin:0;color:${BRAND.textMuted};font-size:14px;text-align:center;">
      This code will expire in <strong>5 minutes</strong>.
    </p>
    ${bulletList([
      '<strong>Verify your email</strong> &mdash; enter the code above to activate your account.',
      '<strong>Create your first project</strong> &mdash; build AI-powered training videos in minutes.',
      '<strong>Invite your team</strong> &mdash; collaborate in shared workspaces.',
    ])}
    ${primaryButton({ href: home, label: `Go to ${brandName()}`, fullWidth: true })}
    ${disclaimerText('If you did not request this email, you can safely ignore it.')}`;

  const html = wrapEmailHtml({
    preheader: `Your verification code is ${otp}. Expires in 5 minutes.`,
    heroGreeting: 'Welcome!',
    heroSubtitle: `Verify your email to get started with ${escapeHtml(brandName())}.`,
    bodyHtml,
    variant: 'user',
  });

  return { subject, text, html };
}

module.exports = buildOtpEmail;
