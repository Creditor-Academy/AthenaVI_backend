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
  whyChooseUsSectionPreSignIn,
  whyChooseUsText,
  sectionDivider,
  BRAND,
} = require('./emailLayout');

function buildOtpEmail(otp) {
  const subject = 'Verify your email';
  const home = frontendUrl();

  const text = `Welcome to ${brandName()}!

Verify your email

Use the One-Time Password below to complete your registration and start creating.

${otp}

This OTP will expire in 5 minutes.

${whyChooseUsText()}

  • Verify your email — enter the code above to activate your account.
  • Create your first project — build AI-powered training videos in minutes.
  • Invite your team — collaborate in shared workspaces.

If you did not request this email, you can safely ignore it.

— ${brandName()}`;

  const bodyHtml = `
    ${sectionHeading('Verify your email', { align: 'left' })}
    <p style="margin:0 0 20px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
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
    <p style="margin:0 0 24px;color:${BRAND.textMuted};font-size:14px;text-align:left;">
      This code will expire in <strong>5 minutes</strong>.
    </p>
    ${whyChooseUsSectionPreSignIn()}
    ${sectionDivider()}
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
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
  });

  return { subject, text, html };
}

module.exports = buildOtpEmail;
