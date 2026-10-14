const {
  brandName,
  escapeHtml,
  wrapEmailHtml,
  primaryButton,
  disclaimerText,
  fallbackUrlBlock,
  sectionHeading,
  BRAND,
} = require('./emailLayout');

function buildPasswordResetEmail(resetLink, expiryMinutes = 15) {
  const subject = 'Reset your password';

  const text = `Reset your password

We received a request to reset your password. Open the link below to create a new one:

${resetLink}

This link will expire in ${expiryMinutes} minutes.

If you did not request a password reset, you can safely ignore this email.

— ${brandName()}`;

  const bodyHtml = `
    ${sectionHeading('Create a new password', { align: 'left' })}
    <p style="margin:0 0 20px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
      We received a request to reset your password. Click the button below to create a new one.
    </p>
    ${primaryButton({ href: resetLink, label: 'Reset password', fullWidth: true })}
    <p style="margin:0;color:${BRAND.textMuted};font-size:14px;text-align:left;">
      This link will expire in <strong>${escapeHtml(String(expiryMinutes))} minutes</strong>.
    </p>
    ${fallbackUrlBlock(resetLink)}
    ${disclaimerText('If you did not request a password reset, you can safely ignore this email.')}`;

  const html = wrapEmailHtml({
    preheader: `Reset your ${brandName()} password. Link expires in ${expiryMinutes} minutes.`,
    heroGreeting: 'Reset your password',
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
  });

  return { subject, text, html };
}

module.exports = buildPasswordResetEmail;
