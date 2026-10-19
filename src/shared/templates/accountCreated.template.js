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

function formatExpiry(expiryHours) {
  if (expiryHours % 24 === 0) {
    const days = expiryHours / 24;
    return `${days} day${days === 1 ? '' : 's'}`;
  }
  return `${expiryHours} hour${expiryHours === 1 ? '' : 's'}`;
}

/**
 * Welcome email for an account created by a platform admin.
 * Never contains a password — the recipient sets their own via `setPasswordLink`.
 */
function buildAccountCreatedEmail({ name, email, setPasswordLink, expiryHours = 72 }) {
  const brand = brandName();
  const greetingName = String(name || '').trim() || 'there';
  const expiry = formatExpiry(expiryHours);
  const subject = `Your ${brand} account is ready`;

  const text = `Hi ${greetingName},

An administrator has created a ${brand} account for you (${email}).

Set your password to get started:
${setPasswordLink}

This link expires in ${expiry}. After that you can use "Forgot password" on the sign-in page to get a new one.

If you were not expecting this email, you can safely ignore it.

— ${brand}`;

  const bodyHtml = `
    ${sectionHeading('Your account is ready', { align: 'left' })}
    <p style="margin:0 0 16px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
      Hi ${escapeHtml(greetingName)}, an administrator has created a ${escapeHtml(brand)} account for you
      (<strong>${escapeHtml(email)}</strong>). Set a password to get started.
    </p>
    ${primaryButton({ href: setPasswordLink, label: 'Set your password', fullWidth: true })}
    <p style="margin:0;color:${BRAND.textMuted};font-size:14px;text-align:left;">
      This link expires in <strong>${escapeHtml(expiry)}</strong>. After that, use
      &ldquo;Forgot password&rdquo; on the sign-in page to get a new one.
    </p>
    ${fallbackUrlBlock(setPasswordLink)}
    ${disclaimerText('If you were not expecting this email, you can safely ignore it.')}`;

  const html = wrapEmailHtml({
    preheader: `Your ${brand} account is ready. Set your password to get started.`,
    heroGreeting: `Welcome to ${brand}`,
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
  });

  return { subject, text, html };
}

module.exports = buildAccountCreatedEmail;
