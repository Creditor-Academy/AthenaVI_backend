const {
  brandName,
  escapeHtml,
  preferencesUrl,
  frontendUrl,
  wrapEmailHtml,
  sectionHeading,
  primaryButton,
  secondaryLink,
  BRAND,
} = require('./emailLayout');

const buildProductAnnouncementEmail = ({ subject, htmlBody, textBody }) => {
  const settingsUrl = preferencesUrl();
  const home = frontendUrl();

  const text =
    textBody ||
    `${subject}\n\nManage notification preferences: ${settingsUrl}\n\nYou received this because you opted in to product emails on ${brandName()}.`;

  const bodyHtml = `
    ${sectionHeading(subject, { align: 'left' })}
    <div style="color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
      ${htmlBody}
    </div>
    <p style="margin:24px 0 0;color:${BRAND.textMuted};font-size:13px;line-height:1.5;border-top:1px solid ${BRAND.border};padding-top:20px;text-align:left;">
      You received this because you opted in to product emails from ${escapeHtml(brandName())}.
    </p>
    ${primaryButton({ href: home, label: `Open ${brandName()}`, fullWidth: true })}
    ${secondaryLink({ href: settingsUrl, label: 'Manage notification preferences', align: 'left' })}`;

  const html = wrapEmailHtml({
    preheader: subject,
    heroGreeting: escapeHtml(subject),
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
    includePreferencesLink: true,
  });

  return { subject, text, html };
};

module.exports = {
  buildProductAnnouncementEmail,
};
