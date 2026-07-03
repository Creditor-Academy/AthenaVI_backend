const {
  brandName,
  escapeHtml,
  preferencesUrl,
  wrapEmailHtml,
} = require('./emailLayout');

const buildProductAnnouncementEmail = ({ subject, htmlBody, textBody }) => {
  const settingsUrl = preferencesUrl();

  const text =
    textBody ||
    `${subject}\n\nManage notification preferences: ${settingsUrl}\n\nYou received this because you opted in to product emails on ${brandName()}.`;

  const bodyHtml = `
    <div style="color:#1A202C;font-size:15px;line-height:1.6;">
      ${htmlBody}
    </div>
    <p style="margin:24px 0 0;color:#64748B;font-size:13px;line-height:1.5;border-top:1px solid #E2E8F0;padding-top:20px;">
      You received this because you opted in to product emails from ${escapeHtml(brandName())}.
    </p>`;

  const html = wrapEmailHtml({
    preheader: subject,
    title: escapeHtml(subject),
    bodyHtml,
    variant: 'user',
    includePreferencesLink: true,
  });

  return { subject, text, html };
};

module.exports = {
  buildProductAnnouncementEmail,
};
