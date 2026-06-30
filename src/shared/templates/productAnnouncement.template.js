const buildProductAnnouncementEmail = ({ subject, htmlBody, textBody }) => {
  const settingsUrl = `${process.env.FRONTEND_URL || ''}/settings/notifications`;
  const text =
    textBody ||
    `${subject}\n\nManage notification preferences: ${settingsUrl}\n\nYou received this because you opted in to product emails on Athena VI.`;

  const html = `
  <div style="background-color:#f4f6f8;padding:40px 0;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:10px;padding:40px 30px;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
      <h2 style="color:#2d3748;margin-bottom:16px;">${subject}</h2>
      <div style="color:#4a5568;font-size:15px;line-height:1.6;">${htmlBody}</div>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:30px 0;" />
      <p style="color:#718096;font-size:12px;">
        You received this because you opted in to product emails.
        <a href="${settingsUrl}" style="color:#2563eb;">Manage notification preferences</a>
      </p>
      <p style="color:#718096;font-size:12px;margin-top:16px;">Athena VI</p>
    </div>
  </div>`;

  return { subject, text, html };
};

module.exports = {
  buildProductAnnouncementEmail,
};
