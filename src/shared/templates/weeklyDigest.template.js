const buildWeeklyDigestEmail = ({
  userName,
  periodStart,
  periodEnd,
  stats,
}) => {
  const greeting = userName ? `Hi ${userName},` : 'Hi,';
  const periodLabel = `${periodStart} – ${periodEnd}`;
  const subject = `Your Athena VI weekly digest (${periodStart})`;

  const lines = [
    `Renders completed: ${stats.rendersCompleted}`,
    `Credits used: ${stats.creditsUsed} AC`,
    `Projects you updated: ${stats.projectsUpdated}`,
    `New teammates in your workspaces: ${stats.teamMembersJoined}`,
  ];

  const text = `${greeting}

Here is your Athena VI activity summary for ${periodLabel}:

${lines.map((l) => `- ${l}`).join('\n')}

Manage notification preferences: ${process.env.FRONTEND_URL || ''}/settings/notifications

— Athena VI`;

  const statsHtml = lines
    .map(
      (line) =>
        `<tr><td style="padding:8px 0;color:#4a5568;font-size:15px;">${line}</td></tr>`
    )
    .join('');

  const settingsUrl = `${process.env.FRONTEND_URL || ''}/settings/notifications`;

  const html = `
  <div style="background-color:#f4f6f8;padding:40px 0;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:10px;padding:40px 30px;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
      <h2 style="color:#2d3748;margin-bottom:10px;">Your weekly digest</h2>
      <p style="color:#4a5568;font-size:15px;margin-bottom:20px;">${greeting}</p>
      <p style="color:#4a5568;font-size:15px;margin-bottom:20px;">Activity for <strong>${periodLabel}</strong>:</p>
      <table style="width:100%;border-collapse:collapse;">${statsHtml}</table>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:30px 0;" />
      <p style="color:#718096;font-size:12px;">
        <a href="${settingsUrl}" style="color:#2563eb;">Manage notification preferences</a>
      </p>
      <p style="color:#718096;font-size:12px;margin-top:16px;">Athena VI</p>
    </div>
  </div>`;

  return { subject, text, html };
};

module.exports = {
  buildWeeklyDigestEmail,
};
