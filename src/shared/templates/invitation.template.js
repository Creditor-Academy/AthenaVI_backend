const {
  brandName,
  escapeHtml,
  wrapEmailHtml,
  primaryButton,
  disclaimerText,
  fallbackUrlBlock,
  sectionHeading,
  bulletList,
  whyChooseUsSectionPreSignIn,
  whyChooseUsText,
  sectionDivider,
  BRAND,
} = require('./emailLayout');

function buildInvitationEmail(link, workspaceName, inviterName) {
  const subject = `${inviterName} invited you to join ${workspaceName}`;

  const text = `You're invited!

${inviterName} has invited you to collaborate in the ${workspaceName} workspace on ${brandName()}.

${whyChooseUsText()}

Accept the invitation:
${link}

This invitation link will expire in 7 days.

  • Shared projects — create and edit video content with your team.
  • Team assets — access avatars, voices, media, and renders in one place.
  • Real-time collaboration — comments, notifications, and workspace roles.

If you were not expecting this invitation, you can safely ignore this email.

— ${brandName()}`;

  const bodyHtml = `
    ${sectionHeading('You\u2019re invited to collaborate', { align: 'left' })}
    <p style="margin:0 0 24px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
      <strong>${escapeHtml(inviterName)}</strong> has invited you to collaborate in the
      <strong>${escapeHtml(workspaceName)}</strong> workspace on ${escapeHtml(brandName())}.
    </p>
    ${whyChooseUsSectionPreSignIn()}
    ${sectionDivider()}
    ${bulletList([
      '<strong>Shared projects</strong> &mdash; create and edit video content with your team.',
      '<strong>Team assets</strong> &mdash; access avatars, voices, media, and renders in one place.',
      '<strong>Real-time collaboration</strong> &mdash; comments, notifications, and workspace roles.',
    ])}
    ${primaryButton({ href: link, label: 'Accept invitation', fullWidth: true })}
    <p style="margin:0;color:${BRAND.textMuted};font-size:14px;text-align:left;">
      This invitation link will expire in <strong>7 days</strong>.
    </p>
    ${fallbackUrlBlock(link)}
    ${disclaimerText('If you were not expecting this invitation, you can safely ignore this email.')}`;

  const html = wrapEmailHtml({
    preheader: `${inviterName} invited you to join ${workspaceName} on ${brandName()}.`,
    heroGreeting: `You're invited!`,
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
  });

  return { subject, text, html };
}

module.exports = buildInvitationEmail;
