const REQUIRED_LOGO_ROLES = ['primary', 'light', 'dark'];

function logoRolePresent(logos, role) {
  const aliases =
    role === 'light'
      ? ['light', 'light-mode']
      : role === 'dark'
        ? ['dark', 'dark-mode']
        : [role];
  return logos.some((m) => aliases.includes(m.role));
}

/**
 * Deterministic brand kit completeness score (no LLM).
 * @param {object} kit — workspace brand kit with media[]
 */
function computeBrandKitHealth(kit) {
  const data = kit?.data || {};
  const roles = data.colorRoles || {};
  const media = kit?.media || [];
  const logos = media.filter((m) => m.kind === 'logo');
  const photos = media.filter((m) => m.kind === 'photo');
  const graphics = media.filter((m) => m.kind === 'graphic');

  const checks = [
    {
      id: 'colors_light',
      label: 'Light theme colors',
      weight: 12,
      pass: Boolean(roles.bg && roles.text && roles.primary),
    },
    {
      id: 'colors_dark',
      label: 'Dark theme colors',
      weight: 10,
      pass: Boolean(roles.bgDark && roles.textDark && roles.primaryDark),
    },
    {
      id: 'logo_primary',
      label: 'Primary logo',
      weight: 15,
      pass: logos.some((m) => m.role === 'primary'),
    },
    {
      id: 'logo_variants',
      label: 'Logo variants',
      weight: 12,
      pass: REQUIRED_LOGO_ROLES.every((r) => logoRolePresent(logos, r)),
    },
    {
      id: 'typography',
      label: 'Typography (heading, subheading, body)',
      weight: 12,
      pass: Boolean(
        data.fonts?.heading?.family &&
          (data.fonts?.subheading?.family || data.fonts?.body?.family)
      ),
    },
    {
      id: 'voice',
      label: 'Brand voice',
      weight: 10,
      pass: Boolean(data.voice?.tone || data.voice?.audience),
    },
    {
      id: 'image_style',
      label: 'Image style brief',
      weight: 8,
      pass: Boolean(String(data.imageStyle || '').trim()),
    },
    {
      id: 'chart_colors',
      label: 'Chart colors',
      weight: 6,
      pass: Array.isArray(data.chartStyles?.colorIds) && data.chartStyles.colorIds.length > 0,
    },
    {
      id: 'photos',
      label: 'Brand photos',
      weight: 8,
      pass: photos.length > 0,
    },
    {
      id: 'graphics',
      label: 'Brand graphics',
      weight: 5,
      pass: graphics.length > 0,
    },
    {
      id: 'tagline',
      label: 'Tagline',
      weight: 2,
      pass: Boolean(String(data.meta?.tagline || '').trim()),
    },
    {
      id: 'guideline',
      label: 'Brand guideline deck',
      weight: 10,
      pass: Boolean(String(data.meta?.guidelineProjectId || '').trim()),
    },
  ];

  const totalWeight = checks.reduce((sum, c) => sum + c.weight, 0);
  const earned = checks.reduce((sum, c) => sum + (c.pass ? c.weight : 0), 0);
  const score = totalWeight ? Math.round((earned / totalWeight) * 100) : 0;

  let label = 'Needs work';
  if (score >= 90) label = 'Excellent Consistency';
  else if (score >= 75) label = 'Good Consistency';
  else if (score >= 50) label = 'Fair Consistency';

  return {
    score,
    label,
    checks: checks.map(({ id, label: checkLabel, pass }) => ({ id, label: checkLabel, pass })),
    missing: checks.filter((c) => !c.pass).map((c) => c.id),
    guidelineProjectId: data.meta?.guidelineProjectId || null,
  };
}

module.exports = {
  computeBrandKitHealth,
  REQUIRED_LOGO_ROLES,
};
