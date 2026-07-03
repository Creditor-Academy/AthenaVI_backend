const DEFAULT_EMAIL_LOGO_URL =
  'https://testing-vi.s3.us-east-1.amazonaws.com/Copilot_20260703_145052.png';

const BRAND = {
  headerBg: '#0E1627',
  headerBgLight: '#1A2840',
  headerText: '#FFFFFF',
  pageBg: '#E8EDF3',
  cardBg: '#FFFFFF',
  textPrimary: '#0F172A',
  textMuted: '#64748B',
  textLight: '#94A3B8',
  accent: '#3B82F6',
  accentDark: '#1E40AF',
  border: '#E2E8F0',
  panelBg: '#F8FAFC',
  featureBg: '#FFFFFF',
  featureBorder: '#E2E8F0',
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
};

const WHY_CHOOSE_US = [
  {
    number: '01',
    category: 'AI Engine',
    headline: 'AI-Powered Creation with NextGen Tools',
    description:
      'Generate professional videos in minutes with our advanced AI technology.',
    tags: ['Real-time Gen', 'HD 4K Support', 'AI-Powered Creation'],
    layout: 'wide',
    theme: {
      bg: '#D8E0EC',
      border: '#B8C4D4',
      accent: '#0E1627',
      stripe: '#0E1627',
      watermark: '#0E1627',
      watermarkOpacity: '0.12',
      tagBg: '#C5D0E0',
      tagText: '#0E1627',
    },
  },
  {
    number: '02',
    category: 'Toolkit',
    headline: 'Easy Customization',
    subheadline: 'Customize Every Frame with Ease',
    description:
      'Personalize every aspect of your videos with intuitive editing tools.',
    tags: ['Infinite Edit', 'Layer Control'],
    layout: 'tall',
    theme: {
      bg: '#E5C5C1',
      border: '#D4A8A3',
      accent: '#5C4549',
      stripe: '#B08B89',
      watermark: '#B08B89',
      watermarkOpacity: '0.28',
      tagBg: '#D9B0AB',
      tagText: '#4A383C',
    },
  },
  {
    number: '03',
    category: 'Vocal AI',
    headline: 'Voice-Based Interaction',
    description:
      'Enable users to ask questions using voice and receive intelligent spoken responses.',
    tags: ['Smart NLP', 'Instant Voice'],
    layout: 'tall',
    theme: {
      bg: '#DDD0D4',
      border: '#C4B0B6',
      accent: '#4A3A40',
      stripe: '#7F6269',
      watermark: '#7F6269',
      watermarkOpacity: '0.22',
      tagBg: '#CDBBC1',
      tagText: '#4A3A40',
    },
  },
  {
    number: '04',
    category: 'Templates',
    headline: 'World-class templates that empower creators',
    description:
      'Jump-start your projects with professionally designed templates built for creators and teams.',
    tags: ['Ready to Use', 'Fully Editable', 'Creator-Ready'],
    layout: 'wide',
    theme: {
      bg: '#F4E1E0',
      border: '#E0C4C2',
      accent: '#5C4549',
      stripe: '#B08B89',
      watermark: '#B08B89',
      watermarkOpacity: '0.2',
      tagBg: '#EBD4D2',
      tagText: '#5C4549',
    },
  },
];

const BENTO = {
  wide: '64%',
  narrow: '36%',
  row1Height: '188px',
  row2Height: '280px',
  radius: '20px',
  gap: '5px',
};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function brandName() {
  return process.env.EMAIL_BRAND_NAME || 'Virtual Studio';
}

function frontendUrl() {
  const raw = process.env.FRONTEND_URL || 'https://virtualstudio.lmsathena.com';
  return raw.replace(/\/$/, '');
}

function logoUrl() {
  return process.env.EMAIL_LOGO_URL || DEFAULT_EMAIL_LOGO_URL;
}

function hasCustomLogo() {
  return Boolean(logoUrl());
}

function exploreUrl() {
  return process.env.EMAIL_EXPLORE_URL || `${frontendUrl()}/products`;
}

function preferencesUrl() {
  return `${frontendUrl()}/settings/notifications`;
}

function currentYear() {
  return new Date().getFullYear();
}

function emailMobileStyles() {
  return `
    <style type="text/css">
      body { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
      table { border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
      img { -ms-interpolation-mode: bicubic; border: 0; outline: none; text-decoration: none; }
      @media only screen and (max-width: 620px) {
        .email-shell { width: 100% !important; max-width: 100% !important; }
        .outer-pad { padding: 12px 10px !important; }
        .header-pad { padding: 24px 20px 28px !important; }
        .body-pad { padding: 24px 18px 8px !important; }
        .footer-pad { padding: 20px 18px 12px !important; }
        .hero-title { font-size: 26px !important; line-height: 1.25 !important; }
        .hero-title-lg { font-size: 28px !important; line-height: 1.2 !important; }
        .hero-sub { font-size: 14px !important; }
        .header-left { text-align: left !important; }
        .logo-img { max-width: 88px !important; width: 88px !important; height: auto !important; }
        .feature-col {
          display: block !important;
          width: 100% !important;
          max-width: 100% !important;
          box-sizing: border-box !important;
          height: auto !important;
        }
        .feature-pad { padding: 0 0 12px 0 !important; }
        .bento-grid { border-spacing: 0 !important; }
        .bento-wide, .bento-narrow {
          display: block !important;
          width: 100% !important;
          max-width: 100% !important;
          padding: 0 0 10px 0 !important;
          height: auto !important;
        }
        .bento-card-body { height: auto !important; min-height: 0 !important; }
        .bento-watermark { font-size: 36px !important; }
        .premium-card { padding: 16px 14px !important; min-height: 0 !important; height: auto !important; }
        .stat-col {
          display: block !important;
          width: 100% !important;
          max-width: 100% !important;
          box-sizing: border-box !important;
        }
        .stat-pad { padding: 10px 0 !important; }
        .btn-link {
          display: block !important;
          width: 100% !important;
          padding: 14px 20px !important;
          font-size: 15px !important;
          box-sizing: border-box !important;
        }
        .data-label {
          display: block !important;
          width: 100% !important;
          padding: 0 0 4px 0 !important;
        }
        .data-value {
          display: block !important;
          width: 100% !important;
          padding: 0 0 14px 0 !important;
        }
        .otp-code { font-size: 28px !important; letter-spacing: 5px !important; }
      }
    </style>`;
}

function preheaderHtml(text) {
  if (!text) {
    return '';
  }

  return `
    <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:${BRAND.pageBg};">
      ${escapeHtml(text)}
    </div>`;
}

function brandWordmarkHtml() {
  const name = brandName();
  const parts = name.split(/\s+/);
  const first = parts[0] || name;
  const rest = parts.slice(1).join(' ');

  return `
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto 12px;">
      <tr>
        <td style="vertical-align:middle;padding-right:8px;">
          <div style="width:30px;height:30px;border-radius:8px;background:rgba(255,255,255,0.15);text-align:center;line-height:30px;">
            <span style="color:${BRAND.headerText};font-size:13px;font-weight:700;">VS</span>
          </div>
        </td>
        <td style="vertical-align:middle;text-align:left;">
          <span style="color:${BRAND.headerText};font-size:18px;font-weight:700;letter-spacing:-0.02em;line-height:1.2;">${escapeHtml(first)}</span>${rest ? `<span style="color:rgba(255,255,255,0.9);font-size:18px;font-weight:400;"> ${escapeHtml(rest)}</span>` : ''}
        </td>
      </tr>
    </table>`;
}

function logoBlockHtml({ align = 'center', width = 140 } = {}) {
  const customLogo = logoUrl();
  const alignStyle = align === 'left' ? 'margin:0;' : 'margin:0 auto;';

  if (hasCustomLogo()) {
    return `
      <a href="${escapeHtml(frontendUrl())}" style="text-decoration:none;display:inline-block;">
        <img class="logo-img" src="${escapeHtml(customLogo)}" alt="${escapeHtml(brandName())}" width="${width}" height="auto"
          style="display:block;${alignStyle}max-width:${width}px;width:${width}px;height:auto;border:0;outline:none;" />
      </a>`;
  }

  return brandWordmarkHtml();
}

function emailHeader({ variant, heroGreeting, heroSubtitle, headerAlign = 'center' }) {
  const adminBadge =
    variant === 'admin'
      ? `<p style="margin:12px 0 0;color:rgba(255,255,255,0.75);font-size:10px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;">
           Admin notification
         </p>`
      : '';

  if (heroGreeting && headerAlign === 'left') {
    const subtitleBlock = heroSubtitle
      ? `<p class="hero-sub" style="margin:10px 0 0;color:rgba(255,255,255,0.82);font-size:15px;line-height:1.5;font-weight:400;text-align:left;">
           ${heroSubtitle}
         </p>`
      : '';

    return `
      <tr>
        <td class="header-pad header-left" style="background-color:${BRAND.headerBg};padding:24px 28px 28px;text-align:left;border-radius:16px 16px 0 0;">
          ${logoBlockHtml({ align: 'left', width: 96 })}
          <h1 class="hero-title-lg" style="margin:14px 0 0;color:${BRAND.headerText};font-size:34px;font-weight:700;line-height:1.15;letter-spacing:-0.03em;text-align:left;">
            ${heroGreeting}
          </h1>
          ${subtitleBlock}
          ${adminBadge}
        </td>
      </tr>`;
  }

  if (heroGreeting) {
    const subtitleBlock = heroSubtitle
      ? `<p class="hero-sub" style="margin:8px 0 0;color:rgba(255,255,255,0.82);font-size:15px;line-height:1.5;font-weight:400;">
           ${heroSubtitle}
         </p>`
      : '';

    return `
      <tr>
        <td class="header-pad" style="background-color:${BRAND.headerBg};padding:28px 28px 32px;text-align:center;border-radius:16px 16px 0 0;">
          ${logoBlockHtml()}
          <h1 class="hero-title" style="margin:0;color:${BRAND.headerText};font-size:26px;font-weight:700;line-height:1.25;letter-spacing:-0.02em;">
            ${heroGreeting}
          </h1>
          ${subtitleBlock}
          ${adminBadge}
        </td>
      </tr>`;
  }

  return `
    <tr>
      <td class="header-pad" style="background-color:${BRAND.headerBg};padding:24px 28px 22px;text-align:center;border-radius:16px 16px 0 0;">
        ${logoBlockHtml()}
        ${adminBadge}
      </td>
    </tr>`;
}

function standardFooter({ includePreferencesLink = false } = {}) {
  const home = frontendUrl();
  const prefs = preferencesUrl();

  const preferencesLine = includePreferencesLink
    ? `<p style="margin:0 0 8px;color:${BRAND.textMuted};font-size:12px;line-height:1.5;">
         <a href="${escapeHtml(prefs)}" style="color:${BRAND.accent};text-decoration:none;">Manage notification preferences</a>
       </p>`
    : '';

  return `
    <tr>
      <td class="footer-pad" style="padding:24px 28px 12px;text-align:center;background-color:${BRAND.cardBg};border-radius:0 0 16px 16px;">
        ${preferencesLine}
        <p style="margin:0 0 8px;color:${BRAND.textMuted};font-size:12px;line-height:1.5;">
          <a href="${escapeHtml(home)}" style="color:${BRAND.accent};text-decoration:none;font-weight:500;">${escapeHtml(brandName())}</a>
        </p>
        <p style="margin:0;color:${BRAND.textLight};font-size:11px;">
          &copy; ${currentYear()} ${escapeHtml(brandName())}. All rights reserved.
        </p>
      </td>
    </tr>`;
}

function wrapEmailHtml({
  preheader,
  title,
  bodyHtml,
  footerHtml,
  variant = 'user',
  includePreferencesLink = false,
  heroGreeting,
  heroSubtitle,
  headerAlign = 'center',
}) {
  const footer =
    footerHtml ||
    (variant === 'admin'
      ? `<tr>
           <td class="footer-pad" style="padding:18px 28px 12px;text-align:center;background-color:${BRAND.cardBg};border-radius:0 0 16px 16px;">
             <p style="margin:0;color:${BRAND.textLight};font-size:11px;">
               Internal notification &mdash; ${escapeHtml(brandName())}
             </p>
           </td>
         </tr>`
      : standardFooter({ includePreferencesLink }));

  const titleBlock =
    title && !heroGreeting
      ? `<h2 style="margin:0 0 20px;color:${BRAND.textPrimary};font-size:21px;font-weight:700;line-height:1.3;text-align:center;">
           ${title}
         </h2>`
      : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <title>${escapeHtml(typeof title === 'string' ? title.replace(/<[^>]*>/g, '') : brandName())}</title>
  ${emailMobileStyles()}
</head>
<body style="margin:0;padding:0;background-color:${BRAND.pageBg};font-family:${BRAND.fontFamily};width:100%;">
  ${preheaderHtml(preheader)}
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color:${BRAND.pageBg};">
    <tr>
      <td class="outer-pad" style="padding:28px 16px;">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" class="email-shell"
          style="max-width:580px;margin:0 auto;background-color:${BRAND.cardBg};border-radius:16px;box-shadow:0 10px 40px rgba(11,31,58,0.12);overflow:hidden;">
          ${emailHeader({ variant, heroGreeting, heroSubtitle, headerAlign })}
          <tr>
            <td class="body-pad" style="padding:28px 28px 8px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;">
              ${titleBlock}
              ${bodyHtml}
            </td>
          </tr>
          ${footer}
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function sectionHeading(text, { align = 'center' } = {}) {
  return `
    <h3 style="margin:0 0 14px;color:${BRAND.textPrimary};font-size:17px;font-weight:700;line-height:1.35;text-align:${align};">
      ${escapeHtml(text)}
    </h3>`;
}

function sectionDivider() {
  return `<hr style="border:none;border-top:1px solid ${BRAND.border};margin:24px 0;" />`;
}

function bulletList(items) {
  const rows = items
    .map(
      (item) => `
        <tr>
          <td style="padding:0 12px 12px 0;vertical-align:top;width:14px;">
            <div style="width:7px;height:7px;background-color:${BRAND.headerBg};border-radius:2px;margin-top:7px;"></div>
          </td>
          <td style="padding:0 0 12px;color:${BRAND.textPrimary};font-size:14px;line-height:1.55;">
            ${item}
          </td>
        </tr>`
    )
    .join('');

  return `
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:0 0 4px;">
      ${rows}
    </table>`;
}

function bentoFeatureCardCell(feature, slot) {
  const theme = feature.theme;
  const slots = {
    'r1-wide': {
      width: BENTO.wide,
      height: BENTO.row1Height,
      pad: `padding:0 ${BENTO.gap} ${BENTO.gap} 0;`,
      className: 'bento-wide',
    },
    'r1-narrow': {
      width: BENTO.narrow,
      height: BENTO.row1Height,
      pad: `padding:0 0 ${BENTO.gap} ${BENTO.gap};`,
      className: 'bento-narrow',
    },
    'r2-narrow': {
      width: BENTO.narrow,
      height: BENTO.row2Height,
      pad: `padding:${BENTO.gap} ${BENTO.gap} 0 0;`,
      className: 'bento-narrow',
    },
    'r2-wide': {
      width: BENTO.wide,
      height: BENTO.row2Height,
      pad: `padding:${BENTO.gap} 0 0 ${BENTO.gap};`,
      className: 'bento-wide',
    },
  };
  const { width, height, pad, className } = slots[slot];
  const isNarrow = className === 'bento-narrow';
  const headlineSize = isNarrow ? '13px' : '15px';
  const descSize = isNarrow ? '12px' : '13px';
  const watermarkSize = isNarrow ? '56px' : '50px';
  const cardPad = isNarrow ? '16px 14px' : '18px 18px';

  const subheadlineBlock = feature.subheadline
    ? `<p style="margin:0 0 6px;color:${theme.accent};font-size:${isNarrow ? '11px' : '12px'};font-weight:600;line-height:1.35;">
         ${escapeHtml(feature.subheadline)}
       </p>`
    : '';

  const tagsBlock = feature.tags?.length
    ? `<p style="margin:0;font-size:0;line-height:0;">${feature.tags
        .map(
          (tag) => `
          <span style="display:inline-block;margin:0 4px 4px 0;padding:4px 9px;background-color:${theme.tagBg};color:${theme.tagText};font-size:9px;font-weight:600;border-radius:20px;line-height:1.3;border:1px solid ${theme.border};">
            ${escapeHtml(tag)}
          </span>`
        )
        .join('')}</p>`
    : '';

  const headerRow = `
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
      <tr>
        <td valign="top" style="vertical-align:top;padding-right:8px;">
          <p style="margin:0;color:${theme.accent};font-size:9px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;line-height:1.3;">
            ${escapeHtml(feature.category)}
          </p>
        </td>
        <td align="right" valign="top" width="1" style="vertical-align:top;white-space:nowrap;">
          <span class="bento-watermark" style="display:block;font-size:${watermarkSize};font-weight:800;color:${theme.watermark};opacity:${theme.watermarkOpacity};letter-spacing:-0.05em;line-height:0.85;font-family:${BRAND.fontFamily};">
            ${escapeHtml(feature.number)}
          </span>
        </td>
      </tr>
    </table>`;

  const bodyBlock = `
    <p style="margin:10px 0 6px;color:${theme.accent};font-size:${headlineSize};font-weight:700;line-height:1.3;">
      ${escapeHtml(feature.headline)}
    </p>
    ${subheadlineBlock}
    <p style="margin:0;color:${BRAND.textMuted};font-size:${descSize};line-height:1.5;">
      ${escapeHtml(feature.description)}
    </p>`;

  const cardInner = isNarrow
    ? `
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" height="100%" style="height:100%;">
        <tr>
          <td valign="top" style="vertical-align:top;">
            ${headerRow}
            ${bodyBlock}
          </td>
        </tr>
        <tr>
          <td height="100%" style="height:100%;font-size:0;line-height:0;mso-line-height-rule:exactly;">&nbsp;</td>
        </tr>
        <tr>
          <td valign="bottom" style="vertical-align:bottom;padding-top:10px;">
            ${tagsBlock}
          </td>
        </tr>
      </table>`
    : `
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" height="100%" style="height:100%;">
        <tr>
          <td valign="top" style="vertical-align:top;">
            ${headerRow}
            ${bodyBlock}
          </td>
        </tr>
        <tr>
          <td valign="bottom" style="vertical-align:bottom;padding-top:12px;">
            ${tagsBlock}
          </td>
        </tr>
      </table>`;

  return `
    <td class="feature-col ${className} feature-pad" width="${width}" valign="top"
      style="width:${width};${pad}vertical-align:top;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" class="bento-card-body"
        style="border-collapse:separate;border-spacing:0;height:${height};min-height:${height};">
        <tr>
          <td bgcolor="${theme.bg}" class="bento-card-body" valign="top"
            style="background-color:${theme.bg};border:1px solid ${theme.border};border-radius:${BENTO.radius};padding:${cardPad};height:${height};min-height:${height};vertical-align:top;">
            ${cardInner}
          </td>
        </tr>
      </table>
    </td>`;
}

function whyChooseUsSection({ leading = false, align = 'center' } = {}) {
  const [card01, card02, card03, card04] = WHY_CHOOSE_US;
  const leadBlock = leading ? '' : sectionDivider();

  return `
    ${leadBlock}
    ${sectionHeading(`Why choose ${brandName()}?`, { align })}
    <p style="margin:0 0 16px;color:${BRAND.textMuted};font-size:13px;line-height:1.55;text-align:${align};">
      Next-generation tools to create, customize, and deliver professional video experiences.
    </p>
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" class="bento-grid"
      style="width:100%;margin:0 0 4px;border-collapse:separate;border-spacing:0;table-layout:fixed;">
      <tr>
        ${bentoFeatureCardCell(card01, 'r1-wide')}
        ${bentoFeatureCardCell(card02, 'r1-narrow')}
      </tr>
      <tr>
        ${bentoFeatureCardCell(card03, 'r2-narrow')}
        ${bentoFeatureCardCell(card04, 'r2-wide')}
      </tr>
    </table>`;
}

function whyChooseUsText() {
  const lines = WHY_CHOOSE_US.map((f) => {
    const headline = f.subheadline ? `${f.headline} — ${f.subheadline}` : f.headline;
    const tags = f.tags?.length ? ` (${f.tags.join(', ')})` : '';
    return `  ${f.number} ${f.category} — ${headline}\n     ${f.description}${tags}`;
  });
  return `Why choose ${brandName()}?\n\n${lines.join('\n\n')}`;
}

function primaryButton({ href, label, fullWidth = false }) {
  return `
    <table role="presentation" cellpadding="0" cellspacing="0" width="${fullWidth ? '100%' : 'auto'}" style="margin:20px auto 0;">
      <tr>
        <td style="border-radius:10px;background-color:${BRAND.headerBg};text-align:center;">
          <a class="btn-link" href="${escapeHtml(href)}"
            style="display:inline-block;padding:15px 28px;color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;border-radius:10px;${fullWidth ? 'width:100%;box-sizing:border-box;' : ''}">
            ${escapeHtml(label)}
          </a>
        </td>
      </tr>
    </table>`;
}

function secondaryLink({ href, label, align = 'center' }) {
  return `
    <p style="margin:12px 0 0;font-size:13px;text-align:${align};">
      <a href="${escapeHtml(href)}" style="color:${BRAND.accent};text-decoration:none;font-weight:500;">
        ${escapeHtml(label)}
      </a>
    </p>`;
}

function infoPanel({ title, contentHtml, centered = false }) {
  const titleBlock = title
    ? `<p style="margin:0 0 10px;color:${BRAND.textMuted};font-size:10px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;">
         ${escapeHtml(title)}
       </p>`
    : '';

  const align = centered ? 'center' : 'left';

  return `
    <div class="premium-card" style="background-color:${BRAND.panelBg};border:1px solid ${BRAND.border};border-radius:12px;padding:18px 20px;margin:18px 0;text-align:${align};box-shadow:0 2px 10px rgba(11,31,58,0.04);">
      ${titleBlock}
      ${contentHtml}
    </div>`;
}

function dataTable(rows) {
  const rowHtml = rows
    .map(
      ({ label, valueHtml }) => `
        <tr>
          <td class="data-label" style="padding:10px 0;color:${BRAND.textMuted};font-size:14px;vertical-align:top;width:110px;">${escapeHtml(label)}</td>
          <td class="data-value" style="padding:10px 0;color:${BRAND.textPrimary};font-size:14px;line-height:1.5;">${valueHtml}</td>
        </tr>`
    )
    .join('');

  return `
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:0 0 8px;">
      ${rowHtml}
    </table>`;
}

function disclaimerText(text) {
  return `
    <p style="margin:22px 0 0;color:${BRAND.textMuted};font-size:12px;line-height:1.5;border-top:1px solid ${BRAND.border};padding-top:18px;text-align:center;">
      ${text}
    </p>`;
}

function fallbackUrlBlock(url) {
  return `
    <p style="margin:18px 0 0;color:${BRAND.textMuted};font-size:12px;line-height:1.5;text-align:center;">
      If the button doesn&rsquo;t work, copy and paste this link into your browser:
    </p>
    <p style="margin:8px 0 0;word-break:break-all;font-size:11px;line-height:1.5;text-align:center;">
      <a href="${escapeHtml(url)}" style="color:${BRAND.accent};text-decoration:none;">${escapeHtml(url)}</a>
    </p>`;
}

function statsGrid(stats) {
  const rows = [];
  for (let i = 0; i < stats.length; i += 2) {
    const left = stats[i];
    const right = stats[i + 1];
    rows.push(`
      <tr>
        <td class="stat-col stat-pad" width="50%" style="width:50%;padding:10px 8px;vertical-align:top;">
          <p style="margin:0 0 4px;color:${BRAND.textMuted};font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em;">
            ${escapeHtml(left.label)}
          </p>
          <p style="margin:0;color:${BRAND.textPrimary};font-size:18px;font-weight:700;">
            ${escapeHtml(String(left.value))}
          </p>
        </td>
        ${
          right
            ? `<td class="stat-col stat-pad" width="50%" style="width:50%;padding:10px 8px;vertical-align:top;">
                 <p style="margin:0 0 4px;color:${BRAND.textMuted};font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.04em;">
                   ${escapeHtml(right.label)}
                 </p>
                 <p style="margin:0;color:${BRAND.textPrimary};font-size:18px;font-weight:700;">
                   ${escapeHtml(String(right.value))}
                 </p>
               </td>`
            : '<td class="stat-col" width="50%" style="width:50%;"></td>'
        }
      </tr>`);
  }

  return `
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:14px 0;">
      ${rows.join('')}
    </table>`;
}

function formatSubmittedAt(isoString) {
  try {
    return new Date(isoString).toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'short',
    });
  } catch {
    return isoString;
  }
}

function firstName(name) {
  const trimmed = String(name || '').trim();
  if (!trimmed) {
    return 'there';
  }
  return trimmed.split(/\s+/)[0];
}

const PRE_SIGNIN_WHY_CHOOSE_OPTS = {
  leading: true,
  align: 'left',
};

function whyChooseUsSectionPreSignIn(overrides = {}) {
  return whyChooseUsSection({ ...PRE_SIGNIN_WHY_CHOOSE_OPTS, ...overrides });
}

module.exports = {
  BRAND,
  WHY_CHOOSE_US,
  PRE_SIGNIN_WHY_CHOOSE_OPTS,
  DEFAULT_EMAIL_LOGO_URL,
  escapeHtml,
  brandName,
  frontendUrl,
  logoUrl,
  hasCustomLogo,
  exploreUrl,
  preferencesUrl,
  wrapEmailHtml,
  primaryButton,
  secondaryLink,
  infoPanel,
  dataTable,
  disclaimerText,
  fallbackUrlBlock,
  statsGrid,
  formatSubmittedAt,
  firstName,
  standardFooter,
  sectionHeading,
  sectionDivider,
  bulletList,
  whyChooseUsSection,
  whyChooseUsSectionPreSignIn,
  whyChooseUsText,
  brandWordmarkHtml,
};
