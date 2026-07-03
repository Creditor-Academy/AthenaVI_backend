const DEFAULT_EMAIL_LOGO_URL =
  'https://testing-vi.s3.us-east-1.amazonaws.com/Copilot_20260703_145052.png';

const BRAND = {
  headerBg: '#0B1F3A',
  headerBgLight: '#132D50',
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
    theme: {
      bg: '#E4EDFA',
      border: '#AFC4E3',
      accent: '#1E4A8C',
      iconBg: '#2563EB',
      iconLight: '#93C5FD',
      tagBg: 'rgba(37,99,235,0.12)',
      tagText: '#1E40AF',
    },
    graphic: 'ai',
  },
  {
    number: '02',
    category: 'Toolkit',
    headline: 'Easy Customization',
    subheadline: 'Customize Every Frame with Ease',
    description:
      'Personalize every aspect of your videos with intuitive editing tools.',
    tags: ['Infinite Edit', 'Layer Control'],
    theme: {
      bg: '#E8EEF8',
      border: '#B5C5E0',
      accent: '#1A3D6B',
      iconBg: '#1E40AF',
      iconLight: '#A5B4FC',
      tagBg: 'rgba(30,64,175,0.11)',
      tagText: '#1E3A8A',
    },
    graphic: 'toolkit',
  },
  {
    number: '03',
    category: 'Vocal AI',
    headline: 'Voice-Based Interaction',
    description:
      'Enable users to ask questions using voice and receive intelligent spoken responses.',
    tags: ['Smart NLP', 'Instant Voice'],
    theme: {
      bg: '#E2EFFA',
      border: '#A8C8E6',
      accent: '#0F4C7A',
      iconBg: '#0284C7',
      iconLight: '#7DD3FC',
      tagBg: 'rgba(2,132,199,0.11)',
      tagText: '#0369A1',
    },
    graphic: 'vocal',
  },
  {
    number: '04',
    category: 'Templates',
    headline: 'World-class templates that empower creators',
    description:
      'Jump-start your projects with professionally designed templates built for creators and teams.',
    tags: ['Ready to Use', 'Fully Editable', 'Creator-Ready'],
    theme: {
      bg: '#EBF0F9',
      border: '#BBC8E0',
      accent: '#1E3354',
      iconBg: '#334E7A',
      iconLight: '#94A3B8',
      tagBg: 'rgba(51,78,122,0.1)',
      tagText: '#1E3354',
    },
    graphic: 'templates',
  },
];

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
        .feature-card-wrap { height: auto !important; min-height: 0 !important; }
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
        .premium-card { padding: 16px 14px !important; min-height: 0 !important; }
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

function featureGraphicHtml(type, theme) {
  const dot = (color, size = 5) =>
    `<td style="width:${size}px;height:${size}px;background-color:${color};border-radius:50%;font-size:0;line-height:0;">&nbsp;</td>`;

  const bar = (color, w, h = 14) =>
    `<td style="width:${w}px;height:${h}px;background-color:${color};border-radius:3px;font-size:0;line-height:0;">&nbsp;</td>`;

  const graphics = {
    ai: `
      <table role="presentation" cellpadding="2" cellspacing="2" style="margin:0 auto;">
        <tr>${dot('#FFFFFF')}${dot(theme.iconLight)}</tr>
        <tr>${dot(theme.iconLight)}${dot('#FFFFFF')}</tr>
      </table>`,
    toolkit: `
      <table role="presentation" cellpadding="0" cellspacing="3" style="margin:0 auto;">
        <tr>${bar('#FFFFFF', 22, 4)}</tr>
        <tr>${bar(theme.iconLight, 18, 4)}</tr>
        <tr>${bar('rgba(255,255,255,0.55)', 14, 4)}</tr>
      </table>`,
    vocal: `
      <table role="presentation" cellpadding="1" cellspacing="2" style="margin:0 auto;">
        <tr>
          ${bar('#FFFFFF', 3, 8)}
          ${bar(theme.iconLight, 3, 14)}
          ${bar('#FFFFFF', 3, 18)}
          ${bar(theme.iconLight, 3, 12)}
          ${bar('#FFFFFF', 3, 10)}
        </tr>
      </table>`,
    templates: `
      <table role="presentation" cellpadding="2" cellspacing="2" style="margin:0 auto;">
        <tr>${bar('#FFFFFF', 10, 10)}${bar(theme.iconLight, 10, 10)}</tr>
        <tr>${bar(theme.iconLight, 10, 10)}${bar('#FFFFFF', 10, 10)}</tr>
      </table>`,
  };

  return `
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
      <tr>
        <td style="width:48px;height:48px;background-color:${theme.iconBg};border-radius:14px;text-align:center;vertical-align:middle;box-shadow:0 4px 12px rgba(11,31,58,0.18);">
          ${graphics[type] || graphics.ai}
        </td>
      </tr>
    </table>`;
}

function premiumFeatureCard(feature, { cardHeight } = {}) {
  const theme = feature.theme || {
    bg: BRAND.featureBg,
    border: BRAND.featureBorder,
    accent: BRAND.headerBg,
    iconBg: BRAND.headerBg,
    iconLight: BRAND.accent,
    tagBg: 'rgba(11,31,58,0.06)',
    tagText: BRAND.headerBg,
  };

  const subheadlineBlock = feature.subheadline
    ? `<p style="margin:0 0 6px;color:${theme.accent};font-size:12px;font-weight:600;line-height:1.35;">
         ${escapeHtml(feature.subheadline)}
       </p>`
    : '';

  const tagsBlock = feature.tags?.length
    ? `<p style="margin:10px 0 0;font-size:0;line-height:0;">${feature.tags
        .map(
          (tag) => `
          <span style="display:inline-block;margin:0 5px 5px 0;padding:3px 9px;background-color:${theme.tagBg};color:${theme.tagText};font-size:10px;font-weight:600;border-radius:20px;line-height:1.3;border:1px solid ${theme.border};">
            ${escapeHtml(tag)}
          </span>`
        )
        .join('')}</p>`
    : cardHeight
      ? `<p style="margin:10px 0 0;font-size:0;line-height:0;height:0;">&nbsp;</p>`
      : '';

  const heightStyle = cardHeight
    ? `height:${cardHeight}px;min-height:${cardHeight}px;box-sizing:border-box;overflow:hidden;`
    : 'min-height:150px;';

  const cardInner = `
    <div class="premium-card" style="background-color:${theme.bg};border:1px solid ${theme.border};border-radius:14px;padding:0; ${heightStyle} box-shadow:0 6px 18px rgba(11,31,58,0.08);">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background-color:${theme.bg};border-radius:14px;">
        <tr>
          <td style="height:4px;background:linear-gradient(90deg,${theme.iconBg} 0%,${theme.iconLight} 100%);border-radius:14px 14px 0 0;font-size:0;line-height:0;">&nbsp;</td>
        </tr>
        <tr>
          <td style="padding:16px 16px 12px;vertical-align:top;">
            <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="width:54px;vertical-align:top;padding-right:10px;">
                  ${featureGraphicHtml(feature.graphic, theme)}
                </td>
                <td style="vertical-align:middle;">
                  <p style="margin:0 0 4px;color:${theme.iconBg};font-size:10px;font-weight:700;letter-spacing:0.07em;text-transform:uppercase;line-height:1.3;">
                    <span style="color:${theme.accent};opacity:0.55;margin-right:4px;">${escapeHtml(feature.number)}</span>${escapeHtml(feature.category)}
                  </p>
                  <p style="margin:0;color:${theme.accent};font-size:14px;font-weight:700;line-height:1.35;">
                    ${escapeHtml(feature.headline)}
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:0 16px 16px;vertical-align:top;">
            ${subheadlineBlock}
            <p style="margin:0;color:${BRAND.textMuted};font-size:13px;line-height:1.5;">
              ${escapeHtml(feature.description)}
            </p>
            ${tagsBlock}
          </td>
        </tr>
      </table>
    </div>`;

  if (!cardHeight) {
    return cardInner;
  }

  return `
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" height="${cardHeight}" class="feature-card-wrap" style="height:${cardHeight}px;">
      <tr>
        <td valign="top" height="${cardHeight}" style="height:${cardHeight}px;vertical-align:top;">
          ${cardInner}
        </td>
      </tr>
    </table>`;
}

function whyChooseUsSection({
  leading = false,
  equalHeight = false,
  cardHeight = 220,
  align = 'center',
} = {}) {
  const cardOpts = equalHeight ? { cardHeight } : {};

  const featureCells = WHY_CHOOSE_US.map(
    (feature, index) => `
      <td class="feature-col feature-pad" width="50%" valign="top" style="width:50%;padding:${index % 2 === 0 ? '0 6px 12px 0' : '0 0 12px 6px'};vertical-align:top;${equalHeight ? `height:${cardHeight}px;` : ''}">
        ${premiumFeatureCard(feature, cardOpts)}
      </td>`
  );

  const row1 = `<tr>${featureCells[0]}${featureCells[1]}</tr>`;
  const row2 = `<tr>${featureCells[2]}${featureCells[3]}</tr>`;

  const leadBlock = leading ? '' : sectionDivider();

  return `
    ${leadBlock}
    ${sectionHeading(`Why choose ${brandName()}?`, { align })}
    <p style="margin:0 0 18px;color:${BRAND.textMuted};font-size:13px;line-height:1.55;text-align:${align};">
      Next-generation tools to create, customize, and deliver professional video experiences.
    </p>
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:0 0 4px;">
      ${row1}
      ${row2}
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
  equalHeight: true,
  cardHeight: 240,
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
