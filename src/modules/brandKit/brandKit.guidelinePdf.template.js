/**
 * Brand guideline PDF HTML template.
 * Vertical style-sheet: accent header, palette, full typography roles,
 * shape/tokens, and logo variants — with print margins and no mid-block splits.
 */

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeHex(hex, fallback = '#64748B') {
  const raw = String(hex || '').trim();
  if (!raw) return fallback;
  let clean = raw.startsWith('#') ? raw.slice(1) : raw;
  if (clean.length === 3) {
    clean = clean
      .split('')
      .map((c) => c + c)
      .join('');
  }
  if (!/^[0-9a-fA-F]{6}$/.test(clean)) return fallback;
  return `#${clean.toUpperCase()}`;
}

function resolveRoleHex(data, role, fallback) {
  const id = data?.colorRoles?.[role];
  const color = (data?.colors || []).find((c) => c.id === id);
  return normalizeHex(color?.hex || fallback, fallback);
}

function roleLabelForColor(data, colorId) {
  const roles = data?.colorRoles || {};
  const labels = [];
  for (const [role, id] of Object.entries(roles)) {
    if (id === colorId) labels.push(role);
  }
  if (!labels.length) return '';
  const preferred = [
    'primary',
    'accent',
    'bg',
    'text',
    'secondary',
    'muted',
    'primaryDark',
    'bgDark',
    'textDark',
  ];
  const sorted = labels.sort((a, b) => {
    const ai = preferred.indexOf(a);
    const bi = preferred.indexOf(b);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });
  return sorted[0];
}

function googleFontsHref(families) {
  const unique = [
    ...new Set(families.map((f) => String(f || '').trim()).filter(Boolean)),
  ];
  if (!unique.length) return null;
  const query = unique
    .map(
      (f) =>
        `family=${encodeURIComponent(f).replace(/%20/g, '+')}:wght@300;400;500;600;700;800`
    )
    .join('&');
  return `https://fonts.googleapis.com/css2?${query}&display=swap`;
}

const LOGO_ORDER = [
  'primary',
  'secondary',
  'icon',
  'main',
  'light',
  'light-mode',
  'dark',
  'dark-mode',
  'black',
  'white',
  'with-name-adjacent',
  'with-name-below',
];

const FONT_ROLE_ORDER = ['heading', 'subheading', 'body', 'tertiary'];

const FONT_ROLE_LABELS = {
  heading: 'Heading',
  subheading: 'Subheading',
  body: 'Body',
  tertiary: 'Tertiary',
};

const FONT_ROLE_SAMPLES = {
  heading: 'The quick brown fox jumps over the lazy dog',
  subheading: 'Clear hierarchy for titles, decks, and section leads',
  body: 'Body copy stays readable across presentations, guidelines, and product UI.',
  tertiary: 'Supporting labels, captions, and compact UI text',
};

function formatLogoRole(role) {
  const map = {
    primary: 'Primary',
    secondary: 'Secondary',
    icon: 'Icon',
    main: 'Main',
    light: 'Light',
    'light-mode': 'Light mode',
    dark: 'Dark',
    'dark-mode': 'Dark mode',
    black: 'Black',
    white: 'White',
    'with-name-adjacent': 'With name (adjacent)',
    'with-name-below': 'With name (below)',
  };
  return map[role] || String(role || 'Logo').replace(/-/g, ' ');
}

function collectFontRoles(fonts = {}) {
  const roles = [];
  const seen = new Set();

  for (const key of FONT_ROLE_ORDER) {
    const face = fonts[key];
    if (!face || typeof face !== 'object') continue;
    const family = String(face.family || '').trim();
    if (!family) continue;
    seen.add(key);
    roles.push({
      key,
      label: FONT_ROLE_LABELS[key] || key,
      family,
      weight: Number(face.weight) || (key === 'heading' ? 700 : key === 'subheading' ? 600 : 400),
      sizePx: Number(face.sizePx) || (key === 'heading' ? 40 : key === 'subheading' ? 20 : 14),
      lineHeight: Number(face.lineHeight) || (key === 'heading' ? 1.2 : key === 'subheading' ? 1.4 : 1.6),
      sample: FONT_ROLE_SAMPLES[key] || FONT_ROLE_SAMPLES.body,
    });
  }

  // Any extra user-defined font roles
  for (const [key, face] of Object.entries(fonts)) {
    if (seen.has(key) || !face || typeof face !== 'object') continue;
    const family = String(face.family || '').trim();
    if (!family) continue;
    roles.push({
      key,
      label: String(key)
        .replace(/[-_]/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase()),
      family,
      weight: Number(face.weight) || 400,
      sizePx: Number(face.sizePx) || 14,
      lineHeight: Number(face.lineHeight) || 1.4,
      sample: FONT_ROLE_SAMPLES.body,
    });
  }

  return roles;
}

function buildLogoTiles(logos) {
  const list = [...(logos || [])];
  list.sort((a, b) => {
    const ai = LOGO_ORDER.indexOf(a.role);
    const bi = LOGO_ORDER.indexOf(b.role);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });
  if (!list.length) {
    return `<div class="empty-note">No logo variants uploaded yet.</div>`;
  }
  return list
    .map((logo) => {
      const darkBg = ['light', 'light-mode', 'white'].includes(logo.role);
      return `
        <div class="logo-tile avoid-break ${darkBg ? 'logo-tile--dark' : ''}">
          <div class="logo-tile__frame">
            ${
              logo.dataUrl
                ? `<img src="${logo.dataUrl}" alt="${escapeHtml(formatLogoRole(logo.role))}" />`
                : `<span class="logo-tile__missing">No image</span>`
            }
          </div>
          <div class="logo-tile__meta">
            <div class="logo-tile__role">${escapeHtml(formatLogoRole(logo.role))}</div>
            ${logo.name ? `<div class="logo-tile__name">${escapeHtml(logo.name)}</div>` : ''}
          </div>
        </div>`;
    })
    .join('');
}

function buildPaletteSwatches(data) {
  const colors = data?.colors || [];
  if (!colors.length) {
    return `<div class="empty-note">No colors defined.</div>`;
  }
  return colors
    .map((c) => {
      const hex = normalizeHex(c.hex);
      const role = roleLabelForColor(data, c.id);
      return `
        <div class="swatch avoid-break">
          <div class="swatch__chip" style="background:${escapeHtml(hex)}"></div>
          <div class="swatch__meta">
            ${role ? `<div class="swatch__role">${escapeHtml(role)}</div>` : ''}
            <div class="swatch__name">${escapeHtml(c.name || 'Color')}</div>
            <div class="swatch__hex">${escapeHtml(hex)}</div>
          </div>
        </div>`;
    })
    .join('');
}

function buildTypographyCards(fontRoles) {
  if (!fontRoles.length) {
    return `<div class="empty-note">No typography roles defined.</div>`;
  }
  return fontRoles
    .map((role) => {
      const sampleSize = Math.min(Math.max(role.sizePx * 0.55, 12), 28);
      return `
        <div class="type-card avoid-break">
          <div class="type-card__head">
            <span class="type-card__role">${escapeHtml(role.label)}</span>
            <span class="type-card__specs">
              ${escapeHtml(role.family)} · ${escapeHtml(String(role.weight))} ·
              ${escapeHtml(String(role.sizePx))}px · LH ${escapeHtml(String(role.lineHeight))}
            </span>
          </div>
          <div
            class="type-card__aa"
            style="font-family:'${escapeHtml(role.family)}', Inter, Helvetica, Arial, sans-serif; font-weight:${escapeHtml(String(role.weight))};"
          >Aa</div>
          <div
            class="type-card__sample"
            style="font-family:'${escapeHtml(role.family)}', Inter, Helvetica, Arial, sans-serif; font-weight:${escapeHtml(String(role.weight))}; font-size:${sampleSize}px; line-height:${escapeHtml(String(role.lineHeight))};"
          >${escapeHtml(role.sample)}</div>
          <div class="type-card__alphabet" style="font-family:'${escapeHtml(role.family)}', Inter, Helvetica, Arial, sans-serif; font-weight:${escapeHtml(String(role.weight))};">
            AaBbCcDdEeFf · 0123456789
          </div>
        </div>`;
    })
    .join('');
}

function buildTokenPills(data) {
  const usage = data?.usage || {};
  const clear = usage.logoClearSpace || '1.5× clear space';
  const minPx = usage.logoMinSizePx || 24;
  const pills = [
    { label: 'SCALE', value: '×1.333' },
    { label: 'GRID', value: '8px' },
    { label: 'RADIUS', value: '12px' },
    { label: 'CONTAINER', value: '1140px' },
    { label: 'CLEAR SPACE', value: String(clear) },
    { label: 'LOGO MIN', value: `${minPx}px` },
  ];
  return pills
    .map(
      (p) =>
        `<span class="token-pill avoid-break"><strong>${escapeHtml(p.label)}</strong> ${escapeHtml(p.value)}</span>`
    )
    .join('');
}

function pickPrimaryLogo(logos = []) {
  const order = ['primary', 'main', 'secondary', 'icon', 'with-name-adjacent', 'with-name-below'];
  for (const role of order) {
    const hit = logos.find((l) => l.role === role && l.dataUrl);
    if (hit) return hit;
  }
  return logos.find((l) => l.dataUrl) || null;
}

/**
 * @param {object} opts
 * @param {string} opts.kitName
 * @param {object} opts.data - brand kit data
 * @param {Array<{role:string,name?:string,dataUrl?:string}>} opts.logos
 * @param {string} [opts.subtitle]
 */
function buildGuidelinePdfHtml({ kitName, data, logos, subtitle }) {
  const primary = resolveRoleHex(data, 'primary', '#2563EB');
  const pageBg = resolveRoleHex(data, 'bg', '#F7F8FC');
  const text = resolveRoleHex(data, 'text', '#0F172A');
  const muted = resolveRoleHex(data, 'muted', '#64748B');

  const fontRoles = collectFontRoles(data?.fonts || {});
  const heading = fontRoles.find((r) => r.key === 'heading') || fontRoles[0];
  const displayFamily = heading?.family || 'Inter';
  const bodyFamily =
    fontRoles.find((r) => r.key === 'body')?.family || displayFamily;
  const tagline = data?.meta?.tagline || subtitle || '';
  const fontsHref = googleFontsHref(fontRoles.map((r) => r.family));
  const brandLogo = pickPrimaryLogo(logos);
  const brandTitle = kitName || 'Brand Kit';

  // Page content inset — applied via @page so EVERY printed page gets top/bottom padding
  const PAGE_MARGIN_TOP = 18;
  const PAGE_MARGIN_BOTTOM = 20;
  const PAGE_MARGIN_X = 16;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(kitName)} — Brand Guidelines</title>
  ${fontsHref ? `<link rel="stylesheet" href="${fontsHref}" />` : ''}
  <style>
    @page {
      size: A4;
      margin: ${PAGE_MARGIN_TOP}mm ${PAGE_MARGIN_X}mm ${PAGE_MARGIN_BOTTOM}mm ${PAGE_MARGIN_X}mm;
      background: ${escapeHtml(pageBg)};
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      background: ${escapeHtml(pageBg)};
      color: ${escapeHtml(text)};
      font-family: "${escapeHtml(bodyFamily)}", Inter, Helvetica, Arial, sans-serif;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .sheet {
      background: ${escapeHtml(pageBg)};
    }
    .content {
      padding: 0;
    }
    .avoid-break {
      break-inside: avoid;
      page-break-inside: avoid;
    }
    .section {
      margin: 0 0 4mm;
      padding: 7mm 0 9mm;
      border-bottom: 1px solid rgba(100, 116, 139, 0.22);
      -webkit-box-decoration-break: clone;
      box-decoration-break: clone;
    }
    .section:last-of-type {
      border-bottom: none;
      margin-bottom: 0;
    }
    .section__label {
      margin: 0 0 6mm;
      font-size: 11px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: ${escapeHtml(muted)};
      font-weight: 700;
      break-after: avoid;
      page-break-after: avoid;
    }
    .hero {
      background: ${escapeHtml(primary)};
      color: #fff;
      width: 100%;
      margin: 0 0 10mm;
      padding: 14mm 14mm 12mm;
      border-radius: 8mm;
      break-inside: avoid;
      page-break-inside: avoid;
      page-break-after: avoid;
      overflow: hidden;
    }
    .hero__brand {
      display: flex;
      align-items: center;
      gap: 5mm;
      margin: 0 0 8mm;
      min-width: 0;
    }
    .hero__logo {
      width: 18mm;
      height: 18mm;
      flex-shrink: 0;
      border-radius: 4mm;
      background: rgba(255, 255, 255, 0.16);
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
      padding: 2mm;
    }
    .hero__logo img {
      max-width: 100%;
      max-height: 100%;
      object-fit: contain;
    }
    .hero__name {
      margin: 0;
      font-size: 18px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      line-height: 1.2;
      word-break: break-word;
    }
    .hero__accent {
      font-size: 13px;
      opacity: 0.92;
      margin: 0 0 6mm;
      font-weight: 500;
      padding-left: 0;
    }
    .hero__font {
      font-family: "${escapeHtml(displayFamily)}", Inter, Helvetica, Arial, sans-serif;
      font-size: 44px;
      font-weight: 800;
      line-height: 1.05;
      letter-spacing: -0.03em;
      margin: 0;
      word-break: break-word;
    }
    .hero__kit {
      margin-top: 5mm;
      font-size: 13px;
      opacity: 0.9;
      font-weight: 500;
    }
    .palette {
      display: flex;
      flex-wrap: wrap;
      gap: 5mm;
    }
    .swatch { width: 28mm; }
    .swatch__chip {
      width: 28mm;
      height: 28mm;
      border-radius: 6mm;
      border: 1px solid rgba(15, 23, 42, 0.08);
    }
    .swatch__meta {
      margin-top: 2.5mm;
      font-size: 10px;
      line-height: 1.35;
      color: ${escapeHtml(muted)};
    }
    .swatch__role {
      text-transform: lowercase;
      font-weight: 600;
      color: ${escapeHtml(text)};
    }
    .swatch__name {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .swatch__hex {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .type-stack {
      display: flex;
      flex-direction: column;
      gap: 4mm;
    }
    .type-card {
      background: #fff;
      border: 1px solid rgba(15, 23, 42, 0.08);
      border-radius: 4mm;
      padding: 5mm 6mm;
    }
    .type-card__head {
      display: flex;
      flex-wrap: wrap;
      gap: 2mm 4mm;
      align-items: baseline;
      margin-bottom: 3mm;
    }
    .type-card__role {
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: ${escapeHtml(primary)};
    }
    .type-card__specs {
      font-size: 11px;
      color: ${escapeHtml(muted)};
    }
    .type-card__aa {
      font-size: 42px;
      line-height: 1;
      letter-spacing: -0.03em;
      color: ${escapeHtml(text)};
      margin-bottom: 2mm;
    }
    .type-card__sample {
      color: ${escapeHtml(text)};
      margin-bottom: 2mm;
    }
    .type-card__alphabet {
      font-size: 12px;
      color: ${escapeHtml(muted)};
    }
    .tokens {
      display: flex;
      flex-wrap: wrap;
      gap: 3mm;
      align-items: center;
    }
    .token-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      background: ${escapeHtml(primary)};
      color: #fff;
      border-radius: 999px;
      padding: 3.2mm 7mm;
      font-size: 12px;
      font-weight: 700;
    }
    .token-pill {
      display: inline-flex;
      align-items: center;
      gap: 2mm;
      border: 1px solid rgba(15, 23, 42, 0.12);
      background: #fff;
      border-radius: 999px;
      padding: 2.6mm 5mm;
      font-size: 11px;
      color: ${escapeHtml(text)};
      white-space: nowrap;
    }
    .token-pill strong {
      color: ${escapeHtml(muted)};
      font-weight: 700;
      letter-spacing: 0.04em;
      font-size: 10px;
    }
    .logos {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 5mm;
    }
    .logo-tile {
      background: #fff;
      border: 1px solid rgba(15, 23, 42, 0.08);
      border-radius: 5mm;
      overflow: hidden;
    }
    .logo-tile--dark .logo-tile__frame { background: #0F172A; }
    .logo-tile__frame {
      height: 34mm;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #F8FAFC;
      padding: 4mm;
    }
    .logo-tile__frame img {
      max-width: 100%;
      max-height: 26mm;
      object-fit: contain;
    }
    .logo-tile__missing {
      font-size: 11px;
      color: ${escapeHtml(muted)};
    }
    .logo-tile__meta { padding: 3mm 4mm 4mm; }
    .logo-tile__role {
      font-size: 12px;
      font-weight: 700;
      color: ${escapeHtml(text)};
    }
    .logo-tile__name {
      margin-top: 1mm;
      font-size: 10px;
      color: ${escapeHtml(muted)};
    }
    .empty-note {
      font-size: 12px;
      color: ${escapeHtml(muted)};
    }
    .footer {
      margin-top: 8mm;
      padding-bottom: 2mm;
      font-size: 10px;
      color: ${escapeHtml(muted)};
      break-inside: avoid;
      page-break-inside: avoid;
    }
  </style>
</head>
<body>
  <div class="sheet">
    <header class="hero avoid-break">
      <div class="hero__brand">
        ${
          brandLogo?.dataUrl
            ? `<div class="hero__logo"><img src="${brandLogo.dataUrl}" alt="${escapeHtml(brandTitle)} logo" /></div>`
            : ''
        }
        <h1 class="hero__name">${escapeHtml(brandTitle)}</h1>
      </div>
      <p class="hero__accent">accent · ${escapeHtml(primary)}</p>
      <p class="hero__font">${escapeHtml(displayFamily)}</p>
      ${tagline ? `<p class="hero__kit">${escapeHtml(tagline)}</p>` : ''}
    </header>

    <div class="content">
      <section class="section">
        <h2 class="section__label">Palette</h2>
        <div class="palette">
          ${buildPaletteSwatches(data)}
        </div>
      </section>

      <section class="section">
        <h2 class="section__label">Typography</h2>
        <div class="type-stack">
          ${buildTypographyCards(fontRoles)}
        </div>
      </section>

      <section class="section avoid-break">
        <h2 class="section__label">Shape &amp; tokens</h2>
        <div class="tokens">
          <span class="token-btn avoid-break">Button</span>
          ${buildTokenPills(data)}
        </div>
      </section>

      <section class="section">
        <h2 class="section__label">Logo variants</h2>
        <div class="logos">
          ${buildLogoTiles(logos)}
        </div>
      </section>

      <p class="footer">Generated by Athena Brand Kits · ${escapeHtml(new Date().toLocaleDateString())}</p>
    </div>
  </div>
</body>
</html>`;
}

module.exports = {
  buildGuidelinePdfHtml,
  collectFontRoles,
  pickPrimaryLogo,
  normalizeHex,
  formatLogoRole,
};
