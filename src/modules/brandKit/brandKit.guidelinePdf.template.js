/**
 * Brand guideline PDF HTML template.
 * Vertical style-sheet: accent header, palette, full typography roles,
 * shape/tokens, and logo variants — with print margins and no mid-block splits.
 */

const { googleFontsHref } = require('../../shared/fonts/googleFontsCss');

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

const FONT_ROLE_ORDER = ['heading', 'subheading', 'body', 'tertiary'];

const LOGO_ROLE_ALIASES = {
  primary: ['primary', 'main'],
  'with-name-below': ['with-name-below'],
  'with-name-adjacent': ['with-name-adjacent'],
  'with-name-below-dark': ['with-name-below-dark'],
  'with-name-adjacent-dark': ['with-name-adjacent-dark'],
  dark: ['dark', 'dark-mode'],
  light: ['light', 'light-mode'],
  white: ['white'],
  black: ['black'],
};

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
    'with-name-adjacent-dark': 'With name (adjacent, dark)',
    'with-name-below-dark': 'With name (below, dark)',
  };
  return map[role] || String(role || 'Logo').replace(/-/g, ' ');
}

function collectFontRoles(fonts = {}, data = {}) {
  const roles = [];
  const seen = new Set();
  const map = new Map((data?.colors || []).map((c) => [c.id, c.hex]));

  const hexFor = (face, mode) => {
    const colorRoles = data?.colorRoles || {};
    const id =
      mode === 'dark'
        ? face?.darkTextColorId || colorRoles.textDark || colorRoles.text
        : face?.lightTextColorId || colorRoles.text;
    return map.get(id) || (mode === 'dark' ? '#F8FAFC' : '#0F172A');
  };

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
      lightTextColor: hexFor(face, 'light'),
      darkTextColor: hexFor(face, 'dark'),
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
      lightTextColor: hexFor(face, 'light'),
      darkTextColor: hexFor(face, 'dark'),
    });
  }

  return roles;
}

function findLogoByRoles(logos = [], roles = []) {
  const wanted = new Set(roles.map((r) => String(r).toLowerCase()));
  return (
    logos.find((l) => wanted.has(String(l.role || '').toLowerCase()) && l.dataUrl) ||
    logos.find((l) => wanted.has(String(l.role || '').toLowerCase())) ||
    null
  );
}

function logoCellNeedsDarkBg(role) {
  const r = String(role || '').toLowerCase();
  return (
    r === 'light' ||
    r === 'light-mode' ||
    r === 'white' ||
    r === 'dark' ||
    r === 'dark-mode' ||
    r === 'with-name-below-dark' ||
    r === 'with-name-adjacent-dark'
  );
}

function buildLogoCell(logo, fallbackLabel, extraClass = '') {
  const role = logo?.role || fallbackLabel;
  const label = formatLogoRole(fallbackLabel || role);
  const darkBg = logoCellNeedsDarkBg(role) || logoCellNeedsDarkBg(fallbackLabel);
  const cls = ['logo-cell', 'avoid-break', darkBg ? 'logo-cell--dark' : '', extraClass]
    .filter(Boolean)
    .join(' ');
  return `
    <div class="${cls}">
      <div class="logo-cell__frame">
        ${
          logo?.dataUrl
            ? `<img src="${logo.dataUrl}" alt="${escapeHtml(label)}" />`
            : `<span class="logo-cell__missing">No image</span>`
        }
      </div>
      <div class="logo-cell__label">${escapeHtml(label)}</div>
    </div>`;
}

/**
 * Logo layout:
 * Top: primary (left) + 2×2 wordmark grid (light + dark lockups)
 * Bottom: dark | light | white | black
 */
function buildLogoLayout(logos) {
  const primary = findLogoByRoles(logos, LOGO_ROLE_ALIASES.primary);
  const wordmarkSlots = [
    ['with-name-below', findLogoByRoles(logos, LOGO_ROLE_ALIASES['with-name-below'])],
    ['with-name-adjacent', findLogoByRoles(logos, LOGO_ROLE_ALIASES['with-name-adjacent'])],
    ['with-name-below-dark', findLogoByRoles(logos, LOGO_ROLE_ALIASES['with-name-below-dark'])],
    [
      'with-name-adjacent-dark',
      findLogoByRoles(logos, LOGO_ROLE_ALIASES['with-name-adjacent-dark']),
    ],
  ];
  const dark = findLogoByRoles(logos, LOGO_ROLE_ALIASES.dark);
  const light = findLogoByRoles(logos, LOGO_ROLE_ALIASES.light);
  const white = findLogoByRoles(logos, LOGO_ROLE_ALIASES.white);
  const black = findLogoByRoles(logos, LOGO_ROLE_ALIASES.black);

  const hasAny = [primary, ...wordmarkSlots.map(([, l]) => l), dark, light, white, black].some(
    (l) => l?.dataUrl
  );
  if (!hasAny && !(logos || []).length) {
    return `<div class="empty-note">No logo variants uploaded yet.</div>`;
  }

  const wordmarkHtml = wordmarkSlots
    .filter(([, logo]) => logo)
    .map(([role, logo]) => buildLogoCell(logo, role))
    .join('');

  return `
    <div class="logos-layout">
      <div class="logos-top">
        ${buildLogoCell(primary, 'primary', 'logo-cell--primary')}
        ${
          wordmarkHtml
            ? `<div class="logo-wordmark-grid">${wordmarkHtml}</div>`
            : `<div class="logo-wordmark-grid logo-wordmark-grid--empty"><div class="empty-note">No wordmark lockups yet.</div></div>`
        }
      </div>
      <div class="logos-bottom">
        ${buildLogoCell(dark, 'dark')}
        ${buildLogoCell(light, 'light')}
        ${buildLogoCell(white, 'white')}
        ${buildLogoCell(black, 'black')}
      </div>
    </div>`;
}

function contrastInk(hex) {
  const clean = normalizeHex(hex, '#64748B').slice(1);
  const n = Number.parseInt(clean, 16);
  if (!Number.isFinite(n)) return '#0F172A';
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  const luma = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luma > 0.62 ? '#0F172A' : '#FFFFFF';
}

function resolveButtonPreview(data, kind = 'primary') {
  const colors = data?.colors || [];
  const roles = data?.colorRoles || {};
  const style = data?.buttons?.[kind] || {};
  const hexFor = (id, fallback) => {
    const match = colors.find((c) => c.id === id);
    return normalizeHex(match?.hex || fallback, fallback);
  };
  const primaryHex = resolveRoleHex(data, 'primary', '#2563EB');
  const bgHex = resolveRoleHex(data, 'bg', '#F8FAFC');
  const background = style.backgroundColorId
    ? hexFor(style.backgroundColorId, kind === 'secondary' ? bgHex : primaryHex)
    : kind === 'secondary'
      ? bgHex
      : primaryHex;
  const text = style.textColorId
    ? hexFor(style.textColorId, contrastInk(background))
    : kind === 'secondary'
      ? primaryHex
      : contrastInk(background);
  const border = style.borderColorId
    ? hexFor(style.borderColorId, background)
    : kind === 'secondary'
      ? primaryHex
      : background;
  const borderWidthPx = Number(style.borderWidthPx) || (kind === 'secondary' ? 1.5 : 0);
  const borderRadiusPx = Number(style.borderRadiusPx) || 10;
  const paddingYPx = Number(style.paddingYPx) || 10;
  const paddingXPx = Number(style.paddingXPx) || 20;
  const fontWeight = Number(style.fontWeight) || 600;
  const fontSizePx = Number(style.fontSizePx) || 14;
  const label = kind === 'secondary' ? 'Secondary' : 'Primary';
  return {
    label,
    background,
    text,
    border,
    borderWidthPx,
    borderRadiusPx,
    paddingYPx,
    paddingXPx,
    fontWeight,
    fontSizePx,
  };
}

function buildButtonsSection(data) {
  return ['primary', 'secondary']
    .map((kind) => {
      const b = resolveButtonPreview(data, kind);
      return `
        <div class="btn-preview avoid-break">
          <div class="btn-preview__label">${escapeHtml(b.label)}</div>
          <div
            class="btn-preview__btn"
            style="
              background:${escapeHtml(b.background)};
              color:${escapeHtml(b.text)};
              border:${escapeHtml(String(b.borderWidthPx))}px solid ${escapeHtml(b.border)};
              border-radius:${escapeHtml(String(b.borderRadiusPx))}px;
              padding:${escapeHtml(String(b.paddingYPx))}px ${escapeHtml(String(b.paddingXPx))}px;
              font-weight:${escapeHtml(String(b.fontWeight))};
              font-size:${escapeHtml(String(b.fontSizePx))}px;
            "
          >${escapeHtml(b.label)} button</div>
          <div class="btn-preview__meta">
            ${escapeHtml(b.background)} · radius ${escapeHtml(String(b.borderRadiusPx))}px ·
            ${escapeHtml(String(b.fontWeight))} / ${escapeHtml(String(b.fontSizePx))}px
          </div>
        </div>`;
    })
    .join('');
}

function buildMockupTiles(mockups) {
  const list = [...(mockups || [])].filter((m) => m?.dataUrl);
  if (!list.length) {
    return `<div class="empty-note">No product photos with brand logo yet.</div>`;
  }
  return list
    .map((m) => {
      const label = m.name || m.role || m.templateId || 'Mockup';
      return `
        <div class="mockup-tile avoid-break">
          <div class="mockup-tile__frame">
            <img src="${m.dataUrl}" alt="${escapeHtml(label)}" />
          </div>
          <div class="mockup-tile__label">${escapeHtml(label)}</div>
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

function buildTypeCardInner(role, data) {
  const sampleSize = Math.min(Math.max(role.sizePx * 0.42, 10), 18);
  const fontStack = `'${escapeHtml(role.family)}', Inter, Helvetica, Arial, sans-serif`;
  const lightBg = resolveRoleHex(data, 'bg', '#FFFFFF');
  const darkBg = resolveRoleHex(data, 'bgDark', '#0F172A');
  const lightColor = normalizeHex(role.lightTextColor, '#0F172A');
  const darkColor = normalizeHex(role.darkTextColor, '#F8FAFC');

  return `
    <div class="type-card__body">
      <div class="type-card__head">
        <span class="type-card__role">${escapeHtml(role.label)}</span>
      </div>
      <div class="type-card__meta">
        <span>${escapeHtml(role.family)}</span>
        <span>${escapeHtml(String(role.weight))}</span>
        <span>${escapeHtml(String(role.sizePx))}px</span>
        <span>LH ${escapeHtml(String(role.lineHeight))}</span>
      </div>
      <div
        class="type-card__aa"
        style="font-family:${fontStack}; font-weight:${escapeHtml(String(role.weight))};"
      >Aa</div>
      <div class="type-theme-row">
        <div class="type-theme type-theme--light" style="background:${escapeHtml(lightBg)};">
          <span class="type-theme__label">Light</span>
          <p
            class="type-theme__sample"
            style="font-family:${fontStack}; font-weight:${escapeHtml(String(role.weight))}; font-size:${sampleSize}px; line-height:${escapeHtml(String(role.lineHeight))}; color:${escapeHtml(lightColor)};"
          >${escapeHtml(role.sample)}</p>
          <span class="type-theme__hex">${escapeHtml(lightColor)}</span>
        </div>
        <div class="type-theme type-theme--dark" style="background:${escapeHtml(darkBg)};">
          <span class="type-theme__label">Dark</span>
          <p
            class="type-theme__sample"
            style="font-family:${fontStack}; font-weight:${escapeHtml(String(role.weight))}; font-size:${sampleSize}px; line-height:${escapeHtml(String(role.lineHeight))}; color:${escapeHtml(darkColor)};"
          >${escapeHtml(role.sample)}</p>
          <span class="type-theme__hex">${escapeHtml(darkColor)}</span>
        </div>
      </div>
      <div class="type-card__alphabet" style="font-family:${fontStack}; font-weight:${escapeHtml(String(role.weight))};">
        AaBbCcDdEeFf · 0123456789
      </div>
    </div>`;
}

function buildTypographyCards(fontRoles, data) {
  if (!fontRoles.length) {
    return `<div class="empty-note">No typography roles defined.</div>`;
  }

  return `
    <div class="type-stack">
      ${fontRoles
        .map(
          (role) => `
        <div class="type-card avoid-break">
          ${buildTypeCardInner(role, data)}
        </div>`
        )
        .join('')}
    </div>`;
}

function buildColorThemesSection(data) {
  const bg = resolveRoleHex(data, 'bg', '#F8FAFC');
  const text = resolveRoleHex(data, 'text', '#0F172A');
  const primary = resolveRoleHex(data, 'primary', '#2563EB');
  const accent = resolveRoleHex(data, 'accent', primary);
  const bgDark = resolveRoleHex(data, 'bgDark', '#0F172A');
  const textDark = resolveRoleHex(data, 'textDark', '#F8FAFC');
  const primaryDark = resolveRoleHex(data, 'primaryDark', primary);

  const swatch = (hex, label, fg) => {
    const ink = fg || contrastInk(hex);
    return `
      <div class="theme-swatch avoid-break">
        <div class="theme-swatch__chip" style="background:${escapeHtml(hex)}; color:${escapeHtml(ink)};">
          <span>${escapeHtml(label)}</span>
        </div>
        <div class="theme-swatch__hex">${escapeHtml(hex)}</div>
      </div>`;
  };

  return `
    <div class="theme-panels">
      <div class="theme-panel avoid-break" style="background:${escapeHtml(bg)}; color:${escapeHtml(text)};">
        <div class="theme-panel__title">Light theme</div>
        <div class="theme-panel__swatches">
          ${swatch(bg, 'bg', text)}
          ${swatch(text, 'text', bg)}
          ${swatch(primary, 'primary', contrastInk(primary))}
          ${swatch(accent, 'accent', contrastInk(accent))}
        </div>
        <p class="theme-panel__sample">Sample text on the light background for UI and print.</p>
      </div>
      <div class="theme-panel theme-panel--dark avoid-break" style="background:${escapeHtml(bgDark)}; color:${escapeHtml(textDark)};">
        <div class="theme-panel__title">Dark theme</div>
        <div class="theme-panel__swatches">
          ${swatch(bgDark, 'bg', textDark)}
          ${swatch(textDark, 'text', bgDark)}
          ${swatch(primaryDark, 'primary', contrastInk(primaryDark))}
        </div>
        <p class="theme-panel__sample">Sample text on the dark background for UI and print.</p>
      </div>
    </div>`;
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
  return (
    findLogoByRoles(logos, LOGO_ROLE_ALIASES.primary) ||
    logos.find((l) => l.dataUrl) ||
    null
  );
}

/**
 * @param {object} opts
 * @param {string} opts.kitName
 * @param {object} opts.data - brand kit data
 * @param {Array<{role:string,name?:string,dataUrl?:string}>} opts.logos
 * @param {Array<{role?:string,name?:string,templateId?:string,dataUrl?:string}>} [opts.mockups]
 * @param {string} [opts.subtitle]
 */
function buildGuidelinePdfHtml({ kitName, data, logos, mockups, subtitle }) {
  const primary = resolveRoleHex(data, 'primary', '#2563EB');
  // Page background stays white / near-white regardless of brand bg role
  const pageBg = '#FFFFFF';
  const text = resolveRoleHex(data, 'text', '#0F172A');
  const muted = resolveRoleHex(data, 'muted', '#64748B');

  const fontRoles = collectFontRoles(data?.fonts || {}, data);
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
      gap: 5mm;
    }
    .type-card {
      background: #FAFAFA;
      border: 1px solid rgba(15, 23, 42, 0.08);
      border-radius: 5mm;
      padding: 5mm 6mm;
      overflow: hidden;
    }
    .type-card__body {
      display: flex;
      flex-direction: column;
      gap: 2.5mm;
    }
    .type-card__head {
      display: flex;
      align-items: baseline;
    }
    .type-card__role {
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: ${escapeHtml(primary)};
    }
    .type-card__meta {
      display: flex;
      flex-wrap: wrap;
      gap: 2mm 4mm;
      font-size: 10px;
      color: ${escapeHtml(muted)};
    }
    .type-card__aa {
      font-size: 36px;
      line-height: 1;
      letter-spacing: -0.03em;
      color: ${escapeHtml(text)};
    }
    .type-theme-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 4mm;
      margin: 1mm 0 2mm;
    }
    .type-theme {
      border-radius: 3mm;
      padding: 3mm 4mm;
      border: 1px solid rgba(15, 23, 42, 0.1);
      min-height: 22mm;
      display: flex;
      flex-direction: column;
      gap: 2mm;
    }
    .type-theme__label {
      font-size: 9px;
      font-weight: 800;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      opacity: 0.72;
    }
    .type-theme__sample {
      margin: 0;
      flex: 1;
      word-break: break-word;
    }
    .type-theme__hex {
      font-size: 9px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      opacity: 0.8;
    }
    .type-card__alphabet {
      font-size: 11px;
      color: ${escapeHtml(muted)};
    }
    .theme-panels {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 5mm;
      margin-bottom: 6mm;
    }
    .theme-panel {
      border-radius: 5mm;
      padding: 5mm 6mm;
      border: 1px solid rgba(15, 23, 42, 0.1);
    }
    .theme-panel__title {
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 4mm;
      opacity: 0.85;
    }
    .theme-panel__swatches {
      display: flex;
      flex-wrap: wrap;
      gap: 3mm;
      margin-bottom: 4mm;
    }
    .theme-swatch {
      width: 22mm;
    }
    .theme-swatch__chip {
      height: 14mm;
      border-radius: 3mm;
      display: flex;
      align-items: flex-end;
      padding: 2mm;
      font-size: 8px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      border: 1px solid rgba(15, 23, 42, 0.08);
    }
    .theme-swatch__hex {
      margin-top: 1.5mm;
      font-size: 9px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      opacity: 0.85;
    }
    .theme-panel__sample {
      margin: 0;
      font-size: 12px;
      line-height: 1.45;
    }
    .tokens {
      display: flex;
      flex-wrap: wrap;
      gap: 3mm;
      align-items: center;
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
    .buttons-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6mm;
    }
    .btn-preview {
      background: #FAFAFA;
      border: 1px solid rgba(15, 23, 42, 0.08);
      border-radius: 4mm;
      padding: 5mm 6mm;
    }
    .btn-preview__label {
      font-size: 10px;
      font-weight: 800;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: ${escapeHtml(muted)};
      margin-bottom: 4mm;
    }
    .btn-preview__btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      line-height: 1.2;
      white-space: nowrap;
    }
    .btn-preview__meta {
      margin-top: 4mm;
      font-size: 10px;
      color: ${escapeHtml(muted)};
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .logos-layout {
      display: flex;
      flex-direction: column;
      gap: 5mm;
    }
    .logos-top {
      display: grid;
      grid-template-columns: 1.35fr 1fr;
      gap: 5mm;
      align-items: start;
    }
    .logo-wordmark-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 4mm;
      min-width: 0;
    }
    .logo-wordmark-grid--empty {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 40mm;
      background: #FAFAFA;
      border: 1px dashed rgba(15, 23, 42, 0.12);
      border-radius: 5mm;
      padding: 4mm;
    }
    .logos-bottom {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 5mm;
    }
    .logo-cell {
      width: 100%;
      background: #fff;
      border: 1px solid rgba(15, 23, 42, 0.08);
      border-radius: 5mm;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .logo-cell--primary {
      height: 100%;
      min-height: 0;
    }
    .logo-cell__frame {
      aspect-ratio: 1 / 1;
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #FAFAFA;
      padding: 4mm;
    }
    .logo-cell--primary .logo-cell__frame {
      aspect-ratio: auto;
      min-height: 48mm;
      max-height: 72mm;
    }
    .logo-wordmark-grid .logo-cell__frame {
      aspect-ratio: 4 / 3;
      min-height: 0;
    }
    .logo-cell--dark .logo-cell__frame {
      background: #0F172A;
    }
    .logo-cell__frame img {
      max-width: 78%;
      max-height: 78%;
      object-fit: contain;
    }
    .logo-cell__missing {
      font-size: 10px;
      color: ${escapeHtml(muted)};
      text-align: center;
      padding: 2mm;
    }
    .logo-cell__label {
      padding: 2.5mm 3mm 3.2mm;
      font-size: 10px;
      font-weight: 700;
      color: ${escapeHtml(text)};
      text-align: center;
      line-height: 1.25;
    }
    .mockups {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 5mm;
    }
    .mockup-tile {
      background: #fff;
      border: 1px solid rgba(15, 23, 42, 0.08);
      border-radius: 4mm;
      overflow: hidden;
    }
    .mockup-tile__frame {
      aspect-ratio: 1 / 1;
      width: 100%;
      background: #FAFAFA;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }
    .mockup-tile__frame img {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .mockup-tile__label {
      padding: 2.5mm 3mm 3mm;
      font-size: 10px;
      font-weight: 700;
      color: ${escapeHtml(text)};
      text-align: center;
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
        <h2 class="section__label">Color themes</h2>
        ${buildColorThemesSection(data)}
        <h2 class="section__label" style="margin-top: 6mm;">Palette</h2>
        <div class="palette">
          ${buildPaletteSwatches(data)}
        </div>
      </section>

      <section class="section">
        <h2 class="section__label">Typography</h2>
        ${buildTypographyCards(fontRoles, data)}
      </section>

      <section class="section">
        <h2 class="section__label">Buttons</h2>
        <div class="buttons-row">
          ${buildButtonsSection(data)}
        </div>
      </section>

      <section class="section avoid-break">
        <h2 class="section__label">Shape &amp; tokens</h2>
        <div class="tokens">
          ${buildTokenPills(data)}
        </div>
      </section>

      <section class="section">
        <h2 class="section__label">Logo variants</h2>
        ${buildLogoLayout(logos)}
      </section>

      <section class="section">
        <h2 class="section__label">Product photos with brand logo</h2>
        <div class="mockups">
          ${buildMockupTiles(mockups)}
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
