/**
 * Shared device chrome + screenshot prompt helpers.
 */

function parseHexLum(hex) {
  const s = String(hex || '').replace('#', '').trim();
  if (s.length !== 6) return null;
  const r = parseInt(s.slice(0, 2), 16) / 255;
  const g = parseInt(s.slice(2, 4), 16) / 255;
  const b = parseInt(s.slice(4, 6), 16) / 255;
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function isDarkThemeTokens(themeTokens = {}) {
  const appearance = String(themeTokens?.appearance || '').toLowerCase();
  if (appearance === 'dark') return true;
  if (appearance === 'light') return false;
  const bg = themeTokens?.palette?.bg || themeTokens?.palette?.background;
  const lum = parseHexLum(bg);
  return lum != null && lum < 0.45;
}

/**
 * Device bezel / chassis colors. Dark decks use mid-grey frames (not black).
 */
function deviceFrameChromeColors(themeTokens = {}, kind = 'phone') {
  const dark = isDarkThemeTokens(themeTokens);
  const isPhone = kind === 'phone' || kind === 'phone_landscape';
  if (dark) {
    return {
      fill: isPhone ? '#9CA3AF' : '#D1D5DB',
      stroke: '#6B7280',
      strokeWidth: isPhone ? 0 : 3,
    };
  }
  return {
    fill: isPhone ? '#1e293b' : '#f8fafc',
    stroke: '#0f172a',
    strokeWidth: isPhone ? 0 : 4,
  };
}

/** Apply chrome colors onto an existing device_frame element. */
function paintDeviceFrameElement(el, themeTokens = {}) {
  if (!el || (el.role !== 'device_frame' && !/FRAME$/i.test(String(el.slotId || '')))) return el;
  const kind = String(el.content?.deviceFrame || 'phone').toLowerCase();
  const chrome = deviceFrameChromeColors(themeTokens, kind);
  return {
    ...el,
    content: {
      ...(el.content || {}),
      // Always string fills — object fills are for gradients; chrome is solid hex.
      fill: chrome.fill,
      stroke: chrome.stroke,
      strokeWidth: chrome.strokeWidth,
    },
  };
}

/**
 * Classify device screen slot → UI screenshot type.
 * phone/watch → mobile app UI; tablet/laptop → website UI.
 */
function deviceScreenUiKind(slotId = '', layoutId = '') {
  const id = String(slotId || '').toUpperCase();
  const layout = String(layoutId || '').toLowerCase();
  if (/WATCH/.test(id)) return 'watch_app';
  if (/TABLET|LAPTOP/.test(id)) return 'website';
  if (/PHONE/.test(id)) return 'mobile_app';
  if (/^DEVICE_IMAGE/.test(id)) {
    if (/tablet|laptop/.test(layout)) return 'website';
    return 'mobile_app';
  }
  return null;
}

function isDeviceScreenSlotId(slotId = '') {
  return Boolean(deviceScreenUiKind(slotId));
}

function deviceUiScreenshotDirective(slotId = '', layoutId = '') {
  const kind = deviceScreenUiKind(slotId, layoutId);
  if (kind === 'website') {
    return 'Flat website / web-app UI screenshot only (browser page layout, nav, content panels) — no laptop or tablet hardware, no bezel, no photographic scene';
  }
  if (kind === 'watch_app') {
    return 'Flat smartwatch app UI screenshot only (compact circular/square face UI) — no watch hardware, no bezel';
  }
  if (kind === 'mobile_app') {
    return 'Flat mobile app UI screenshot only (phone app screens: lists, maps, cards, tabs) — no phone hardware, no bezel, no photographic scene';
  }
  return 'Flat UI screenshot only — no device hardware or bezel';
}

/** Dark readable ink for text sitting on light bands/surfaces. */
const ON_LIGHT_SURFACE_TEXT = '#111827';
const ON_LIGHT_SURFACE_MUTED = '#4B5563';

module.exports = {
  isDarkThemeTokens,
  deviceFrameChromeColors,
  paintDeviceFrameElement,
  deviceScreenUiKind,
  isDeviceScreenSlotId,
  deviceUiScreenshotDirective,
  ON_LIGHT_SURFACE_TEXT,
  ON_LIGHT_SURFACE_MUTED,
  parseHexLum,
};
