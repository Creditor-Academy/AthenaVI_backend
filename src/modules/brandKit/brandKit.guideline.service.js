const crypto = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const presentationDao = require('../presentation/presentation.dao');
const s3Service = require('../s3/s3.service');
const brandKitDao = require('./brandKit.dao');
const brandKitCredit = require('./brandKitCredit.service');
const brandKitService = require('./brandKit.service');
const { injectBrandLogo } = require('../presentation/layoutToElements');

const CANVAS = { width: 1920, height: 1080 };
const MARGIN = 80;
const GRID_GAP = 24;

function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

function textEl(id, text, placement, style = {}) {
  return {
    id: newId(id),
    type: 'text',
    layer: style.layer ?? 2,
    placement,
    content: {
      text: String(text || ''),
      fontSize: style.fontSize ?? 24,
      bold: style.bold ?? false,
      fontWeight: style.fontWeight ?? (style.bold ? 700 : 400),
      align: style.align ?? 'left',
      colorRole: style.colorRole ?? 'text',
      lineHeight: style.lineHeight ?? 1.3,
      fontFamily: style.fontFamily ?? null,
    },
    role: style.role ?? id,
  };
}

function shapeEl(id, placement, fillRole, layer = 0) {
  return {
    id: newId(id),
    type: 'shape',
    layer,
    placement,
    content: {
      shape: 'rect',
      fill: { type: 'solid', colorRole: fillRole },
    },
    role: id,
  };
}

function imageEl(id, url, placement, role = 'image') {
  return {
    id: newId(id),
    type: 'image',
    layer: 3,
    placement,
    content: { url, fit: 'contain', alt: role },
    role,
  };
}

async function resolveMediaUrl(media) {
  if (!media?.s3Key) return media?.url || null;
  try {
    return await s3Service.getPresignedGetUrl(media.s3Key, 3600);
  } catch {
    return media.url || s3Service.buildPublicUrl(media.s3Key);
  }
}

async function kitWithPresignedMedia(kit) {
  const media = await Promise.all(
    (kit.media || []).map(async (m) => ({
      ...m,
      url: await resolveMediaUrl(m),
    }))
  );
  return { ...kit, media };
}

function assertGuidelineReady(kit) {
  brandKitService.validateBrandKitData(kit.data);
  if (!String(kit.name || '').trim()) {
    throw new AppError('Brand kit name is required to generate guidelines', 400);
  }
}

// 1. Cover Slide
function buildCoverSlide(kit, themeTokens) {
  const tagline = kit.data?.meta?.tagline || '';
  const palette = themeTokens.palette || {};
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  let doc = {
    version: 1,
    canvas: CANVAS,
    elements: [
      shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
      shapeEl('accent_bar', { x: 0, y: 0, width: 24, height: CANVAS.height, rotation: 0, opacity: 1 }, 'primary', 1),
      textEl('brand_name', kit.name, { x: MARGIN + 40, y: 340, width: 1300, height: 110, rotation: 0, opacity: 1 }, {
        fontSize: 72,
        bold: true,
        fontWeight: themeTokens.fonts?.headingWeight ?? 700,
        fontFamily: themeTokens.fonts?.heading,
        role: 'title',
        layer: 2,
      }),
      textEl('guideline_title', 'Brand Identity & Design Guidelines', { x: MARGIN + 40, y: 470, width: 900, height: 50, rotation: 0, opacity: 1 }, {
        fontSize: 32,
        colorRole: 'primary',
        role: 'subtitle',
      }),
    ],
  };

  if (tagline) {
    doc.elements.push(
      textEl('tagline', tagline, { x: MARGIN + 40, y: 550, width: 1100, height: 48, rotation: 0, opacity: 1 }, {
        fontSize: 22,
        colorRole: 'muted',
        role: 'tagline',
      })
    );
  }

  doc.elements.push(
    textEl('date', `Published: ${dateStr}`, { x: MARGIN + 40, y: 960, width: 400, height: 32, rotation: 0, opacity: 1 }, {
      fontSize: 14,
      colorRole: 'muted',
      role: 'caption',
    })
  );

  const logo = brandKitService.pickLogoForBackground(themeTokens);
  if (logo?.url || logo?.s3Key) {
    const url = logo.url || s3Service.buildPublicUrl(logo.s3Key);
    doc = injectBrandLogo(doc, { ...logo, url }, { contentType: 'title', force: true });
  }

  return {
    order: 1,
    contentType: 'title',
    layoutId: 'brand_guideline_cover',
    content: { title: kit.name, subtitle: tagline, background: { color: palette.bg } },
    elements: doc,
  };
}

// 2. Mission & Voice Slide
function buildMissionVoiceSlide(kit, themeTokens) {
  const data = kit.data || {};
  const voice = data.voice || {};
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Brand Mission & Voice Pillars', { x: MARGIN, y: MARGIN, width: 1000, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
  ];

  const cardW = 560;
  const cardH = 320;
  
  // Mission Card
  elements.push(shapeEl('card_mission', { x: MARGIN, y: 180, width: cardW, height: cardH, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('label_mission', 'BRAND MISSION', { x: MARGIN + 24, y: 204, width: cardW - 48, height: 28, rotation: 0, opacity: 1 }, { fontSize: 13, colorRole: 'primary', bold: true, role: 'caption' }));
  elements.push(textEl('val_mission', data.meta?.tagline || 'Empowering communication through high-impact brand design.', { x: MARGIN + 24, y: 244, width: cardW - 48, height: 220, rotation: 0, opacity: 1 }, { fontSize: 20, lineHeight: 1.4, role: 'body' }));

  // Tone Card
  elements.push(shapeEl('card_tone', { x: MARGIN + cardW + GRID_GAP, y: 180, width: cardW, height: cardH, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('label_tone', 'TONE OF VOICE', { x: MARGIN + cardW + GRID_GAP + 24, y: 204, width: cardW - 48, height: 28, rotation: 0, opacity: 1 }, { fontSize: 13, colorRole: 'primary', bold: true, role: 'caption' }));
  elements.push(textEl('val_tone', voice.tone || 'Professional, confident, clear, and inspiring.', { x: MARGIN + cardW + GRID_GAP + 24, y: 244, width: cardW - 48, height: 220, rotation: 0, opacity: 1 }, { fontSize: 20, lineHeight: 1.4, role: 'body' }));

  // Audience Card
  elements.push(shapeEl('card_aud', { x: MARGIN + (cardW + GRID_GAP) * 2, y: 180, width: cardW, height: cardH, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('label_aud', 'TARGET AUDIENCE', { x: MARGIN + (cardW + GRID_GAP) * 2 + 24, y: 204, width: cardW - 48, height: 28, rotation: 0, opacity: 1 }, { fontSize: 13, colorRole: 'primary', bold: true, role: 'caption' }));
  elements.push(textEl('val_aud', voice.audience || 'Enterprise leaders, creative professionals, and decision makers.', { x: MARGIN + (cardW + GRID_GAP) * 2 + 24, y: 244, width: cardW - 48, height: 220, rotation: 0, opacity: 1 }, { fontSize: 20, lineHeight: 1.4, role: 'body' }));

  // Voice Principles Section
  elements.push(shapeEl('card_principles', { x: MARGIN, y: 540, width: 1760, height: 420, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('label_principles', 'BRAND VOICE PRINCIPLES & APPLICATION', { x: MARGIN + 32, y: 570, width: 1700, height: 32, rotation: 0, opacity: 1 }, { fontSize: 14, colorRole: 'primary', bold: true, role: 'caption' }));

  const dosText = Array.isArray(voice.dos) && voice.dos.length ? voice.dos.map(d => `✓ ${d}`).join('\n') : '✓ Be direct, articulate, and value-focused.\n✓ Maintain visual consistency across decks & collaterals.';
  const dontsText = Array.isArray(voice.donts) && voice.donts.length ? voice.donts.map(d => `✕ ${d}`).join('\n') : '✕ Avoid jargon, overly complex phrasing, or cluttered visual elements.\n✕ Do not alter official brand palette hex values.';

  elements.push(textEl('val_dos', `DO'S:\n${dosText}`, { x: MARGIN + 32, y: 620, width: 830, height: 310, rotation: 0, opacity: 1 }, { fontSize: 16, lineHeight: 1.5, role: 'body' }));
  elements.push(textEl('val_donts', `DON'TS:\n${dontsText}`, { x: MARGIN + 900, y: 620, width: 830, height: 310, rotation: 0, opacity: 1 }, { fontSize: 16, lineHeight: 1.5, role: 'body' }));

  return {
    order: 2,
    contentType: 'image+text',
    layoutId: 'brand_guideline_mission_voice',
    content: { title: 'Brand Mission & Voice Pillars' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

// Helper for color swatches
function colorSwatchElements(startY, colors, roles, prefix) {
  const elements = [];
  const swatchW = 380;
  const swatchH = 150;
  let x = MARGIN;
  const entries = [
    { roleKey: prefix ? `primary${prefix}` : 'primary', label: `Primary${prefix ? ' (Dark)' : ' (Light)'}` },
    { roleKey: prefix ? `bg${prefix}` : 'bg', label: `Background${prefix ? ' (Dark)' : ' (Light)'}` },
    { roleKey: prefix ? `text${prefix}` : 'text', label: `Text${prefix ? ' (Dark)' : ' (Light)'}` },
    { roleKey: prefix ? `accent${prefix}` : 'accent', label: 'Accent' },
  ];

  const map = brandKitService.colorMap({ colors });
  for (const entry of entries) {
    const colorId = roles[entry.roleKey] || roles[entry.roleKey.replace('Dark', '')];
    const hex = brandKitService.resolveHex(map, colorId, '#3B82F6');
    elements.push(
      shapeEl(`swatch_${entry.roleKey}`, { x, y: startY, width: swatchW, height: swatchH, rotation: 0, opacity: 1 }, 'surface', 1)
    );
    elements.push({
      id: newId('swatch_color'),
      type: 'shape',
      layer: 2,
      placement: { x: x + 16, y: startY + 16, width: swatchW - 32, height: 72, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: { type: 'solid', color: hex } },
      role: 'accent',
    });
    elements.push(
      textEl(`swatch_label_${entry.roleKey}`, `${entry.label}\nHEX: ${hex}`, {
        x: x + 16,
        y: startY + 98,
        width: swatchW - 32,
        height: 40,
        rotation: 0,
        opacity: 1,
      }, { fontSize: 13, role: 'caption', bold: true })
    );
    x += swatchW + GRID_GAP;
  }
  return elements;
}

// 3. Colors Slide
function buildColorsSlide(kit, themeTokens) {
  const data = kit.data || {};
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Brand Color Palette & Mode Specs', { x: MARGIN, y: MARGIN, width: 1000, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
    textEl('section_light', 'LIGHT MODE PALETTE', { x: MARGIN, y: 180, width: 400, height: 32, rotation: 0, opacity: 1 }, {
      fontSize: 16,
      colorRole: 'primary',
      bold: true,
      role: 'subtitle',
    }),
    ...colorSwatchElements(220, data.colors, data.colorRoles || {}, ''),
  ];

  elements.push(
    textEl('section_dark', 'DARK MODE PALETTE', { x: MARGIN, y: 440, width: 400, height: 32, rotation: 0, opacity: 1 }, {
      fontSize: 16,
      colorRole: 'primary',
      bold: true,
      role: 'subtitle',
    })
  );
  elements.push(...colorSwatchElements(480, data.colors, data.colorRoles || {}, 'Dark'));

  return {
    order: 3,
    contentType: 'section_divider',
    layoutId: 'brand_guideline_colors',
    content: { title: 'Brand Color Palette & Mode Specs' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

// 4. Logo System Slide
function buildLogosSlide(kit, themeTokens) {
  const logos = (kit.media || []).filter((m) => m.kind === 'logo');
  const roles = [
    'primary',
    'light',
    'dark',
    'with-name-below',
    'with-name-adjacent',
    'with-name-below-dark',
    'with-name-adjacent-dark',
    'monochrome',
  ];
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Logo Architecture & Variants', { x: MARGIN, y: MARGIN, width: 900, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
  ];

  const cardW = 380;
  const cardH = 190;
  let col = 0;
  let row = 0;
  const cols = 4;
  const startX = MARGIN;
  const startY = 180;

  for (const role of roles) {
    const x = startX + col * (cardW + GRID_GAP);
    const y = startY + row * (cardH + GRID_GAP);
    const media =
      logos.find((m) => m.role === role) ||
      (role === 'light' ? logos.find((m) => m.role === 'light-mode') : null) ||
      (role === 'dark' ? logos.find((m) => m.role === 'dark-mode') : null) ||
      (role === 'monochrome' ? logos.find((m) => m.role === 'black' || m.role === 'white') : null);
    
    const isDarkBg = role.includes('dark') || role === 'dark';
    
    elements.push(
      shapeEl(`card_${role}`, { x, y, width: cardW, height: cardH, rotation: 0, opacity: 1 }, isDarkBg ? 'primary' : 'surface', 1)
    );
    elements.push(
      textEl(`role_${role}`, role.replace(/-/g, ' ').toUpperCase(), {
        x: x + 16,
        y: y + 12,
        width: cardW - 32,
        height: 24,
        rotation: 0,
        opacity: 1,
      }, { fontSize: 11, colorRole: isDarkBg ? 'bg' : 'muted', role: 'caption', bold: true })
    );
    if (media && media.url) {
      elements.push(
        imageEl(`logo_${role}`, media.url, {
          x: x + 24,
          y: y + 40,
          width: cardW - 48,
          height: cardH - 56,
          rotation: 0,
          opacity: 1,
        }, role)
      );
    } else {
      elements.push(
        textEl(`missing_${role}`, 'Standard Variant', {
          x: x + 16,
          y: y + 80,
          width: cardW - 32,
          height: 40,
          rotation: 0,
          opacity: 1,
        }, { fontSize: 14, colorRole: isDarkBg ? 'bg' : 'muted', align: 'center', role: 'caption' })
      );
    }
    col += 1;
    if (col >= cols) {
      col = 0;
      row += 1;
    }
  }

  const clearSpace = kit.data?.usage?.logoClearSpace || 'Minimum clear space equal to 1x height of logo mark.';
  elements.push(shapeEl('clear_bg', { x: MARGIN, y: 640, width: 1760, height: 320, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('clear_title', 'LOGO USAGE & CLEAR SPACE RULES', { x: MARGIN + 32, y: 664, width: 1700, height: 28, rotation: 0, opacity: 1 }, { fontSize: 14, colorRole: 'primary', bold: true, role: 'caption' }));
  elements.push(textEl('clear_desc', `• Clear Space: ${clearSpace}\n• Minimum Digital Size: 32px height for favicon/icon, 120px width for primary lockup.\n• Proportions: Never stretch, distort, re-color, or rotate official brand logomarks.\n• Contrast: Always ensure adequate contrast against background surfaces.`, { x: MARGIN + 32, y: 704, width: 1700, height: 220, rotation: 0, opacity: 1 }, { fontSize: 16, lineHeight: 1.5, role: 'body' }));

  return {
    order: 4,
    contentType: 'grid',
    layoutId: 'brand_guideline_logos',
    content: { title: 'Logo Architecture & Variants' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

// 5. Typography Slide
function buildTypographySlide(kit, themeTokens) {
  const fonts = kit.data?.fonts || {};
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Typography System & Type Scale', { x: MARGIN, y: MARGIN, width: 1000, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
  ];

  const levels = [
    { key: 'heading', label: 'Heading (H1)', sample: `${kit.name || 'Brand Identity System'}` },
    { key: 'subheading', label: 'Subheading (H2)', sample: 'Clear visual hierarchy drives engaging presentations and marketing decks.' },
    { key: 'body', label: 'Body Text', sample: 'Body copy ensures maximum readability across print guidelines, product UI, and digital collateral.' },
  ];

  let y = 180;
  for (const level of levels) {
    const face = fonts[level.key] || {};
    const spec = `Font Family: ${face.family || 'Outfit'}  |  Weight: ${face.weight ?? (level.key === 'heading' ? 700 : 400)}  |  Size: ${face.sizePx ?? (level.key === 'heading' ? 44 : level.key === 'subheading' ? 24 : 16)}px  |  Line Height: ${face.lineHeight ?? 1.3}`;
    
    elements.push(shapeEl(`card_type_${level.key}`, { x: MARGIN, y, width: 1760, height: 240, rotation: 0, opacity: 1 }, 'surface', 1));
    elements.push(
      textEl(`spec_${level.key}`, `${level.label.toUpperCase()} — ${spec}`, {
        x: MARGIN + 32,
        y: y + 20,
        width: 1700,
        height: 28,
        rotation: 0,
        opacity: 1,
      }, { fontSize: 12, colorRole: 'primary', bold: true, role: 'caption' })
    );
    elements.push(
      textEl(`sample_${level.key}`, level.sample, {
        x: MARGIN + 32,
        y: y + 60,
        width: 1700,
        height: 150,
        rotation: 0,
        opacity: 1,
      }, {
        fontSize: face.sizePx ?? (level.key === 'heading' ? 44 : level.key === 'subheading' ? 24 : 16),
        fontWeight: face.weight ?? (level.key === 'heading' ? 700 : 400),
        fontFamily: face.family,
        lineHeight: face.lineHeight ?? 1.3,
        role: level.key,
      })
    );
    y += 260;
  }

  return {
    order: 5,
    contentType: 'bullet_list',
    layoutId: 'brand_guideline_typography',
    content: { title: 'Typography System & Type Scale' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

// 6. UI Components & Button Styles Slide
function buildUIButtonsSlide(kit, themeTokens) {
  const data = kit.data || {};
  const buttonStyle = data.buttonStyle || {};
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'UI Component & Button Styles', { x: MARGIN, y: MARGIN, width: 1000, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
  ];

  const cardW = 840;
  const cardH = 740;
  
  // Primary Button Preview
  elements.push(shapeEl('card_primary_btn', { x: MARGIN, y: 180, width: cardW, height: cardH, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('lbl_primary_btn', 'PRIMARY BUTTON SPECIFICATION', { x: MARGIN + 32, y: 212, width: cardW - 64, height: 28, rotation: 0, opacity: 1 }, { fontSize: 14, colorRole: 'primary', bold: true, role: 'caption' }));
  
  elements.push(shapeEl('btn_primary_shape', { x: MARGIN + 32, y: 270, width: 360, height: 72, rotation: 0, opacity: 1 }, 'primary', 2));
  elements.push(textEl('btn_primary_text', 'Primary Action', { x: MARGIN + 32, y: 290, width: 360, height: 40, rotation: 0, opacity: 1 }, { fontSize: 20, bold: true, align: 'center', colorRole: 'bg', role: 'button' }));

  const primaryRadius = buttonStyle.primaryBorderRadius || '12px';
  const primaryPadding = buttonStyle.primaryPadding || '14px 28px';
  elements.push(textEl('primary_specs', `• Fill Color: Primary Brand Accent\n• Corner Radius: ${primaryRadius}\n• Padding: ${primaryPadding}\n• Usage: High-priority call to actions across web & slide decks.`, { x: MARGIN + 32, y: 380, width: cardW - 64, height: 300, rotation: 0, opacity: 1 }, { fontSize: 16, lineHeight: 1.6, role: 'body' }));

  // Secondary Button Preview
  elements.push(shapeEl('card_sec_btn', { x: MARGIN + cardW + GRID_GAP, y: 180, width: cardW, height: cardH, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('lbl_sec_btn', 'SECONDARY BUTTON SPECIFICATION', { x: MARGIN + cardW + GRID_GAP + 32, y: 212, width: cardW - 64, height: 28, rotation: 0, opacity: 1 }, { fontSize: 14, colorRole: 'primary', bold: true, role: 'caption' }));
  
  elements.push(shapeEl('btn_sec_shape', { x: MARGIN + cardW + GRID_GAP + 32, y: 270, width: 360, height: 72, rotation: 0, opacity: 1 }, 'surface', 2));
  elements.push(textEl('btn_sec_text', 'Secondary Action', { x: MARGIN + cardW + GRID_GAP + 32, y: 290, width: 360, height: 40, rotation: 0, opacity: 1 }, { fontSize: 20, bold: true, align: 'center', colorRole: 'text', role: 'button' }));

  const secRadius = buttonStyle.secondaryBorderRadius || '12px';
  const secPadding = buttonStyle.secondaryPadding || '14px 28px';
  elements.push(textEl('sec_specs', `• Fill Color: Neutral Surface / Outline\n• Corner Radius: ${secRadius}\n• Padding: ${secPadding}\n• Usage: Alternative actions, secondary navigation, and outline buttons.`, { x: MARGIN + cardW + GRID_GAP + 32, y: 380, width: cardW - 64, height: 300, rotation: 0, opacity: 1 }, { fontSize: 16, lineHeight: 1.6, role: 'body' }));

  return {
    order: 6,
    contentType: 'grid',
    layoutId: 'brand_guideline_ui_buttons',
    content: { title: 'UI Component & Button Styles' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

// 7. Imagery & Charts Slide
function buildImagerySlide(kit, themeTokens) {
  const data = kit.data || {};
  const chartColors = themeTokens.brand?.chartColors || ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'];
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Imagery & Chart Color System', { x: MARGIN, y: MARGIN, width: 1000, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
    
    shapeEl('brief_card', { x: MARGIN, y: 180, width: 1760, height: 160, rotation: 0, opacity: 1 }, 'surface', 1),
    textEl('style_label', 'IMAGE STYLE BRIEF & ART DIRECTION', { x: MARGIN + 24, y: 200, width: 1700, height: 28, rotation: 0, opacity: 1 }, { fontSize: 13, colorRole: 'primary', bold: true, role: 'caption' }),
    textEl('style_body', data.imageStyle || 'Clean, modern, high-contrast studio photography with vibrant brand color accents.', {
      x: MARGIN + 24,
      y: 236,
      width: 1700,
      height: 90,
      rotation: 0,
      opacity: 1,
    }, { fontSize: 18, role: 'body', lineHeight: 1.4 }),
  ];

  elements.push(shapeEl('chart_card', { x: MARGIN, y: 360, width: 1760, height: 180, rotation: 0, opacity: 1 }, 'surface', 1));
  elements.push(textEl('chart_lbl', 'CHART & DATA VISUALIZATION PALETTE', { x: MARGIN + 24, y: 380, width: 1700, height: 28, rotation: 0, opacity: 1 }, { fontSize: 13, colorRole: 'primary', bold: true, role: 'caption' }));

  let cx = MARGIN + 24;
  for (let i = 0; i < chartColors.length && i < 8; i += 1) {
    elements.push({
      id: newId('chart_swatch'),
      type: 'shape',
      layer: 2,
      placement: { x: cx, y: 420, width: 180, height: 90, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: { type: 'solid', color: chartColors[i] } },
      role: 'accent',
    });
    elements.push(textEl(`chart_hex_${i}`, chartColors[i], { x: cx, y: 515, width: 180, height: 20, rotation: 0, opacity: 1 }, { fontSize: 12, align: 'center', colorRole: 'muted', role: 'caption' }));
    cx += 210;
  }

  const photo = (kit.media || []).find((m) => m.kind === 'photo');
  const mockups = (kit.media || []).filter((m) => m.kind === 'mockup' && m.url).slice(0, 2);

  if (mockups.length > 0) {
    mockups.forEach((m, idx) => {
      elements.push(
        imageEl(`mockup_${idx}`, m.url, {
          x: MARGIN + idx * (860 + GRID_GAP),
          y: 560,
          width: 860,
          height: 440,
          rotation: 0,
          opacity: 1,
        }, 'image')
      );
    });
  } else if (photo?.url) {
    elements.push(
      imageEl('sample_photo', photo.url, {
        x: MARGIN,
        y: 560,
        width: 1760,
        height: 440,
        rotation: 0,
        opacity: 1,
      }, 'image')
    );
  }

  return {
    order: 7,
    contentType: 'image+text',
    layoutId: 'brand_guideline_imagery',
    content: { title: 'Imagery & Chart Color System', imageStyle: data.imageStyle },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

// 8. Governance & Compliance Slide
function buildGovernanceSlide(kit, themeTokens) {
  const voice = kit.data?.voice || {};
  const usage = kit.data?.usage || {};
  const bullets = [
    'Always use approved vector logomarks from the official Brand Kit repository.',
    'Do not alter official hex codes, font family pairings, or aspect ratios.',
    voice.tone ? `Target Voice Tone: ${voice.tone}` : null,
    voice.audience ? `Target Audience: ${voice.audience}` : null,
    ...(Array.isArray(usage.doNot) ? usage.doNot.map((d) => `Do Not: ${d}`) : []),
    'All presentation decks and public assets must comply with published brand guidelines.',
  ].filter(Boolean);

  const bodyText = bullets.map((b) => `• ${b}`).join('\n\n');

  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Brand Governance & Compliance', {
      x: MARGIN,
      y: MARGIN,
      width: 1200,
      height: 64,
      rotation: 0,
      opacity: 1,
    }, { fontSize: 44, bold: true, role: 'title' }),
    shapeEl('panel', { x: MARGIN, y: 180, width: 1760, height: 780, rotation: 0, opacity: 1 }, 'surface', 1),
    textEl('compliance', `COMPLIANCE GUIDELINES & BEST PRACTICES\n\n${bodyText}`, {
      x: MARGIN + 40,
      y: 220,
      width: 1680,
      height: 700,
      rotation: 0,
      opacity: 1,
    }, { fontSize: 20, role: 'body', lineHeight: 1.6 }),
  ];

  return {
    order: 8,
    contentType: 'closing',
    layoutId: 'brand_guideline_governance',
    content: { title: 'Brand Governance & Compliance', bullets },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

function buildGuidelineSlides(kit, themeTokens) {
  return [
    buildCoverSlide(kit, themeTokens),
    buildMissionVoiceSlide(kit, themeTokens),
    buildColorsSlide(kit, themeTokens),
    buildLogosSlide(kit, themeTokens),
    buildTypographySlide(kit, themeTokens),
    buildUIButtonsSlide(kit, themeTokens),
    buildImagerySlide(kit, themeTokens),
    buildGovernanceSlide(kit, themeTokens),
  ];
}

async function generateGuideline({ workspaceId, userId, brandKitId, folderId }) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);

  const feature = brandKitCredit.BRAND_KIT_FEATURE.GUIDELINE_GENERATE;
  const estimatedAc = brandKitCredit.getFlatAc(feature);
  await brandKitCredit.assertAfford(workspaceId, userId, estimatedAc);

  assertGuidelineReady(kit);
  const kitReady = await kitWithPresignedMedia(kit);
  const themeTokens = brandKitService.brandKitToThemeTokens(kitReady);
  const slidePayloads = buildGuidelineSlides(kitReady, themeTokens);
  const deckName = `${kit.name} — Brand Guidelines`;
  const warnings = [];
  const hasPrimaryLogo = (kitReady.media || []).some(
    (m) => m.kind === 'logo' && (m.role === 'primary' || !m.role)
  );
  if (!hasPrimaryLogo) {
    warnings.push('primary_logo_missing');
  }

  const slideRows = slidePayloads.map((s) => ({
    order: s.order,
    contentType: s.contentType,
    layoutId: s.layoutId,
    content: s.content,
    imageRef: null,
    elements: s.elements,
    status: 'READY',
    manuallyEdited: true,
  }));

  const existingProjectId = kit.data?.meta?.guidelineProjectId || null;
  let project = null;
  let deck = null;
  let regenerated = false;

  if (existingProjectId) {
    const existingProject = await prisma.project.findFirst({
      where: { id: existingProjectId, workspaceId },
      select: { id: true, name: true, folderId: true },
    });
    const existingDeck = existingProject
      ? await presentationDao.findDeckByProjectId(existingProjectId)
      : null;

    if (existingProject && existingDeck) {
      await presentationDao.deleteSlidesByDeckId(existingDeck.id);
      await presentationDao.updateDeck(existingDeck.id, { themeTokens, status: 'DRAFT' });
      await presentationDao.updateProjectName(existingProjectId, deckName);
      await presentationDao.createSlides(existingDeck.id, slideRows);
      project = existingProject;
      deck = await presentationDao.findDeckById(existingDeck.id);
      regenerated = true;
    }
  }

  if (!project || !deck) {
    const folder = await prisma.folder.findFirst({
      where: { id: folderId, workspaceId },
      select: { id: true },
    });
    if (!folder) throw new AppError(messages.FOLDER_NOT_FOUND, 404);

    const created = await presentationDao.createPresentationProject({
      workspaceId,
      folderId,
      name: deckName,
      createdBy: userId,
      themeTokens,
      aspectRatio: '16:9',
      locale: 'en',
    });
    project = created.project;
    deck = created.deck;
    await presentationDao.createSlides(deck.id, slideRows);

    const updatedData = {
      ...(kit.data && typeof kit.data === 'object' ? kit.data : {}),
      meta: {
        ...((kit.data && kit.data.meta) || {}),
        guidelineProjectId: project.id,
      },
    };

    await brandKitDao.updateKit({
      workspaceId,
      brandKitId,
      data: updatedData,
    });
  }

  await brandKitCredit.chargeFlat({
    workspaceId,
    userId,
    feature,
    idempotencyKey: `brandKit:guideline:${workspaceId}:${brandKitId}:${Date.now()}`,
    metadata: { brandKitId, action: 'guideline_generate', projectId: project.id },
  });

  const refreshedDeck = await presentationDao.findDeckByProjectId(project.id);

  return {
    presentationId: project.id,
    deckId: deck.id,
    name: deckName,
    slideCount: slidePayloads.length,
    status: refreshedDeck?.status || 'DRAFT',
    themeTokens,
    warnings,
    regenerated,
  };
}

async function getGuidelineInfo(workspaceId, brandKitId) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);

  const projectId = kit.data?.meta?.guidelineProjectId || null;
  if (!projectId) {
    return { linked: false, presentationId: null, status: null, slideCount: 0 };
  }

  const deck = await presentationDao.findDeckByProjectId(projectId);
  if (!deck) {
    return { linked: false, presentationId: projectId, status: 'missing', slideCount: 0 };
  }

  const project = await prisma.project.findFirst({
    where: { id: projectId, workspaceId },
    select: { id: true, name: true },
  });

  return {
    linked: true,
    presentationId: projectId,
    name: project?.name || null,
    status: deck.status,
    slideCount: (deck.slides || []).length,
    aspectRatio: deck.aspectRatio,
  };
}

module.exports = {
  buildGuidelineSlides,
  generateGuideline,
  getGuidelineInfo,
  CANVAS,
};
