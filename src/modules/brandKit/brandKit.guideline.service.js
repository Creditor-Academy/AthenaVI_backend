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
      textEl('brand_name', kit.name, { x: MARGIN, y: 360, width: 1200, height: 100, rotation: 0, opacity: 1 }, {
        fontSize: 64,
        bold: true,
        fontWeight: themeTokens.fonts?.headingWeight ?? 700,
        fontFamily: themeTokens.fonts?.heading,
        role: 'title',
        layer: 2,
      }),
      textEl('guideline_title', 'Brand Guidelines', { x: MARGIN, y: 480, width: 800, height: 60, rotation: 0, opacity: 1 }, {
        fontSize: 32,
        colorRole: 'primary',
        role: 'subtitle',
      }),
    ],
  };

  if (tagline) {
    doc.elements.push(
      textEl('tagline', tagline, { x: MARGIN, y: 560, width: 1000, height: 48, rotation: 0, opacity: 1 }, {
        fontSize: 22,
        colorRole: 'muted',
        role: 'tagline',
      })
    );
  }

  doc.elements.push(
    textEl('date', dateStr, { x: MARGIN, y: 980, width: 400, height: 32, rotation: 0, opacity: 1 }, {
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

function colorSwatchElements(startY, colors, roles, prefix) {
  const elements = [];
  const swatchW = 380;
  const swatchH = 140;
  let x = MARGIN;
  const entries = [
    { roleKey: prefix ? `primary${prefix}` : 'primary', label: `Primary${prefix ? ' (Dark)' : ' (Light)'}` },
    { roleKey: prefix ? `bg${prefix}` : 'bg', label: `Background${prefix ? ' (Dark)' : ' (Light)'}` },
    { roleKey: prefix ? `text${prefix}` : 'text', label: `Text${prefix ? ' (Dark)' : ' (Light)'}` },
  ];

  const map = brandKitService.colorMap({ colors });
  for (const entry of entries) {
    const colorId = roles[entry.roleKey] || roles[entry.roleKey.replace('Dark', '')];
    const hex = brandKitService.resolveHex(map, colorId, '#CCCCCC');
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
      textEl(`swatch_label_${entry.roleKey}`, `${entry.label}\n${hex}`, {
        x: x + 16,
        y: startY + 96,
        width: swatchW - 32,
        height: 40,
        rotation: 0,
        opacity: 1,
      }, { fontSize: 14, role: 'caption' })
    );
    x += swatchW + GRID_GAP;
  }
  return elements;
}

function buildColorsSlide(kit, themeTokens) {
  const data = kit.data || {};
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Brand Colors', { x: MARGIN, y: MARGIN, width: 800, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
    textEl('section_light', 'Light Mode', { x: MARGIN, y: 180, width: 400, height: 36, rotation: 0, opacity: 1 }, {
      fontSize: 20,
      colorRole: 'primary',
      role: 'subtitle',
    }),
    ...colorSwatchElements(230, data.colors, data.colorRoles || {}, ''),
  ];

  if (data.colorRoles?.bgDark || data.colorRoles?.primaryDark) {
    elements.push(
      textEl('section_dark', 'Dark Mode', { x: MARGIN, y: 420, width: 400, height: 36, rotation: 0, opacity: 1 }, {
        fontSize: 20,
        colorRole: 'primary',
        role: 'subtitle',
      })
    );
    elements.push(...colorSwatchElements(470, data.colors, data.colorRoles || {}, 'Dark'));
  }

  return {
    order: 2,
    contentType: 'section_divider',
    layoutId: 'brand_guideline_colors',
    content: { title: 'Brand Colors' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

function buildLogosSlide(kit, themeTokens) {
  const logos = (kit.media || []).filter((m) => m.kind === 'logo');
  const roles = [
    'primary',
    'light',
    'dark',
    'with-name-below',
    'with-name-adjacent',
    'black',
    'white',
  ];
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Logo System', { x: MARGIN, y: MARGIN, width: 800, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
  ];

  const cardW = 240;
  const cardH = 200;
  let col = 0;
  let row = 0;
  const cols = 4;
  const startX = MARGIN;
  const startY = 200;

  for (const role of roles) {
    const x = startX + col * (cardW + GRID_GAP);
    const y = startY + row * (cardH + GRID_GAP);
    const media =
      logos.find((m) => m.role === role) ||
      (role === 'light' ? logos.find((m) => m.role === 'light-mode') : null) ||
      (role === 'dark' ? logos.find((m) => m.role === 'dark-mode') : null);
    elements.push(
      shapeEl(`card_${role}`, { x, y, width: cardW, height: cardH, rotation: 0, opacity: 1 }, 'surface', 1)
    );
    elements.push(
      textEl(`role_${role}`, role.replace(/-/g, ' ').toUpperCase(), {
        x: x + 12,
        y: y + 12,
        width: cardW - 24,
        height: 24,
        rotation: 0,
        opacity: 1,
      }, { fontSize: 11, colorRole: 'muted', role: 'caption' })
    );
    if (media) {
      const url = media.url;
      if (url) {
        elements.push(
          imageEl(`logo_${role}`, url, {
            x: x + 24,
            y: y + 40,
            width: cardW - 48,
            height: cardH - 60,
            rotation: 0,
            opacity: 1,
          }, role)
        );
      }
    } else {
      elements.push(
        textEl(`missing_${role}`, 'Not provided', {
          x: x + 12,
          y: y + 80,
          width: cardW - 24,
          height: 40,
          rotation: 0,
          opacity: 1,
        }, { fontSize: 14, colorRole: 'muted', align: 'center', role: 'caption' })
      );
    }
    col += 1;
    if (col >= cols) {
      col = 0;
      row += 1;
    }
  }

  const clearSpace = kit.data?.usage?.logoClearSpace;
  if (clearSpace) {
    elements.push(
      textEl('clear_space', `Clear space: ${clearSpace}`, {
        x: MARGIN,
        y: 920,
        width: 1200,
        height: 32,
        rotation: 0,
        opacity: 1,
      }, { fontSize: 16, colorRole: 'muted' })
    );
  }

  return {
    order: 3,
    contentType: 'grid',
    layoutId: 'brand_guideline_logos',
    content: { title: 'Logo System' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

function buildTypographySlide(kit, themeTokens) {
  const fonts = kit.data?.fonts || {};
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Typography', { x: MARGIN, y: MARGIN, width: 800, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
  ];

  const levels = [
    { key: 'heading', label: 'Heading', sample: 'The quick brown fox jumps over the lazy dog' },
    { key: 'subheading', label: 'Subheading', sample: 'A clean, modern sans serif for clarity and contrast.' },
    { key: 'body', label: 'Body', sample: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Brand body copy should be readable at small sizes.' },
  ];

  let y = 180;
  for (const level of levels) {
    const face = fonts[level.key] || {};
    const spec = `${face.family || 'Inter'} — ${face.weight ?? 400} — ${face.sizePx ?? 16}px — LH ${face.lineHeight ?? 1.4}`;
    elements.push(
      textEl(`spec_${level.key}`, `${level.label}\n${spec}`, {
        x: MARGIN,
        y,
        width: 700,
        height: 56,
        rotation: 0,
        opacity: 1,
      }, { fontSize: 14, colorRole: 'muted', role: 'caption' })
    );
    elements.push(
      textEl(`sample_${level.key}`, level.sample, {
        x: MARGIN,
        y: y + 60,
        width: 1760,
        height: level.key === 'body' ? 100 : 56,
        rotation: 0,
        opacity: 1,
      }, {
        fontSize: face.sizePx ?? (level.key === 'heading' ? 40 : level.key === 'subheading' ? 20 : 14),
        fontWeight: face.weight ?? 400,
        fontFamily: face.family,
        lineHeight: face.lineHeight ?? 1.3,
        role: level.key,
      })
    );
    y += level.key === 'body' ? 200 : 160;
  }

  return {
    order: 4,
    contentType: 'bullet_list',
    layoutId: 'brand_guideline_typography',
    content: { title: 'Typography' },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

function buildImagerySlide(kit, themeTokens) {
  const data = kit.data || {};
  const chartColors = themeTokens.brand?.chartColors || [];
  const elements = [
    shapeEl('bg', { x: 0, y: 0, width: CANVAS.width, height: CANVAS.height, rotation: 0, opacity: 1 }, 'bg', 0),
    textEl('title', 'Imagery & Charts', { x: MARGIN, y: MARGIN, width: 900, height: 64, rotation: 0, opacity: 1 }, {
      fontSize: 44,
      bold: true,
      role: 'title',
    }),
    textEl('style_label', 'Image Style Brief', { x: MARGIN, y: 180, width: 400, height: 32, rotation: 0, opacity: 1 }, {
      fontSize: 18,
      colorRole: 'primary',
    }),
    textEl('style_body', data.imageStyle || 'Not specified', {
      x: MARGIN,
      y: 220,
      width: 1200,
      height: 80,
      rotation: 0,
      opacity: 1,
    }, { fontSize: 16, role: 'body' }),
  ];

  let cx = MARGIN;
  for (let i = 0; i < chartColors.length && i < 8; i += 1) {
    elements.push({
      id: newId('chart_swatch'),
      type: 'shape',
      layer: 2,
      placement: { x: cx, y: 340, width: 80, height: 80, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: { type: 'solid', color: chartColors[i] } },
      role: 'accent',
    });
    cx += 96;
  }

  const photo = (kit.media || []).find((m) => m.kind === 'photo');
  if (photo?.url) {
    elements.push(
      imageEl('sample_photo', photo.url, {
        x: MARGIN,
        y: 460,
        width: 480,
        height: 320,
        rotation: 0,
        opacity: 1,
      }, 'image')
    );
  }

  return {
    order: 5,
    contentType: 'image+text',
    layoutId: 'brand_guideline_imagery',
    content: { title: 'Imagery & Charts', imageStyle: data.imageStyle },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

function buildGovernanceSlide(kit, themeTokens) {
  const voice = kit.data?.voice || {};
  const usage = kit.data?.usage || {};
  const bullets = [
    'Always use approved logo vectors from the official brand kit repository.',
    'Do not alter hex codes, font family pairings, or aspect ratios.',
    voice.tone ? `Target voice tone: ${voice.tone}` : null,
    voice.audience ? `Target audience: ${voice.audience}` : null,
    ...(Array.isArray(usage.doNot) ? usage.doNot.map((d) => `Do not: ${d}`) : []),
    ...(Array.isArray(voice.dos) ? voice.dos.map((d) => `Do: ${d}`) : []),
    ...(Array.isArray(voice.donts) ? voice.donts.map((d) => `Don't: ${d}`) : []),
  ].filter(Boolean);

  const bodyText = bullets.map((b) => `• ${b}`).join('\n');

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
    shapeEl('panel', { x: MARGIN, y: 180, width: 1760, height: 720, rotation: 0, opacity: 1 }, 'surface', 1),
    textEl('compliance', `Compliance Guidelines\n\n${bodyText}`, {
      x: MARGIN + 40,
      y: 220,
      width: 1680,
      height: 640,
      rotation: 0,
      opacity: 1,
    }, { fontSize: 18, role: 'body', lineHeight: 1.5 }),
  ];

  return {
    order: 6,
    contentType: 'closing',
    layoutId: 'brand_guideline_governance',
    content: { title: 'Brand Governance & Compliance', bullets },
    elements: { version: 1, canvas: CANVAS, elements },
  };
}

function buildGuidelineSlides(kit, themeTokens) {
  return [
    buildCoverSlide(kit, themeTokens),
    buildColorsSlide(kit, themeTokens),
    buildLogosSlide(kit, themeTokens),
    buildTypographySlide(kit, themeTokens),
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
