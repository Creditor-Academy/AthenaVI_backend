const crypto = require('crypto');
const {
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
} = require('./presentation.constants');
const { isCatalogPlaceholderText } = require('./catalogPlaceholder');
const {
  relativeLuminance,
  AA_CONTRAST_RATIO,
  contrastRatioCss,
} = require('./theme.service');
const { normalizeChartContent } = require('./chartContentNormalize');
const { resolveSemanticTheme } = require('./artDirection/semanticTheme');
const { resolveTextColor } = require('./artDirection/resolveTextColor');
const { inferTypographyRole } = require('./artDirection/typographyRoles');
const { repairElementsDoc } = require('./artDirection/validateDesign');
const { PROCESS_STEP_COLORS, processRibbonInlineSvg, processRibbonLabelBox, processIconInlineSvg, processFlowArrowInlineSvg } = require('./diagrams/diagramProcessStepsSvg');
const {
  agendaGraphicFrame,
  agendaChromeSpecs,
  agendaOverlayPlacements,
  resolveAgendaMeta,
  specToGraphicContent,
  isAgendaThreeColumnColouredLayout,
} = require('./diagrams/agendaInfographicSvg');
const {
  isAgendaMinimalLayout,
  isAgendaNumberedLayout,
  isAgendaHeroLayout,
  isAgendaThreeColumnLayout,
  isAgendaTimelineLayout,
  isAgendaTwoColumnLayout,
} = require('./diagrams/agendaSharedSvg');
const {
  agendaThreeColumnGraphicFrame,
  colouredColumnTextContent,
  specToThreeColumnContent,
  isAgendaThreeColumnTextSlot,
} = require('./diagrams/agendaThreeColumn');
const {
  agendaThreeCardsGraphicFrame,
  agendaThreeCardsChromeSpecs,
  specToThreeCardsContent,
  isAgendaThreeCardsLayout,
  isAgendaThreeCardsHeroLayout,
} = require('./diagrams/agendaThreeCards');
const {
  agendaHeroCardsGraphicFrame,
  specToHeroCardsContent,
  isAgendaHeroCardsLayout,
} = require('./diagrams/agendaHeroCards');
const {
  agendaNumberedBlocksGraphicFrame,
  specToNumberedBlocksContent,
  isAgendaNumberedBlocksLayout,
  isAgendaNumberedBlocksTextSlot,
} = require('./diagrams/agendaNumberedBlocks');
const {
  agendaNumberedTimelineGraphicFrame,
  specToNumberedTimelineContent,
  isAgendaNumberedTimelineLayout,
  isAgendaNumberedTimelineTextSlot,
} = require('./diagrams/agendaNumberedTimeline');
const {
  agendaMinimalQuietGraphicFrame,
  specToMinimalQuietContent,
  isAgendaMinimalQuietLayout,
  isAgendaMinimalQuietTextSlot,
} = require('./diagrams/agendaMinimalQuiet');
const {
  agendaEditorialGraphicFrame,
  specToEditorialContent,
  isAgendaEditorialLayout,
  isAgendaEditorialTextSlot,
} = require('./diagrams/agendaEditorialHub');
const {
  agendaCardsGraphicFrame,
  specToAgendaCardsContent,
  isAgendaCardsLayout,
  isAgendaCardsTextSlot,
} = require('./diagrams/agendaCardsTiles');
const {
  agendaTwoColumnRibbonGraphicFrame,
  specToTwoColumnRibbonContent,
  isAgendaTwoColumnRibbonLayout,
  isAgendaTwoColumnRibbonTextSlot,
} = require('./diagrams/agendaTwoColumnRibbons');
const { cycleDiagramInlineSvg, cycleSegmentInlineSvg, cycleSegmentPlacement, CYCLE_SEGMENT_COLORS, cycleOverlayPlacements, cycleNodePalette, cycleNodeTopArcSvg, cycleNodeBotArcSvg, cycleNodeIconSvg, CYCLE_RING_N, CYCLE_RING_COLORS, CYCLE_RING_GEOM, cycleRingSegSvg, cycleRingSegPlacement, cycleRingDiamondSvg, cycleRingCalloutSvg, cycleRingCallouts } = require('./diagrams/diagramCycleSvg');
const { funnelStageInlineSvg, funnelStagePlacement, FUNNEL_TITLE_COLORS, FUNNEL_GEOM, FUNNEL_STAGE_COLORS, funnelOverlayPlacements, packFunnelStageTextBlocks, FUNNEL_H_GEOM, funnelHSegInlineSvg, funnelHSegPlacement, funnelHOverlayPlacements } = require('./diagrams/diagramFunnelSvg');
const { matrixQuadPlacement, matrixArrowPlacement, matrixArrowInlineSvg, MATRIX_GEOM, MATRIX_QUAD_COLORS, MATRIX_ARROW_COLOR, matrixOverlayPlacements, MATRIX_GRID_COLORS, MATRIX_Q_TINTS, MATRIX_Q_TITLE, MATRIX_Q_AXIS, matrixQuadrantCrossInlineSvg } = require('./diagrams/diagramMatrixSvg');
const {
  PYRAMID_N,
  PYRAMID_COLORS,
  pyramidStagePlacement,
  pyramidStageInlineSvg,
  pyramidGraphicBox,
  pyramidLegendPlacements,
  pyramidModeFromSchema,
  PYRAMID_BADGE_CLIP,
} = require('./diagrams/diagramPyramid');
const {
  SWOT_N,
  SWOT_LETTERS,
  SWOT_COLORS,
  SWOT_LABELS,
  swotPetalPlacement,
  swotPetalInlineSvg,
  swotIconInlineSvg,
  swotDashInlineSvg,
  swotGraphicBox,
  swotOverlayPlacements,
  swotModeFromSchema,
  swotQuadFrame,
} = require('./diagrams/diagramSwotSvg');
const {
  VENN_N,
  VENN_COLORS,
  vennRingColor,
  vennCoreInlineSvg,
  vennIconInlineSvg,
  vennFrame,
  vennSetGeom,
  vennModeFromSchema,
  vennThreeCircleFrame,
  vennStackedFrame,
} = require('./diagrams/diagramVennSvg');
const { isDevicePhoneHighlightsLayout, layoutDevicePhoneHighlights } = require('./diagrams/devicePhoneHighlightsLayout');
const { isDevicePhoneTripleLayout, layoutDevicePhoneTriple } = require('./diagrams/devicePhoneTripleLayout');
const { isDeviceMultiClusterLayout, layoutDeviceMultiCluster } = require('./diagrams/deviceMultiClusterLayout');
const { isDeviceLaptopSplitLayout, layoutDeviceLaptopSplit } = require('./diagrams/deviceLaptopSplitLayout');
const { isDeviceTabletSplitLayout, layoutDeviceTabletSplit } = require('./diagrams/deviceTabletSplitLayout');
const { isDeviceTabletCenteredLayout, layoutDeviceTabletCentered } = require('./diagrams/deviceTabletCenteredLayout');
const { isTeamFourLayout, layoutTeamFour } = require('./diagrams/teamFourLayout');
const { isTeamThreeHorizontalLayout, layoutTeamThreeHorizontal } = require('./diagrams/teamThreeHorizontalLayout');
const { isTeamThreeVerticalLayout, layoutTeamThreeVertical } = require('./diagrams/teamThreeVerticalLayout');
const { isTeamThreeFullCardsLayout, layoutTeamThreeFullCards } = require('./diagrams/teamThreeFullCardsLayout');
const {
  deviceFrameChromeColors,
  paintDeviceFrameElement,
  parseHexLum,
} = require('./diagrams/deviceChrome.util');
const { isTeamFiveLayout, layoutTeamFive } = require('./diagrams/teamFiveLayout');
const { isTeamSixLayout, layoutTeamSix } = require('./diagrams/teamSixLayout');
const { isTeamByDepartmentLayout, layoutTeamByDepartment } = require('./diagrams/teamByDepartmentLayout');
const { isTeamFeaturedLeadLayout, layoutTeamFeaturedLead } = require('./diagrams/teamFeaturedLeadLayout');
const { isTeamOrgSimpleLayout, layoutTeamOrgSimple } = require('./diagrams/teamOrgSimpleLayout');
const {
  QUOTE_GRID_N,
  QUOTE_MARK_COLOR,
  QUOTE_CARD_BORDER,
  quoteMarkInlineSvg,
  quoteGridFrame,
  quoteGridCardGeom,
  quotePortraitGeom,
  quoteTestimonialGeom,
  quoteStatementLeftGeom,
  quoteAttributionSplitGeom,
} = require('./quotes/quoteGridLayout');
const {
  compileLayoutGeometry,
  getSlotPlacement,
  gridRegionToPlacement,
  resolveSlotPaddingPx,
  applySlotGeometryTransform,
} = require('./compileLayoutGeometry');
const {
  timelineNodeInlineSvg,
  timelineSpineSegmentInlineSvg,
  timelineChevronInlineSvg,
  processPhaseCircleInlineSvg,
  resolveTimelineMeta,
} = require('./timelineProcessSvg');

function parseRegion(region) {
  const str = String(region || '');
  const cols = str.match(/cols\s+(\d+)\s*-\s*(\d+)/i);
  const rows = str.match(/rows\s+(\d+)\s*-\s*(\d+)/i);
  if (!cols || !rows) return null;
  return {
    c1: Math.max(1, Number(cols[1])),
    c2: Math.max(Number(cols[1]), Number(cols[2])),
    r1: Math.max(1, Number(rows[1])),
    r2: Math.max(Number(rows[1]), Number(rows[2])),
  };
}

const TEXT_SLOT_ROLES = new Set([
  'heading', 'subheading', 'body', 'caption', 'stat', 'stat_label', 'quote', 'attribution', 'eyebrow',
]);

/** Split text|image slides — fade photo edge into slide background (editorial bleed). */
function resolveSplitImageEdgeFade(layoutSchema, slot) {
  if (!layoutSchema?.slots?.length || !slot) return null;
  const contentType = String(layoutSchema?.content_type || '').toLowerCase();
  const layoutId = String(layoutSchema?.layout_id || '').toLowerCase();
  if (contentType !== 'title' && !/^title_/.test(layoutId)) return null;

  const imgReg = parseRegion(slot.region);
  if (!imgReg) return null;

  const textSlots = layoutSchema.slots.filter((s) => {
    if (s.id === slot.id) return false;
    return TEXT_SLOT_ROLES.has(String(s.role || '').toLowerCase());
  });
  if (!textSlots.length) return null;

  let textColSum = 0;
  let textCount = 0;
  for (const ts of textSlots) {
    const tr = parseRegion(ts.region);
    if (!tr) continue;
    textColSum += (tr.c1 + tr.c2) / 2;
    textCount += 1;
  }
  if (!textCount) return null;

  const textCenter = textColSum / textCount;
  const imgCenter = (imgReg.c1 + imgReg.c2) / 2;

  if (imgCenter > textCenter && imgReg.c1 >= 6) {
    return { side: 'left', width: 0.3 };
  }
  if (imgCenter < textCenter && imgReg.c2 <= 7) {
    return { side: 'right', width: 0.3 };
  }
  return null;
}

function edgeFadeMaskCss(edgeFade) {
  if (!edgeFade) return null;
  const width = Math.min(0.45, Math.max(0.12, Number(edgeFade.width) || 0.28));
  const pct = Math.round(width * 100);
  const side = String(edgeFade.side || 'left').toLowerCase();
  if (side === 'right') {
    return `linear-gradient(to left, transparent 0%, black ${pct}%, black 100%)`;
  }
  return `linear-gradient(to right, transparent 0%, black ${pct}%, black 100%)`;
}

function applySplitImageEdgeFade(doc, layoutSchema) {
  if (!doc?.elements?.length || !layoutSchema?.slots?.length) return doc;
  const slotById = Object.fromEntries(layoutSchema.slots.map((s) => [String(s.id), s]));
  const elements = doc.elements.map((el) => {
    if (el.type !== 'image' || !el.slotId) return el;
    const slot = slotById[String(el.slotId)];
    if (!slot) return el;
    const edgeFade = resolveSplitImageEdgeFade(layoutSchema, slot);
    if (!edgeFade) return el;
    return {
      ...el,
      content: {
        ...(el.content || {}),
        edgeFade,
        borderRadius: 0,
        boxShadow: undefined,
        shadow: undefined,
      },
    };
  });
  return { ...doc, elements };
}

function textPaddingForRole(role) {
  const r = String(role || '').toLowerCase();
  if (r === 'heading' || r === 'quote' || r === 'title') return { x: 12, y: 8 };
  if (r === 'caption' || r === 'stat_label' || r === 'eyebrow' || r === 'subheading') {
    return { x: 8, y: 4 };
  }
  return { x: 10, y: 6 };
}

const COLUMN_STACK_GAP_PX = 14;
const COLUMN_STACK_MIN_TITLE = 36;
const COLUMN_STACK_MIN_BODY = 48;

function columnStackKey(slotId) {
  const m = String(slotId || '').match(
    /^(CARD|COL|ROW|FEATURE)_(\d+)_(TITLE|SUBTITLE|BODY|TEXT)$/i
  );
  if (!m) return null;
  return `${m[1].toUpperCase()}_${m[2]}`;
}

function columnStackPartWeight(part, text) {
  const len = String(text || '').trim().length;
  const p = String(part || '').toUpperCase();
  if (p === 'TITLE' || p === 'SUBTITLE') return Math.max(1, Math.min(4, Math.ceil(len / 18) || 1));
  return Math.max(2, Math.min(10, Math.ceil(len / 40) || 2));
}

/**
 * Re-pack CARD/COL/ROW title+body stacks so short titles take less height and
 * longer bodies expand within the original column band, with a fixed gap.
 */
function packColumnTextStacks(elements) {
  if (!Array.isArray(elements) || !elements.length) return elements;
  const groups = new Map();
  for (const el of elements) {
    if (!el || el.type !== 'text' || !el.placement) continue;
    const key = columnStackKey(el.slotId);
    if (!key) continue;
    const part =
      String(el.slotId)
        .match(/_(TITLE|SUBTITLE|BODY|TEXT)$/i)?.[1]
        ?.toUpperCase() || 'BODY';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ el, part });
  }

  for (const items of groups.values()) {
    if (items.length < 2) continue;
    items.sort((a, b) => (a.el.placement?.y || 0) - (b.el.placement?.y || 0));
    const first = items[0].el.placement;
    const last = items[items.length - 1].el.placement;
    const bandTop = Number(first.y) || 0;
    const bandBottom = (Number(last.y) || 0) + (Number(last.height) || 0);
    const bandH = Math.max(0, bandBottom - bandTop);
    if (bandH < 40) continue;

    const gapsTotal = COLUMN_STACK_GAP_PX * (items.length - 1);
    const usable = Math.max(0, bandH - gapsTotal);
    const weights = items.map(({ el, part }) =>
      columnStackPartWeight(part, el.content?.text)
    );
    const weightSum = weights.reduce((a, b) => a + b, 0) || items.length;
    let heights = items.map(({ part }, i) => {
      const minH =
        part === 'TITLE' || part === 'SUBTITLE' ? COLUMN_STACK_MIN_TITLE : COLUMN_STACK_MIN_BODY;
      return Math.max(minH, Math.round((weights[i] / weightSum) * usable));
    });
    let sumH = heights.reduce((a, b) => a + b, 0);
    if (sumH > usable && sumH > 0) {
      const scale = usable / sumH;
      heights = heights.map((h) => Math.max(28, Math.round(h * scale)));
      sumH = heights.reduce((a, b) => a + b, 0);
      heights[heights.length - 1] += Math.max(0, usable - sumH);
    }

    let y = bandTop;
    items.forEach(({ el }, i) => {
      el.placement = {
        ...el.placement,
        y: Math.round(y),
        height: Math.max(28, heights[i]),
      };
      y += heights[i] + COLUMN_STACK_GAP_PX;
    });
  }
  return elements;
}

function shouldSplitSharedRow(upperRole, lowerRole) {
  const textRoles = new Set([
    'heading', 'subheading', 'body', 'caption', 'stat', 'stat_label',
    'quote', 'attribution', 'cta', 'contact', 'eyebrow', 'divider',
  ]);
  if (textRoles.has(upperRole) && textRoles.has(lowerRole)) return true;
  if (upperRole === 'heading' && lowerRole === 'body') return true;
  if (upperRole === 'chart' && (lowerRole === 'caption' || textRoles.has(lowerRole))) return true;
  if (upperRole === 'image' && textRoles.has(lowerRole)) return true;
  return false;
}

function adjustSlotRegion(reg, slot, allSlots) {
  const adjusted = { ...reg };
  const role = slot?.role || 'body';
  for (const other of allSlots || []) {
    if (other.id === slot.id) continue;
    const oreg = parseRegion(other.region);
    if (!oreg) continue;
    const otherRole = other.role || 'body';
    if (oreg.r1 === adjusted.r2 && shouldSplitSharedRow(role, otherRole)) {
      adjusted.r2 -= 0.75;
    }
    if (oreg.r2 === adjusted.r1 && shouldSplitSharedRow(otherRole, role)) {
      adjusted.r1 += 0.75;
    }
  }
  if (adjusted.r2 < adjusted.r1) adjusted.r2 = adjusted.r1 + 0.5;
  return adjusted;
}

function getGridDims(slots = []) {
  let maxR = 10;
  let maxC = 12;
  for (const slot of slots) {
    const reg = parseRegion(slot.region);
    if (!reg) continue;
    maxR = Math.max(maxR, reg.r2);
    maxC = Math.max(maxC, reg.c2);
  }
  return { COLS: Math.max(12, maxC), ROWS: Math.max(10, maxR) };
}

function placementFromGrid(reg, canvas = {}, grid = null) {
  return gridRegionToPlacement(reg, grid, canvas, { left: 0, right: 0, top: 0, bottom: 0 });
}

/**
 * Directional pixel insets — deprecated; only used when slot.padding is explicitly set.
 * @deprecated Use slot.padding in layout schema instead.
 */
function directionalImageInsetsPx(reg, canvas = {}, grid = null, slot = null) {
  return resolveSlotPaddingPx(slot, grid, canvas);
}

function applyDirectionalInsets(placement, insets) {
  if (!placement || !insets) return placement;
  const left = Number(insets.left) || 0;
  const right = Number(insets.right) || 0;
  const top = Number(insets.top) || 0;
  const bottom = Number(insets.bottom) || 0;
  if (left === 0 && right === 0 && top === 0 && bottom === 0) return placement;
  return {
    ...placement,
    x: Math.round(placement.x + left),
    y: Math.round(placement.y + top),
    width: Math.max(1, Math.round(placement.width - left - right)),
    height: Math.max(1, Math.round(placement.height - top - bottom)),
  };
}

/**
 * Parse region strings into authoritative pixel placement (no implicit insets).
 */
function regionToPlacement(region, canvas = {}, slot = null, allSlots = null) {
  const parsed = parseRegion(region);
  const grid = getGridDims(allSlots || (slot ? [slot] : []));
  if (!parsed) {
    return { x: 0, y: 0, width: 1, height: 1, rotation: 0, opacity: 1 };
  }

  let reg = { ...parsed };
  if (slot?.allowRowSplit === true && allSlots) {
    reg = adjustSlotRegion(reg, slot, allSlots);
  }

  const paddingPx = slot ? resolveSlotPaddingPx(slot, grid, canvas) : { left: 0, right: 0, top: 0, bottom: 0 };
  let placement = gridRegionToPlacement(reg, grid, canvas, paddingPx);
  if (slot) {
    placement = applySlotGeometryTransform(slot, placement);
  }
  return placement;
}

function findDeviceFrameSlot(slots, imageSlotId) {
  const target = String(imageSlotId || '');
  if (!target) return null;
  return (
    (slots || []).find((slot) => {
      const pairs = slot?.shapeHint?.pairsWithSlotId;
      if (!pairs || String(pairs) !== target) return false;
      const id = String(slot?.id || '');
      const kind = String(slot?.shapeHint?.kind || '');
      return (
        /FRAME$/i.test(id) ||
        /Frame$/i.test(kind) ||
        kind === 'deviceFrame' ||
        /^(phone|tablet|laptop|watch)/i.test(kind)
      );
    }) || null
  );
}

function deviceFrameKindFromSlot(slot = {}) {
  const id = String(slot.id || '').toUpperCase();
  const hintKind = String(slot.shapeHint?.kind || '');
  if (/LAPTOP/.test(id) || hintKind === 'laptopFrame') return 'laptop';
  if (/TABLET/.test(id) || hintKind === 'tabletFrame') return 'tablet';
  if (/LANDSCAPE/.test(id) || hintKind === 'phoneLandscapeFrame') return 'phone_landscape';
  if (/WATCH/.test(id) || hintKind === 'watchFrame') return 'watch';
  return 'phone';
}

function fitDeviceFramePlacement(placement, kind) {
  const p = placement || {};
  const x = p.x ?? 0;
  const y = p.y ?? 0;
  const w = Math.max(1, p.width ?? 400);
  const h = Math.max(1, p.height ?? 300);
  if (kind === 'phone') {
    const aspect = 9 / 19.5;
    const mx = w * 0.01;
    const my = h * 0.01;
    const innerW = Math.max(1, w - mx * 2);
    const innerH = Math.max(1, h - my * 2);
    let rw = innerW;
    let rh = rw / aspect;
    if (rh > innerH) {
      rh = innerH;
      rw = rh * aspect;
    }
    return {
      ...p,
      x: Math.round(x + (w - rw) / 2),
      y: Math.round(y + (h - rh) / 2),
      width: Math.round(rw),
      height: Math.round(rh),
    };
  }
  if (kind !== 'phone_landscape') return { ...p, x, y, width: w, height: h };
  const aspect = 19.5 / 9;
  let rw = w;
  let rh = rw / aspect;
  if (rh > h) {
    rh = h;
    rw = rh * aspect;
  }
  return {
    ...p,
    x: Math.round(x + (w - rw) / 2),
    y: Math.round(y + (h - rh) / 2),
    width: Math.round(rw),
    height: Math.round(rh),
  };
}

function insetScreenRect(placement, kind) {
  const x = placement.x ?? 0;
  const y = placement.y ?? 0;
  const w = placement.width ?? 400;
  const h = placement.height ?? 300;
  if (kind === 'laptop') {
    const padX = w * 0.05;
    const padTop = h * 0.06;
    const padBottom = h * 0.16;
    return {
      x: Math.round(x + padX),
      y: Math.round(y + padTop),
      width: Math.max(40, Math.round(w - padX * 2)),
      height: Math.max(40, Math.round(h - padTop - padBottom)),
    };
  }
  if (kind === 'tablet') {
    const padX = w * 0.12;
    const padY = h * 0.08;
    return {
      x: Math.round(x + padX),
      y: Math.round(y + padY),
      width: Math.max(40, Math.round(w - padX * 2)),
      height: Math.max(40, Math.round(h - padY * 2)),
    };
  }
  if (kind === 'phone_landscape') {
    const bezel = Math.max(10, Math.round(Math.min(w, h) * 0.032));
    return {
      x: Math.round(x + bezel),
      y: Math.round(y + bezel),
      width: Math.max(40, Math.round(w - bezel * 2)),
      height: Math.max(40, Math.round(h - bezel * 2)),
    };
  }
  if (kind === 'watch') {
    const caseW = w * 0.76;
    const caseH = h * 0.54;
    return {
      x: Math.round(x + (w - caseW) / 2),
      y: Math.round(y + (h - caseH) / 2),
      width: Math.max(24, Math.round(caseW)),
      height: Math.max(24, Math.round(caseH)),
    };
  }
  const bezel = Math.max(8, Math.round(Math.min(w, h) * 0.022));
  return {
    x: Math.round(x + bezel),
    y: Math.round(y + bezel),
    width: Math.max(40, Math.round(w - bezel * 2)),
    height: Math.max(40, Math.round(h - bezel * 2)),
  };
}

function buildDeviceFrameElements(frameSlot, imageSlot, framePlacement, imageUrl, imageMeta = {}, themeTokens = null) {
  const kind = deviceFrameKindFromSlot(frameSlot);
  const isPhone = kind === 'phone' || kind === 'phone_landscape';
  const fitted = fitDeviceFramePlacement(framePlacement, kind);
  const screen = insetScreenRect(fitted, kind);
  const radius = kind === 'phone' ? 28 : kind === 'phone_landscape' ? 34 : 10;
  const nest = isPhone ? 0 : 2;
  const phoneShadow = '0 22px 54px rgba(15,23,42,0.22), 0 4px 12px rgba(15,23,42,0.12)';
  const portraitShadow = 'inset 0 0 0 1px rgba(226,232,240,0.28), 0 28px 64px rgba(15,23,42,0.18), 0 8px 18px rgba(15,23,42,0.08)';
  const chrome = deviceFrameChromeColors(themeTokens, kind);
  const elements = [];
  elements.push({
    id: newElementId('frm'),
    slotId: frameSlot.id,
    type: 'shape',
    layer: 8,
    placement: fitted,
    content: {
      shape: 'rect',
      fill: chrome.fill,
      stroke: chrome.stroke,
      strokeWidth: chrome.strokeWidth,
      borderRadius: radius,
      shadow: kind === 'phone' ? portraitShadow : isPhone ? phoneShadow : '0 8px 24px rgba(15,23,42,0.18)',
      boxShadow: kind === 'phone' ? portraitShadow : isPhone ? phoneShadow : '0 8px 24px rgba(15,23,42,0.18)',
      deviceFrame: kind,
      layoutSurface: true,
    },
    role: 'device_frame',
  });
  const imageInset = {
    x: screen.x + nest,
    y: screen.y + (kind === 'laptop' ? Math.max(8, Math.round(screen.height * 0.07)) : nest),
    width: Math.max(20, screen.width - nest * 2),
    height: Math.max(
      20,
      screen.height - (kind === 'laptop' ? Math.max(8, Math.round(screen.height * 0.07)) + nest : nest * 2)
    ),
  };
  const { shadow: _shadow, boxShadow: _boxShadow, ...screenMeta } = imageMeta || {};
  elements.push({
    id: newElementId('img'),
    slotId: imageSlot.id,
    type: 'image',
    layer: 10,
    placement: imageInset,
    content: {
      ...screenMeta,
      url: imageUrl || null,
      fit: 'cover',
      borderRadius: kind === 'phone' ? 28 : kind === 'phone_landscape' ? 22 : 6,
      shadow: undefined,
      boxShadow: undefined,
    },
    role: 'image',
  });
  return elements;
}

function newElementId(prefix = 'el') {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

const IMAGE_PRESENTATION = {
  hero: {
    borderRadius: 18,
    shadow: '0 14px 40px rgba(15, 23, 42, 0.14), 0 4px 14px rgba(99, 102, 241, 0.12)',
  },
  featured: {
    borderRadius: 14,
    shadow: '0 10px 28px rgba(15, 23, 42, 0.1), 0 2px 8px rgba(99, 102, 241, 0.08)',
  },
  card: {
    borderRadius: 12,
    shadow: '0 6px 18px rgba(15, 23, 42, 0.08)',
  },
  inset: {
    borderRadius: 8,
    shadow: '0 2px 10px rgba(15, 23, 42, 0.06)',
  },
  flat: { borderRadius: 0, shadow: null },
};

function inferImageStyle(slotId) {
  const id = String(slotId || '').toUpperCase();
  // Full-bleed backgrounds must be edge-to-edge (no rounded corners / grey gutters).
  if (id === 'BACKGROUND_IMAGE') return 'flat';
  if (id === 'HERO_IMAGE') return 'hero';
  if (/^IMAGE_\d+$|^COL_\d+_IMAGE$|^METRIC_IMAGE/.test(id)) return 'card';
  if (/^DEVICE_|^PHONE_|^LAPTOP_|^TABLET_|^WATCH_/.test(id)) return 'inset';
  return 'featured';
}

function resolveImagePresentation(slot = {}) {
  const key = slot.imageStyle || inferImageStyle(slot.id);
  return IMAGE_PRESENTATION[key] || IMAGE_PRESENTATION.inset;
}

/** Where indexed slots (stat_1, member_2, …) look for their list of entries. */
const LIST_SOURCE_KEYS = {
  stat: ['stats', 'metrics'],
  metric: ['stats', 'metrics'],
  member: ['team', 'members', 'people'],
  milestone: ['milestones', 'timeline', 'events'],
  card: ['cards', 'features', 'items', 'plans', 'tiers'],
  feature: ['features', 'cards', 'plans'],
  item: ['items', 'plans', 'tiers'],
  column: ['columns'],
  plan: ['plans', 'tiers', 'pricing', 'cards'],
  price: ['plans', 'tiers', 'pricing'],
  tier: ['tiers', 'plans', 'pricing'],
};

const INDEXED_SLOT_RE = /^(stat|metric|member|milestone|card|feature|item|column|plan|price|tier)_(\d+)$/;
const MEMBER_FIELD_RE = /^member_(\d+)_(name|role|email|title|bio|body|desc)$/;
const PLAN_FIELD_RE = /^plan_(\d+)_(label|name|price|body)$/;
const AGENDA_ITEM_RE = /^agenda_col_(\d+)_item_(\d+)$/;
const AGENDA_HEADING_RE = /^agenda_col_(\d+)_heading$/;
const DEPT_HEADING_RE = /^dept_(\d+)_heading$/;
const CARD_FIELD_RE = /^card_(\d+)_(title|body)$/;
const COL_FIELD_RE = /^col_(\d+)_(title|body)$/;
const ROW_FIELD_RE = /^row_(\d+)_(title|body)$/;
const FEATURE_FIELD_RE = /^feature_(\d+)_(title|body|text)$/;
/** Phone-highlights: FEATURE_L1_HEADING / FEATURE_R2_BODY → columns[0..5] in L1,L2,L3,R1,R2,R3 order */
const FEATURE_SIDE_FIELD_RE = /^feature_([lr])(\d+)_(heading|body|title|text)$/;
/** Phone-triple side copy: HEADING_L / BODY_R */
const SIDE_HEADING_BODY_RE = /^(heading|body)_([lr])$/;
const MILESTONE_PART_RE = /^milestone_(\d+)_(label|detail)$/;
const QUADRANT_FIELD_RE = /^q(\d+)_(title|body)$/;
const STEP_FIELD_RE = /^step_(\d+)_(title|body)$/;
const FUNNEL_FIELD_RE = /^funnel_(\d+)_(title|body)$/;
const ITEM_FIELD_RE = /^item_(\d+)$/i;
const QUOTE_SLOT_RE = /^quote_(\d+)$/;
const ATTR_SLOT_RE = /^attr_(\d+)$/;
const NAME_SLOT_RE = /^name_(\d+)$/;
const ROLE_SLOT_RE = /^role_(\d+)$/;
const CONTACT_VALUE_RE = /^contact_(address|phone|email)$/;
const CENTERED_LAYOUT_RE = /centered|thank_you|big_number|banner/;
const MAIN_TITLE_SLOT_RE = /^(main_title|title|headline|heading)$/;
const INDEXED_BODY_SLOT_RE =
  /^(body|left_body|right_body|statement|lead|caption|footnote|intro|body_\d+|bullet_\d+|card_\d+_body|col_\d+_body|feature_\d+_(body|text)|agenda_col_\d+_item_\d+|item_\d+|bullet_\d+)$/;

/** Coerce AI/slot payloads to plain text — never return objects (React cannot render them). */
function coerceSlotText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'object') {
    if (Array.isArray(value)) {
      return value.map(coerceSlotText).filter(Boolean).join('\n');
    }
    const nested = value.text ?? value.body ?? value.title ?? value.label ?? value.heading;
    if (nested != null && nested !== value) return coerceSlotText(nested);
    return '';
  }
  return String(value);
}

function itemToText(item) {
  if (item === null || item === undefined) return '';
  if (typeof item === 'string') return item.trim();
  if (typeof item !== 'object') return String(item);
  const head = item.value ?? item.number ?? item.date ?? item.year ?? item.period ?? '';
  const label = item.label ?? item.title ?? item.name ?? item.heading ?? '';
  const role = item.role ?? item.subtitle ?? '';
  const detail = item.text ?? item.body ?? item.description ?? item.summary ?? '';
  return [head, label, role, detail]
    .map((part) => coerceSlotText(part).trim())
    .filter(Boolean)
    .join('\n');
}

function itemsToTexts(value) {
  if (!Array.isArray(value)) return [];
  return value.map(itemToText).filter(Boolean);
}

function bulletBlock(list) {
  return list.map((line) => `• ${line}`).join('\n');
}

function stripMarkdownBold(text) {
  return String(text || '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/__(.+?)__/g, '$1');
}

function parseBulletLineRuns(line, mutedRole = 'muted', textRole = 'text') {
  const raw = typeof line === 'string' ? line.trim() : itemToText(line);
  if (!raw) return null;
  const cleaned = raw.replace(/^•\s*/, '');
  const mdMatch = cleaned.match(/^\*\*(.+?)\*\*:\s*(.+)$/);
  if (mdMatch) {
    return [
      { text: '• ', colorRole: textRole },
      { text: `${mdMatch[1]}:`, fontWeight: 700, colorRole: textRole },
      { text: ` ${stripMarkdownBold(mdMatch[2])}`, colorRole: mutedRole },
    ];
  }
  // **Label** without required colon (common AI variant)
  const mdLoose = cleaned.match(/^\*\*(.+?)\*\*\s*[:\-—–]?\s*(.*)$/);
  if (mdLoose && mdLoose[1]) {
    const label = mdLoose[1].trim();
    const detail = stripMarkdownBold(mdLoose[2] || '').trim();
    if (detail) {
      return [
        { text: '• ', colorRole: textRole },
        { text: `${label}:`, fontWeight: 700, colorRole: textRole },
        { text: ` ${detail}`, colorRole: mutedRole },
      ];
    }
    return [
      { text: '• ', colorRole: textRole },
      { text: label, fontWeight: 700, colorRole: textRole },
    ];
  }
  const colonMatch = cleaned.match(/^([^:]{2,40}):\s*(.+)$/);
  if (colonMatch) {
    return [
      { text: '• ', colorRole: textRole },
      { text: `${colonMatch[1]}:`, fontWeight: 700, colorRole: textRole },
      { text: ` ${stripMarkdownBold(colonMatch[2])}`, colorRole: mutedRole },
    ];
  }
  if (line && typeof line === 'object' && (line.topic || line.label)) {
    const topic = String(line.topic ?? line.label ?? '').trim();
    const detail = String(line.text ?? line.body ?? '').trim();
    if (topic && detail) {
      return [
        { text: '• ', colorRole: textRole },
        { text: `${topic}:`, fontWeight: 700, colorRole: textRole },
        { text: ` ${stripMarkdownBold(detail)}`, colorRole: mutedRole },
      ];
    }
  }
  return [{ text: `• ${stripMarkdownBold(cleaned)}`, colorRole: mutedRole }];
}

function buildBulletListRuns(content, onImage = false) {
  const items = bulletsOf(content);
  if (!items.length) return null;
  const textRole = onImage ? 'textOnImage' : 'text';
  const mutedRole = onImage ? 'textOnImageMuted' : 'muted';
  const runs = [];
  items.forEach((item, index) => {
    const lineRuns = parseBulletLineRuns(item, mutedRole, textRole);
    if (!lineRuns) return;
    if (index > 0) runs.push({ text: '\n', colorRole: mutedRole });
    runs.push(...lineRuns);
  });
  if (!runs.length) return null;
  return {
    text: bulletBlock(items.map((item) => stripMarkdownBold(typeof item === 'string' ? item : itemToText(item)))),
    runs,
  };
}

function applyMarkdownRunsToPlainText(textContent, onImage = false) {
  if (!textContent || textContent.runs?.length) return textContent;
  const raw = String(textContent.text || '');
  if (!raw.includes('**') && !raw.includes('__')) return textContent;
  const textRole = onImage ? 'textOnImage' : 'text';
  const mutedRole = onImage ? 'textOnImageMuted' : 'muted';
  const lines = raw.split('\n');
  const runs = [];
  lines.forEach((line, index) => {
    if (index > 0) runs.push({ text: '\n', colorRole: mutedRole });
    const trimmed = line.trim();
    if (/^•/.test(trimmed) || /^\*\*/.test(trimmed)) {
      const lineRuns = parseBulletLineRuns(trimmed, mutedRole, textRole);
      if (lineRuns) {
        runs.push(...lineRuns);
        return;
      }
    }
    // Inline **bold** spans within a normal body line
    const parts = trimmed.split(/(\*\*[^*]+\*\*)/g).filter((p) => p.length);
    if (parts.length > 1) {
      parts.forEach((part) => {
        const bold = part.match(/^\*\*(.+)\*\*$/);
        if (bold) runs.push({ text: bold[1], fontWeight: 700, colorRole: textRole });
        else runs.push({ text: part, colorRole: mutedRole });
      });
      return;
    }
    runs.push({ text: stripMarkdownBold(line), colorRole: mutedRole });
  });
  return {
    ...textContent,
    text: stripMarkdownBold(raw),
    runs,
  };
}

function applyRichBulletsToTextContent(textContent, content, slotId, onImage = false) {
  const id = String(slotId || '').toLowerCase();
  if (id === 'bullets' || id === 'bullet_list') {
    const rich = buildBulletListRuns(content, onImage);
    if (rich) return { ...textContent, text: rich.text, runs: rich.runs };
  }
  // Per-column / body slots: parse or strip markdown so `**` never shows raw.
  if (
    /^bullet_\d+$/.test(id) ||
    /^body_\d+$/.test(id) ||
    /^card_\d+_body$/.test(id) ||
    /^col_\d+_body$/.test(id) ||
    id === 'body' ||
    id === 'left_body' ||
    id === 'right_body'
  ) {
    return applyMarkdownRunsToPlainText(textContent, onImage);
  }
  if (String(textContent?.text || '').includes('**')) {
    return applyMarkdownRunsToPlainText(textContent, onImage);
  }
  return textContent;
}

function bulletsOf(content) {
  return itemsToTexts(content.bullets);
}

function listForKind(kind, content) {
  const keys = LIST_SOURCE_KEYS[kind] || [`${kind}s`];
  for (const key of keys) {
    const list = itemsToTexts(content[key]);
    if (list.length) return list;
  }
  return [];
}

function objectListForKind(kind, content) {
  const keys = LIST_SOURCE_KEYS[kind] || [`${kind}s`];
  for (const key of keys) {
    const raw = content[key];
    if (Array.isArray(raw) && raw.length) return raw;
  }
  return [];
}

function memberAt(content, index) {
  const list = objectListForKind('member', content);
  const item = list[index];
  if (!item) return '';
  if (typeof item === 'string') return item.trim();
  return item;
}

function planAt(content, index) {
  const list = objectListForKind('plan', content);
  return list[index] || null;
}

function agendaColumnAt(content, colIndex) {
  const columns = content.agenda?.columns;
  if (!Array.isArray(columns)) return null;
  return columns[colIndex] || null;
}

function structuredColumnAt(content, colIndex) {
  const lists = [content.columns, content.cards, content.features];
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    const col = list[colIndex];
    if (col != null) return col;
  }
  return null;
}

/** Map FEATURE_L1..L3,R1..R3 → 0..5 */
function featureSideColumnIndex(side, num) {
  const n = Number(num) || 1;
  const s = String(side || '').toLowerCase();
  if (s === 'l') return Math.max(0, n - 1);
  if (s === 'r') return 3 + Math.max(0, n - 1);
  return Math.max(0, n - 1);
}

function titleLinesFromContent(content = {}) {
  const title = String(content.title || '').trim();
  const fromTitle = title.split(/\n+/).map((s) => s.trim()).filter(Boolean);
  if (fromTitle.length >= 2) return { line1: fromTitle[0], line2: fromTitle.slice(1).join(' ') };
  const runs = Array.isArray(content.titleRuns)
    ? content.titleRuns.map((r) => String(r?.text || '').trim()).filter(Boolean)
    : [];
  if (runs.length >= 2) return { line1: runs[0], line2: runs.slice(1).join(' ') };
  if (fromTitle.length === 1) return { line1: fromTitle[0], line2: '' };
  if (runs.length === 1) return { line1: runs[0], line2: '' };
  return { line1: title, line2: '' };
}

function isMainTitleSlot(slotId, role) {
  const lower = String(slotId || '').toLowerCase();
  const r = String(role || '').toLowerCase();
  if (MAIN_TITLE_SLOT_RE.test(lower)) return true;
  if (r === 'heading' && MAIN_TITLE_SLOT_RE.test(lower)) return true;
  return false;
}

function primaryStat(content) {
  const raw = content.stat || (Array.isArray(content.stats) ? content.stats[0] : null);
  if (!raw) return { value: '', label: '' };
  if (typeof raw === 'string') return { value: raw, label: content.subtitle || '' };
  return {
    value: String(raw.value ?? raw.number ?? '').trim(),
    label: String(raw.label ?? raw.title ?? raw.text ?? content.subtitle ?? '').trim(),
  };
}

function sideOf(content, side) {
  const src = content[side] || content.comparison?.[side] || {};
  const items = itemsToTexts(src.bullets || src.items || src.points);
  return {
    title: String(src.title || src.label || '').trim(),
    body: items.length ? bulletBlock(items) : String(src.body || src.text || '').trim(),
  };
}

function linesOf(value) {
  if (Array.isArray(value)) return itemsToTexts(value).join('\n');
  if (value && typeof value === 'object') return itemToText(value);
  return String(value || '').trim();
}

function tableRowsOf(content) {
  const table = content.table;
  if (!table) return [];
  const rows = Array.isArray(table) ? table : Array.isArray(table.rows) ? table.rows : [];
  const headers = Array.isArray(table?.headers) ? [table.headers] : [];
  return [...headers, ...rows].map((row) => (Array.isArray(row) ? row.map((c) => String(c ?? '')) : [String(row)]));
}

function chartDatasetAt(content, index) {
  if (!content || typeof content !== 'object') return null;
  if (Array.isArray(content.charts) && content.charts[index]) return content.charts[index];
  if (index === 0 && content.chart) return content.chart;
  if (index === 1 && content.chart2) return content.chart2;
  return null;
}

function chartForSlot(slotId, content = {}) {
  const id = String(slotId || '').toUpperCase();
  const chartMatch = id.match(/^CHART_(\d+)$/);
  if (chartMatch) {
    return chartDatasetAt(content, Number(chartMatch[1]) - 1);
  }
  if (/^(MAIN_CHART|DONUT_CHART|LINE_CHART|BAR_CHART|KPI_CHART)/.test(id)) {
    return content.chart || null;
  }
  return content.chart || null;
}

/** Distinct demo datasets so empty CHART_1/2/3 slots all render. */
function sampleChartDataset(index = 0, layoutId = '') {
  const i = Math.max(0, Number(index) || 0);
  if (/donut|pie/i.test(String(layoutId || ''))) {
    const sets = [
      { labels: ['A', 'B', 'C', 'D'], values: [40, 25, 20, 15] },
      { labels: ['A', 'B', 'C', 'D'], values: [30, 30, 25, 15] },
      { labels: ['A', 'B', 'C', 'D'], values: [50, 20, 18, 12] },
    ];
    return sets[i % sets.length];
  }
  const sets = [
    { labels: ['Q1', 'Q2', 'Q3', 'Q4'], values: [42, 58, 51, 67] },
    { labels: ['Q1', 'Q2', 'Q3', 'Q4'], values: [28, 36, 44, 39] },
    { labels: ['Q1', 'Q2', 'Q3', 'Q4'], values: [55, 48, 62, 71] },
  ];
  return sets[i % sets.length];
}

/** True only for real chart data slots — not CHART_HEADING / CHART_CAPTION / titles. */
function isChartElementSlot(slotId, role) {
  if (String(role || '').toLowerCase() === 'chart') return true;
  const id = String(slotId || '').toUpperCase();
  if (/^(MAIN_CHART|DONUT_CHART|LINE_CHART|BAR_CHART|KPI_CHART|PIE_CHART)(_|$)/.test(id)) {
    return true;
  }
  if (/^CHART_\d+$/.test(id)) return true;
  return false;
}

function resolveChartTypeForSlot(slot, chartData, content, layoutSchema) {
  const explicit = String(chartData?.type || chartData?.chartType || '').trim().toLowerCase();
  if (explicit) return explicit;
  const slotType = String(slot?.chartType || slot?.chart_type || '').trim().toLowerCase();
  if (slotType) return slotType;
  const slotId = String(slot?.id || '').toUpperCase();
  const layoutId = String(layoutSchema?.layout_id || '').toLowerCase();
  if (/^DONUT/.test(slotId) || /donut|pie/.test(layoutId)) return 'donut';
  if (/^LINE/.test(slotId) || /line|exponential|area/.test(layoutId)) return 'line';
  const title = `${content?.title || ''} ${content?.summary || ''} ${content?.body || ''}`.toLowerCase();
  const values = chartData?.series?.[0]?.values || chartData?.data || chartData?.values || [];
  const nums = (Array.isArray(values) ? values : []).map(Number).filter((value) => !Number.isNaN(value));
  const sum = nums.reduce((total, value) => total + value, 0);
  if (
    /share|percent|distribution|breakdown|producing|market share|composition|mix|split|portion/.test(title) ||
    (nums.length >= 3 && sum >= 85 && sum <= 115)
  ) {
    return 'donut';
  }
  if (/trend|growth|over time|trajectory|year-over-year|yoy/.test(title)) return 'line';
  return 'column-grouped';
}

function diagramCellAt(content, index) {
  const cells =
    content.diagram?.cells ||
    content.cells ||
    content.quadrants ||
    content.steps ||
    content.funnel ||
    [];
  return Array.isArray(cells) ? cells[index] : null;
}

function titleWordsFromBodyLocal(body, fallback) {
  const words = String(body || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 4)
    .join(' ');
  return words || fallback || '';
}

function layoutHasDedicatedColumnTitleSlots(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((s) => /^(card|col|row|feature)_\d+_title$/i.test(String(s.id || '')));
}

function resolveColumnTitleCandidate(col, index, slideTitle, seen, fallbackPrefix) {
  let title = String(col?.title ?? col?.heading ?? col?.label ?? '').trim();
  const body = String(col?.body ?? col?.text ?? col?.description ?? '').trim();
  const titleLower = title.toLowerCase();
  if (!title || titleLower === slideTitle || seen.has(titleLower)) {
    const fromBody = titleWordsFromBodyLocal(body, '');
    const fromBodyLower = String(fromBody || '')
      .trim()
      .toLowerCase();
    if (fromBody && fromBodyLower !== slideTitle && !seen.has(fromBodyLower)) {
      title = fromBody;
    } else {
      title = `${fallbackPrefix} ${index + 1}`;
    }
  }
  return title;
}

function uniqueColumnTitle(rawTitle, body, index, content, fallbackPrefix = 'Aspect') {
  const slideTitle = String(content?.title || '').trim().toLowerCase();
  const cols = content?.columns || content?.cards || content?.features || [];
  const seen = new Set();
  // Rebuild uniqueness from prior columns the same way we rewrite them, so `seen`
  // includes rewritten titles (not only raw LLM duplicates of the slide title).
  if (Array.isArray(cols)) {
    for (let i = 0; i < index; i += 1) {
      const resolved = resolveColumnTitleCandidate(cols[i], i, slideTitle, seen, fallbackPrefix);
      if (resolved) seen.add(resolved.toLowerCase());
    }
  }
  return resolveColumnTitleCandidate(
    { title: rawTitle, body },
    index,
    slideTitle,
    seen,
    fallbackPrefix
  );
}

function textForSlot(slotId, content = {}, layoutSchema = null) {
  const id = String(slotId || '').toLowerCase();
  const bullets = bulletsOf(content);

  const milestonePlain = id.match(/^milestone_(\d+)$/);
  if (milestonePlain) {
    const milestones = objectListForKind('milestone', content);
    const raw = milestones[Number(milestonePlain[1]) - 1];
    if (!raw) return '';
    if (typeof raw === 'string') return raw.trim();
    const label = String(raw.label ?? raw.date ?? raw.year ?? raw.period ?? raw.title ?? '').trim();
    const detail = String(raw.detail ?? raw.body ?? raw.text ?? raw.description ?? '').trim();
    if (label && detail) return `${label}\n${detail}`;
    return label || detail;
  }

  const indexed = id.match(INDEXED_SLOT_RE);
  if (indexed) {
    const index = Number(indexed[2]) - 1;
    if (indexed[1] === 'milestone') {
      const milestones = objectListForKind('milestone', content);
      const raw = milestones[index];
      if (!raw) return bullets[index] || '';
      if (typeof raw === 'string') return raw.trim();
      const label = String(raw.label ?? raw.date ?? raw.year ?? raw.period ?? raw.title ?? '').trim();
      const detail = String(raw.detail ?? raw.body ?? raw.text ?? raw.description ?? '').trim();
      if (label && detail) return `${label}\n${detail}`;
      return label || detail || itemToText(raw);
    }
    return listForKind(indexed[1], content)[index] || bullets[index] || '';
  }

  const memberField = id.match(MEMBER_FIELD_RE);
  if (memberField) {
    const member = memberAt(content, Number(memberField[1]) - 1);
    if (!member || typeof member !== 'object') return typeof member === 'string' ? member : '';
    const field = memberField[2];
    if (field === 'name') return String(member.name ?? '').trim();
    if (field === 'role' || field === 'title') return String(member.role ?? member.title ?? '').trim();
    if (field === 'email') return String(member.email ?? '').trim();
    if (field === 'bio' || field === 'body' || field === 'desc') {
      return String(member.bio ?? member.body ?? member.description ?? '').trim();
    }
  }

  const quadrantField = id.match(QUADRANT_FIELD_RE);
  if (quadrantField) {
    const cell = diagramCellAt(content, Number(quadrantField[1]) - 1);
    if (!cell) return '';
    if (quadrantField[2] === 'title') {
      return String(cell.title ?? cell.label ?? cell.heading ?? '').trim();
    }
    return String(cell.body ?? cell.text ?? cell.detail ?? '').trim();
  }

  const stepField = id.match(STEP_FIELD_RE);
  if (stepField) {
    const cell = diagramCellAt(content, Number(stepField[1]) - 1);
    if (!cell) return '';
    if (stepField[2] === 'title') {
      return String(cell.title ?? cell.label ?? cell.step ?? '').trim();
    }
    return String(cell.body ?? cell.text ?? cell.detail ?? '').trim();
  }

  const funnelField = id.match(FUNNEL_FIELD_RE);
  if (funnelField) {
    const list = content.funnel || content.diagram?.cells || content.cells || [];
    const cell = Array.isArray(list) ? list[Number(funnelField[1]) - 1] : null;
    if (!cell) return '';
    if (funnelField[2] === 'title') {
      return String(cell.title ?? cell.label ?? '').trim();
    }
    return String(cell.body ?? cell.text ?? '').trim();
  }

  const quoteSlot = id.match(QUOTE_SLOT_RE);
  if (quoteSlot) {
    const quotes = content.quotes || content.testimonials || (content.quote ? [content.quote] : []);
    const raw = Array.isArray(quotes) ? quotes[Number(quoteSlot[1]) - 1] : null;
    if (typeof raw === 'string') return raw.trim();
    return String(raw?.text ?? raw?.quote ?? '').trim();
  }

  const nameSlot = id.match(NAME_SLOT_RE);
  if (nameSlot) {
    const attrs = content.testimonials || content.attributions || content.quotes || [];
    const raw = Array.isArray(attrs) ? attrs[Number(nameSlot[1]) - 1] : null;
    if (typeof raw === 'string') return raw.trim();
    return String(raw?.name ?? raw?.author ?? raw?.attribution ?? '').trim();
  }

  const roleSlot = id.match(ROLE_SLOT_RE);
  if (roleSlot) {
    const attrs = content.testimonials || content.attributions || content.quotes || [];
    const raw = Array.isArray(attrs) ? attrs[Number(roleSlot[1]) - 1] : null;
    if (typeof raw === 'string') return '';
    return String(raw?.role ?? raw?.title ?? raw?.org ?? raw?.company ?? '').trim();
  }

  const attrSlot = id.match(ATTR_SLOT_RE);
  if (attrSlot) {
    const attrs = content.testimonials || content.attributions || [];
    const raw = Array.isArray(attrs) ? attrs[Number(attrSlot[1]) - 1] : null;
    if (typeof raw === 'string') return raw.trim();
    return String(raw?.name ?? raw?.attribution ?? raw?.author ?? '').trim();
  }

  const planField = id.match(PLAN_FIELD_RE);
  if (planField) {
    const plan = planAt(content, Number(planField[1]) - 1);
    if (!plan) return '';
    const field = planField[2];
    if (field === 'label' || field === 'name') return String(plan.label ?? plan.name ?? '').trim();
    if (field === 'price') return String(plan.price ?? '').trim();
    if (field === 'body') {
      const items = Array.isArray(plan.items) ? plan.items : Array.isArray(plan.bullets) ? plan.bullets : [];
      return items.length ? items.map((item) => String(item ?? '').trim()).filter(Boolean).join('\n') : String(plan.body ?? '').trim();
    }
  }

  const agendaHeading = id.match(AGENDA_HEADING_RE);
  if (agendaHeading) {
    const col = agendaColumnAt(content, Number(agendaHeading[1]) - 1);
    return String(col?.heading ?? col?.title ?? '').trim();
  }

  const agendaItem = id.match(AGENDA_ITEM_RE);
  if (agendaItem) {
    const col = agendaColumnAt(content, Number(agendaItem[1]) - 1);
    const items = Array.isArray(col?.items) ? col.items : [];
    return String(items[Number(agendaItem[2]) - 1] ?? '').trim();
  }

  const cardField = id.match(CARD_FIELD_RE);
  if (cardField) {
    const col = structuredColumnAt(content, Number(cardField[1]) - 1);
    if (!col) return '';
    if (cardField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(cardField[1]) - 1,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const colField = id.match(COL_FIELD_RE);
  if (colField) {
    const col = structuredColumnAt(content, Number(colField[1]) - 1);
    if (!col) return '';
    if (colField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(colField[1]) - 1,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const rowField = id.match(ROW_FIELD_RE);
  if (rowField) {
    const col = structuredColumnAt(content, Number(rowField[1]) - 1);
    if (!col) return '';
    if (rowField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(rowField[1]) - 1,
        content,
        'Pillar'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const featureField = id.match(FEATURE_FIELD_RE);
  if (featureField) {
    const col = structuredColumnAt(content, Number(featureField[1]) - 1);
    if (!col) return '';
    if (featureField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(featureField[1]) - 1,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const featureSide = id.match(FEATURE_SIDE_FIELD_RE);
  if (featureSide) {
    const idx = featureSideColumnIndex(featureSide[1], featureSide[2]);
    const col = structuredColumnAt(content, idx);
    if (!col) return '';
    const field = featureSide[3];
    if (field === 'heading' || field === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        idx,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const sideHeadingBody = id.match(SIDE_HEADING_BODY_RE);
  if (sideHeadingBody) {
    const side = sideHeadingBody[2];
    const idx = side === 'l' ? 0 : 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      if (sideHeadingBody[1] === 'heading') {
        return uniqueColumnTitle(
          col.title ?? col.heading ?? col.label,
          col.body ?? col.text,
          idx,
          content,
          'Aspect'
        );
      }
      return String(col.body ?? col.text ?? itemToText(col)).trim();
    }
    const sideCopy = sideOf(content, side === 'l' ? 'left' : 'right');
    return sideHeadingBody[1] === 'heading' ? sideCopy.title : sideCopy.body;
  }

  if (id === 'heading_2') {
    const { line2 } = titleLinesFromContent(content);
    if (line2) return line2;
    return String(content.subtitle || '').trim();
  }

  if (id === 'subheading') {
    return (
      String(content.subtitle || '').trim() ||
      String(content.summary || '')
        .split(/[.!?]/)[0]
        ?.trim() ||
      ''
    );
  }

  const milestonePart = id.match(MILESTONE_PART_RE);
  if (milestonePart) {
    const milestones = objectListForKind('milestone', content);
    const raw = milestones[Number(milestonePart[1]) - 1];
    if (!raw) return '';
    if (typeof raw === 'string') {
      return milestonePart[2] === 'label' ? raw.trim() : '';
    }
    if (milestonePart[2] === 'label') {
      return String(raw.label ?? raw.date ?? raw.year ?? raw.period ?? raw.title ?? '').trim();
    }
    return String(raw.detail ?? raw.body ?? raw.text ?? raw.description ?? '').trim();
  }

  const itemSlot = id.match(ITEM_FIELD_RE);
  if (itemSlot) {
    const index = Number(itemSlot[1]) - 1;
    const fromItems = itemsToTexts(content.items);
    if (fromItems[index]) return fromItems[index];
    if (bullets[index]) return bullets[index];
    const col = structuredColumnAt(content, index);
    if (col) return itemToText(col);
    return '';
  }

  const deptHeading = id.match(DEPT_HEADING_RE);
  if (deptHeading) {
    const depts = content.departments || content.agenda?.columns;
    const dept = Array.isArray(depts) ? depts[Number(deptHeading[1]) - 1] : null;
    return String(dept?.heading ?? dept?.title ?? '').trim();
  }

  const contactValue = id.match(CONTACT_VALUE_RE);
  if (contactValue) {
    const contact = content.contact && typeof content.contact === 'object' ? content.contact : {};
    return String(contact[contactValue[1]] ?? '').trim();
  }

  if (id === 'contact_address_label' || id === 'contact_phone_label' || id === 'contact_email_label') {
    return id.includes('address') ? 'Address' : id.includes('phone') ? 'Phone' : 'Email';
  }

  switch (id) {
    case 'stat_value':
      return primaryStat(content).value;
    case 'stat_label':
      return primaryStat(content).label;
    case 'lead':
      return itemToText(content.lead) || listForKind('member', content)[0] || '';
    case 'center_body':
      return String(content.diagram?.center ?? content.center ?? content.overlap ?? '').trim();
    case 'attribution':
      return String(content.attribution || content.author || content.name || content.source || '').trim();
    case 'name':
      return String(content.name || content.author || content.attribution || '').trim();
    case 'role':
      return String(content.role || content.authorTitle || content.titleLine || '').trim();
    case 'cta':
      return String(
        content.cta ||
          content.callToAction ||
          content.closingCta ||
          (content.title ? `Explore ${String(content.title).split(/\s+/).slice(0, 3).join(' ')}` : '') ||
          'Learn more'
      ).trim();
    case 'contact':
      return linesOf(content.contact);
    case 'caption':
    case 'footnote':
      return String(content.caption || content.footnote || content.note || '').trim();
    case 'main_title':
      return String(content.title || '').trim();
    case 'section_number':
      return String(content.sectionNumber ?? content.section_number ?? '').trim();
    case 'left_title':
      return sideOf(content, 'left').title;
    case 'right_title':
      return sideOf(content, 'right').title;
    case 'left_body':
      return sideOf(content, 'left').body;
    case 'right_body':
      return sideOf(content, 'right').body;
    case 'pros_title':
      return String(content.prosTitle || content.comparison?.prosTitle || 'Pros').trim();
    case 'cons_title':
      return String(content.consTitle || content.comparison?.consTitle || 'Cons').trim();
    case 'pros':
      return bulletBlock(itemsToTexts(content.pros).length ? itemsToTexts(content.pros) : itemsToTexts(content.left?.bullets));
    case 'cons':
      return bulletBlock(itemsToTexts(content.cons).length ? itemsToTexts(content.cons) : itemsToTexts(content.right?.bullets));
    case 'bullets_left':
    case 'bullets_right': {
      const half = Math.ceil(bullets.length / 2);
      return bulletBlock(id.endsWith('left') ? bullets.slice(0, half) : bullets.slice(half));
    }
    case 'timeline': {
      const milestones = listForKind('milestone', content);
      return bulletBlock(milestones.length ? milestones : bullets);
    }
    case 'members': {
      const members = listForKind('member', content);
      return bulletBlock(members.length ? members : bullets);
    }
    case 'left_items':
    case 'right_items': {
      const milestones = listForKind('milestone', content);
      const source = milestones.length ? milestones : bullets;
      const half = Math.ceil(source.length / 2);
      return bulletBlock(id.startsWith('left') ? source.slice(0, half) : source.slice(half));
    }
    case 'table': {
      const rows = tableRowsOf(content);
      return rows.map((row) => row.join('   |   ')).join('\n');
    }
    default:
      break;
  }

  if (id === 'heading') {
    const { line1, line2 } = titleLinesFromContent(content);
    if (line1 && line2) return `${line1}\n${line2}`;
    return String(content.title || line1 || '').trim();
  }

  const metricTitle = id.match(/^metric_title_(\d+)$/);
  if (metricTitle) {
    const col = content.columns?.[Number(metricTitle[1]) - 1];
    return String(col?.title ?? col?.heading ?? '').trim();
  }
  const metricBody = id.match(/^metric_body_(\d+)$/);
  if (metricBody) {
    const col = content.columns?.[Number(metricBody[1]) - 1];
    return String(col?.body ?? col?.text ?? '').trim();
  }

  const statValue = id.match(/^stat_(\d+)_value$/);
  if (statValue) {
    const stat = content.stats?.[Number(statValue[1]) - 1];
    return String(stat?.value ?? stat?.number ?? '').trim();
  }
  const statLabel = id.match(/^stat_(\d+)_label$/);
  if (statLabel) {
    const stat = content.stats?.[Number(statLabel[1]) - 1];
    return String(stat?.label ?? stat?.title ?? stat?.text ?? '').trim();
  }

  const imageLabelSlot = id.match(/^image_(\d+)_label$/);
  if (imageLabelSlot) {
    const idx = Number(imageLabelSlot[1]) - 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        idx,
        content,
        'Gallery'
      );
    }
    const items = Array.isArray(content.items) ? content.items : [];
    const item = items[idx];
    if (typeof item === 'string') {
      return uniqueColumnTitle(item, '', idx, content, 'Gallery');
    }
    if (item) {
      return uniqueColumnTitle(
        item.title ?? item.label ?? item.heading,
        item.body ?? item.text,
        idx,
        content,
        'Gallery'
      );
    }
    return `Gallery ${idx + 1}`;
  }

  const bulletSlot = id.match(/^bullet_(\d+)$/);
  if (bulletSlot) {
    const idx = Number(bulletSlot[1]) - 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      const title = String(col.title ?? col.heading ?? col.label ?? '').trim();
      const body = String(col.body ?? col.text ?? '').trim();
      // When layout has dedicated title slots, body/bullet slots must not repeat the title.
      if (layoutHasDedicatedColumnTitleSlots(layoutSchema)) {
        return body || itemToText(col) || '';
      }
      if (title && body) return `${title}\n${body}`;
      return body || title || itemToText(col);
    }
    return bullets[idx] || '';
  }

  if (
    id.includes('title') &&
    !id.includes('subtitle') &&
    // Never flood indexed process/card/column/row slots with the slide title.
    !/^metric_|^plan_|^col_|^card_|^row_|^feature_|^point_|^member_|^agenda_col_|^step_|^phase_|^item_/.test(
      id
    )
  ) {
    return coerceSlotText(content.title).trim();
  }
  if (id.includes('subtitle')) {
    return (
      coerceSlotText(content.subtitle).trim() ||
      coerceSlotText(content.summary).trim() ||
      (typeof content.body === 'string' ? content.body.split(/[.!?]/)[0]?.trim() : '') ||
      ''
    );
  }
  if (id === 'name' || id === 'author_name') {
    return String(content.name || content.author || content.attribution || '').trim();
  }
  if (id === 'role' || id === 'author_title') {
    return String(content.role || content.authorTitle || content.titleLine || '').trim();
  }
  if (id.includes('quote') || id === 'statement') {
    return coerceSlotText(content.quote || content.body).trim();
  }
  if (id === 'bullets' || id === 'bullet_list') return bulletBlock(bullets);

  const indexedBody = id.match(/^body_(\d+)$/);
  if (indexedBody) {
    const idx = Number(indexedBody[1]) - 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      const title = String(col.title ?? col.heading ?? col.label ?? '').trim();
      const body = String(col.body ?? col.text ?? '').trim();
      if (layoutHasDedicatedColumnTitleSlots(layoutSchema)) {
        return body || itemToText(col) || '';
      }
      if (title && body) return `${title}\n${body}`;
      return body || title || itemToText(col);
    }
    if (bullets[idx]) return bullets[idx];
    return '';
  }

  if (INDEXED_BODY_SLOT_RE.test(id)) {
    if (id === 'body') {
      if (content.body) return coerceSlotText(content.body).trim();
      if (content.summary) return coerceSlotText(content.summary).trim();
      if (bullets.length) return bulletBlock(bullets);
      return '';
    }
    if ((id === 'left_body' || id === 'right_body') && content[id]) {
      return coerceSlotText(content[id]).trim();
    }
    return '';
  }
  if (id === 'accent') return '';
  return '';
}

/**
 * Typography defaults per slot so compiled decks read like a designed template
 * instead of one uniform text size.
 */
function styleForSlot(slotId, layoutSchema) {
  const id = String(slotId || '').toLowerCase();
  const centered = CENTERED_LAYOUT_RE.test(String(layoutSchema?.layout_id || '').toLowerCase());
  const centerable = centered ? 'center' : 'left';

  if (id === 'stat_value') return { fontSize: 54, bold: true, align: centerable };
  if (id === 'stat_label') return { fontSize: 22, bold: false, align: centerable };
  if (/^stat_\d+_value$/.test(id)) return { fontSize: 44, bold: true, align: 'left' };
  if (/^stat_\d+_label$/.test(id)) return { fontSize: 16, bold: false, align: 'left' };
  if (id === 'section_number') return { fontSize: 54, bold: true, align: 'left' };
  if (/^(stat|metric)_\d+$/.test(id)) return { fontSize: 30, bold: true, align: 'left' };
  if (id === 'cta') return { fontSize: 22, bold: true, align: 'center' };
  if (id === 'caption' || id === 'eyebrow') return { fontSize: 14, bold: false, align: 'left' };
  if (id === 'attribution') return { fontSize: 16, bold: false, align: centerable };
  if (id.includes('quote')) return { fontSize: 28, bold: false, align: centerable };
  if (id.includes('subtitle')) return { fontSize: 24, bold: false, align: centerable };
  if (id === 'left_title' || id === 'right_title') return { fontSize: 24, bold: true, align: 'left' };
  if (id.includes('title')) return { fontSize: 42, bold: true, align: centerable };
  return { fontSize: 18, bold: false, align: 'left' };
}

const {
  fontSizeForTextSlot: canvasFontSizeForTextSlot,
  resolveTypeScaleFontSize,
} = require('./canvasTypography');

function paletteColor(palette, role, fallback) {
  if (!palette || !role) return fallback;
  return palette[role] || fallback;
}

function isOverlayLayout(layoutSchema, designTokens) {
  if (designTokens?.backgroundStyle === 'image' || designTokens?.textContrast === 'high') {
    return true;
  }
  const layoutId = String(layoutSchema?.layout_id || '');
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  if (slots.some((s) => s.id === 'BACKGROUND_IMAGE' || /OVERLAY_SCRIM/i.test(String(s.id || '')))) {
    return true;
  }
  if (/full_bg|overlay|statement_top|statement_bottom/i.test(layoutId)) {
    return true;
  }
  return false;
}

function overlayColorRoleForSlot(role, ty = {}, overlayActive) {
  if (!overlayActive) return null;
  if (ty.colorRole === 'textOnImage' || ty.colorRole === 'textOnImageMuted') return ty.colorRole;
  if (role === 'caption' || role === 'eyebrow' || role === 'subheading' || role === 'body') {
    return 'textOnImageMuted';
  }
  return 'textOnImage';
}

function mergeDesignTokensWithTheme(designTokens, themeTokens, layoutSchema) {
  const overlay = isOverlayLayout(layoutSchema, designTokens);
  const defaults = themeTokens?.overlayDefaults || {};
  if (!overlay) return designTokens || null;
  return {
    backgroundStyle: designTokens?.backgroundStyle || defaults.backgroundStyle || 'image',
    overlayOpacity:
      designTokens?.overlayOpacity != null
        ? designTokens.overlayOpacity
        : defaults.overlayOpacity != null
          ? defaults.overlayOpacity
          : 0.45,
    textContrast: designTokens?.textContrast || defaults.textContrast || 'high',
  };
}

function resolveFill(shapeSpec, palette = {}) {
  if (!shapeSpec) return { type: 'solid', colorRole: 'primary' };
  if (typeof shapeSpec.fill === 'string') {
    return { type: 'solid', colorRole: shapeSpec.fill };
  }
  if (shapeSpec.fill && typeof shapeSpec.fill === 'object') {
    if (shapeSpec.fill.type === 'gradient') {
      return {
        type: 'gradient',
        direction: shapeSpec.fill.direction || '135deg',
        stops: (shapeSpec.fill.stops || []).map((stop) => ({
          color: stop.color || paletteColor(palette, stop.colorRole, '#0B1220'),
          colorRole: stop.colorRole || null,
          position: stop.position != null ? stop.position : 0,
        })),
      };
    }
    return {
      type: 'solid',
      color:
        shapeSpec.fill.color ||
        paletteColor(palette, shapeSpec.fill.colorRole || shapeSpec.fillColorRole, null),
      colorRole: shapeSpec.fill.colorRole || shapeSpec.fillColorRole || 'primary',
    };
  }
  if (shapeSpec.fillColorRole) {
    return {
      type: 'solid',
      color: paletteColor(palette, shapeSpec.fillColorRole, null),
      colorRole: shapeSpec.fillColorRole,
    };
  }
  return { type: 'solid', colorRole: 'primary' };
}

function resolveTextStyle(slot, layoutSchema, themeTokens, designTokens, placement, canvasWidth) {
  const slotId = slot.id || '';
  const role = String(slot.role || '').toLowerCase();
  const ty = slot.typography || {};
  const fallback = styleForSlot(slotId, layoutSchema);
  const scale = themeTokens?.typeScale || {};
  const palette = themeTokens?.palette || {};
  const mergedDesignTokens = mergeDesignTokensWithTheme(designTokens, themeTokens, layoutSchema);
  const overlayActive = isOverlayLayout(layoutSchema, mergedDesignTokens);

  const typographyRole = inferTypographyRole({ slot, layoutSchema });
  let fontSize = ty.fontSize;
  if (fontSize == null) {
    const semanticSize =
      typographyRole === 'heroTitle'
        ? scale.display
        : typographyRole === 'title' || typographyRole === 'sectionTitle'
          ? scale.title
          : typographyRole === 'subtitle'
            ? scale.subtitle
            : typographyRole === 'body'
              ? scale.body
              : typographyRole === 'caption' || typographyRole === 'eyebrow' || typographyRole === 'label'
                ? scale.caption
                : typographyRole === 'metric'
                  ? scale.stat ?? scale.display
                  : null;
    if (semanticSize != null && Number(semanticSize) > 0) fontSize = Number(semanticSize);
    else fontSize = resolveTypeScaleFontSize(role, scale);
  }
  if (fontSize == null && role === 'heading' && scale.display != null) {
    fontSize = scale.display;
  }
  if (fontSize == null && placement) {
    fontSize = canvasFontSizeForTextSlot(slot, placement, canvasWidth);
  }
  if (fontSize == null) fontSize = fallback.fontSize;

  const fontWeight = ty.fontWeight != null ? Number(ty.fontWeight) : fallback.bold ? 700 : 400;
  const bold = fontWeight >= 600;
  const align = ty.align || fallback.align || 'left';
  let colorRole = ty.colorRole || null;
  if (!colorRole) {
    const overlayRole = overlayColorRoleForSlot(role, ty, overlayActive);
    if (overlayRole) {
      colorRole = overlayRole;
    } else if (role === 'stat') colorRole = 'accent';
    else if (
      role === 'caption' ||
      role === 'attribution' ||
      role === 'eyebrow' ||
      role === 'stat_label'
    ) {
      colorRole = 'muted';
    } else if (role === 'cta') colorRole = 'primary';
    else colorRole = 'text';
  }
  if (
    overlayActive &&
    (colorRole === 'text' || colorRole === 'muted')
  ) {
    const overlayRole = overlayColorRoleForSlot(role, ty, overlayActive);
    if (overlayRole) colorRole = overlayRole;
  }
  if (
    mergedDesignTokens?.textContrast === 'high' &&
    !ty.colorRole &&
    (colorRole === 'text' || colorRole === 'muted')
  ) {
    colorRole = overlayActive ? 'textOnImage' : 'text';
  }

  return {
    fontSize,
    bold,
    fontWeight,
    align,
    colorRole,
    color: paletteColor(palette, colorRole, null),
    letterSpacing: ty.letterSpacing != null ? ty.letterSpacing : undefined,
    lineHeight: ty.lineHeight != null ? ty.lineHeight : undefined,
  };
}

function elementRoleFromSlot(slot, slotId) {
  if (slot.role) return slot.role;
  const lower = String(slotId || '').toLowerCase();
  if (lower.includes('title') && !lower.includes('subtitle')) return 'title';
  if (lower.includes('subtitle')) return 'subtitle';
  if (lower.includes('bullet')) return 'body';
  if (lower.includes('footnote') || lower.includes('caption')) return 'caption';
  return slotId;
}

function isLogoSlot(slotId, role) {
  const lower = String(slotId || '').toLowerCase();
  const r = String(role || '').toLowerCase();
  return lower === 'logo' || r === 'logo' || (r === 'decoration' && lower.includes('logo'));
}

function isMediaImageSlot(slotId, role, slot) {
  const lower = String(slotId || '').toLowerCase();
  const r = String(role || '').toLowerCase();
  if (isLogoSlot(slotId, role)) return false;
  if (/^text_half_bg$/i.test(lower)) return false;
  if (/_label$/i.test(lower) || r === 'caption') return false;
  if (r === 'background' || r === 'image') return true;
  if (lower.includes('background') || lower.includes('hero')) return true;
  if (lower.includes('image') && !lower.includes('caption')) return true;
  if (slot?.fit === 'cover') return true;
  return false;
}

function resolveSlotImageUrl(slotId, content = {}, imageRef = null, layoutSchema = null) {
  const id = String(slotId || '');
  const map = content.slotImageUrls;
  if (map && typeof map === 'object') {
    if (map[id]) return map[id];
    if (map[id.toUpperCase()]) return map[id.toUpperCase()];
    if (map[id.toLowerCase()]) return map[id.toLowerCase()];
  }

  const heroUrl =
    imageRef?.url
    || imageRef?.s3Url
    || (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null)
    || null;

  let imageSlotCount = 1;
  if (layoutSchema?.slots?.length) {
    imageSlotCount = layoutSchema.slots.filter((slot) =>
      isMediaImageSlot(slot.id, slot.role, slot)
    ).length;
  }

  // Multi-image layouts: only allow hero backfill for primary full-bleed slots.
  // Secondary IMAGE_2 / COL_n slots must keep distinct per-slot URLs.
  if (imageSlotCount > 1) {
    const upper = id.toUpperCase();
    if (heroUrl && (upper === 'BACKGROUND_IMAGE' || upper === 'HERO_IMAGE')) {
      return heroUrl;
    }
    return null;
  }

  return heroUrl;
}

function resolveSlotImageS3Key(slotId, content = {}, imageRef = null, layoutSchema = null) {
  const id = String(slotId || '');
  const map = content.slotImageKeys;
  if (map && typeof map === 'object') {
    if (map[id]) return map[id];
    if (map[id.toUpperCase()]) return map[id.toUpperCase()];
    if (map[id.toLowerCase()]) return map[id.toLowerCase()];
  }

  const heroKey = imageRef?.s3Key || null;
  let imageSlotCount = 1;
  if (layoutSchema?.slots?.length) {
    imageSlotCount = layoutSchema.slots.filter((slot) =>
      isMediaImageSlot(slot.id, slot.role, slot)
    ).length;
  }
  if (imageSlotCount > 1) {
    const upper = id.toUpperCase();
    if (heroKey && (upper === 'BACKGROUND_IMAGE' || upper === 'HERO_IMAGE')) {
      return heroKey;
    }
    return null;
  }
  return heroKey;
}

function isDecorShapeSlot(slotId, role, slot) {
  if (slot?.aiOnly) return false;
  if (isLogoSlot(slotId, role) || isMediaImageSlot(slotId, role, slot)) return false;
  const r = String(role || '').toLowerCase();
  return r === 'decoration' || r === 'divider' || Boolean(slot?.shape);
}

/** Layout-authoring chrome — hidden in previews; applied at generation from AI shapeDecisions. */
function isAiOnlyShapeSlot(slot) {
  if (!slot) return false;
  const id = String(slot.id || '');
  const role = String(slot.role || '').toLowerCase();
  if (/^METRIC_CARD_\d+_BG$/.test(id)) return false;
  if (/^CARD_\d+_BG$/i.test(id)) return false;
  if (/^MILESTONE_\d+_CARD_BG$/i.test(id)) return false;
  if (/^TEXT_HALF_BG$/i.test(id)) return false;
  // Process step circles compile to real canvas nodes
  if (/^STEP_\d+_CIRCLE$/i.test(id) || slot.shapeHint?.kind === 'stepCircle') return false;
  if (/FRAME$/i.test(id) && slot.shapeHint?.pairsWithSlotId) return true;
  if (slot.aiOnly === true) return true;
  if (slot.shapeHint?.aiOnly) return true;
  if (/_BG$|CARD_BG|OVERLAY_SCRIM|CTA_BG/i.test(id)) return true;
  if (role === 'divider') return true;
  if (role === 'decoration' && slot.shape && !isLogoSlot(id, role) && !/FRAME$/i.test(id)) return true;
  if (role === 'background' && id !== 'BACKGROUND_IMAGE' && slot.shape) return true;
  if (/^ICON_\d+$/.test(id)) return true;
  return false;
}

function resolvePairsWithSlotId(slots, hintSlot) {
  const hint = hintSlot?.shapeHint || {};
  if (hint.pairsWithSlotId) return hint.pairsWithSlotId;
  const idx = slots.indexOf(hintSlot);
  for (let i = idx + 1; i < slots.length; i += 1) {
    const r = String(slots[i].role || '').toLowerCase();
    if (['image', 'cta', 'heading', 'body', 'quote'].includes(r)) return slots[i].id;
  }
  return null;
}

function mergeShapeDecisions(layoutSchema, content) {
  if (!content?.shapeDecisions || typeof content.shapeDecisions !== 'object') return {};
  return { ...content.shapeDecisions };
}

function applyRuntimeShapeDecisions(doc, layoutSchema, content, themeTokens, canvas) {
  if (!doc || !layoutSchema) return doc;
  const decisions = mergeShapeDecisions(layoutSchema, content);
  const palette = themeTokens?.palette || {};
  const slots = Array.isArray(layoutSchema.slots) ? layoutSchema.slots : [];
  const slotById = Object.fromEntries(slots.map((s) => [s.id, s]));
  const elements = [...(doc.elements || [])];

  const overlayDecision = decisions.__overlay__;
  // Full-slide scrim only over near-full-bleed photos. Split heroes must not
  // darken the uncovered half into a solid grey slab.
  if (
    overlayDecision?.enabled !== false &&
    overlayDecision?.scrim > 0 &&
    docHasLoadedOverlayImage(doc)
  ) {
    const scrimColor = palette.overlayScrim || 'rgba(0,0,0,0.45)';
    elements.push({
      id: newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: { x: 0, y: 0, width: canvas.width, height: canvas.height, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        fill: { type: 'solid', color: scrimColor, colorRole: 'overlayScrim' },
        opacity: Number(overlayDecision.scrim),
      },
      role: 'design_overlay',
    });
  }

  for (const [slotId, decision] of Object.entries(decisions)) {
    if (slotId === '__overlay__') continue;
    const behind = decision?.behind || 'none';
    if (behind === 'none') continue;

    // Card/column slots get separate inset cards from applyDefaultCardShapes /
    // explicit CARD_n_BG — skip AI behind shapes so they don't merge into one bar.
    const groupKey = cardGroupKey(slotId);
    if (groupKey && (behind === 'card' || behind === 'surface')) continue;

    const targetSlot = slotById[slotId];
    const targetEl = elements.find((el) => el.slotId === slotId);
    if (!targetSlot || !targetEl) continue;

    const placement = targetEl.placement || regionToPlacement(targetSlot.region, canvas);
    let fillRole = 'cardBg';
    if (behind === 'pill') fillRole = 'accent';
    if (behind === 'surface') fillRole = 'surface';
    // Prefer accent; fall back to primary when accent missing from palette.
    if (behind === 'pill' && !paletteColor(palette, 'accent', null)) {
      fillRole = 'primary';
    }

    elements.unshift({
      id: newElementId('shp'),
      type: 'shape',
      slotId: `${slotId}__shape_bg`,
      layer: Math.max(0, (targetEl.layer || 10) - 2),
      placement: { ...placement },
      content: {
        shape: 'rect',
        fill: resolveFill(
          { type: 'rect', fillColorRole: fillRole, borderRadius: decision.borderRadius ?? (behind === 'pill' ? 200 : 10) },
          palette
        ),
        borderRadius: decision.borderRadius ?? (behind === 'pill' ? 200 : 10),
      },
      role: 'decoration',
    });

    // Pill behind CTA must use on-accent label (cream/white), not primary-on-primary.
    if (behind === 'pill') {
      const slotRole = String(targetSlot.role || '').toLowerCase();
      const sid = String(slotId || '').toUpperCase();
      if (
        (slotRole === 'cta' || sid === 'CTA' || /^CTA(_|$)/.test(sid)) &&
        (targetEl.type === 'text' || targetEl.type === 'textbox')
      ) {
        const onAccent =
          paletteColor(palette, 'textOnImage', null) ||
          paletteColor(palette, 'bg', null) ||
          '#FFFFFF';
        targetEl.content = {
          ...(targetEl.content || {}),
          color: onAccent,
          colorRole: 'textOnImage',
        };
        if (Array.isArray(targetEl.content.runs) && targetEl.content.runs.length) {
          targetEl.content.runs = targetEl.content.runs.map((run) => ({
            ...run,
            color: onAccent,
            colorRole: 'textOnImage',
          }));
        }
      }
    }

    if (decision.mask && decision.mask !== 'none' && targetEl.type === 'image') {
      targetEl.content = {
        ...(targetEl.content || {}),
        borderRadius: decision.borderRadius ?? 10,
      };
    }
  }

  doc.elements = elements.sort((a, b) => (a.layer || 0) - (b.layer || 0));
  return doc;
}

function isPackPlaceholderText(text) {
  const t = String(text || '').trim().toLowerCase();
  if (!t) return false;
  if (isCatalogPlaceholderText(text)) return true;
  return (
    /^your (title|subtitle|heading|headline|name|company|tagline|text|quote)/.test(t) ||
    t === 'insert text' ||
    t.startsWith('lorem ipsum') ||
    t === 'double-click to edit' ||
    t === 'double click to edit'
  );
}

function isLogoLikeElement(el) {
  const role = String(el?.role || '').toLowerCase();
  const id = String(el?.id || '').toLowerCase();
  const slotId = String(el?.slotId || '').toLowerCase();
  return role === 'logo' || id.includes('logo') || slotId.includes('logo');
}

const REBIND_TEXT_ROLES = new Set([
  'title',
  'heading',
  'headline',
  'subtitle',
  'subheading',
  'body',
  'bullets',
  'caption',
  'quote',
  'cta',
  'stat_value',
  'stat_label',
  'lead',
  'attribution',
  'table',
  'eyebrow',
  'section_number',
  'footnote',
]);

const REBIND_IMAGE_ROLES = new Set(['image', 'background', 'hero']);

function inferRoleFromKeys(role, slotId, id) {
  const r = String(role || '').toLowerCase();
  if (r) return r;
  const key = String(slotId || id || '').toLowerCase();
  if (!key) return '';
  if (key.includes('logo')) return 'logo';
  if (key.includes('subtitle')) return 'subtitle';
  if (key.includes('title') || key.includes('headline')) return 'title';
  if (key.includes('bullet') || key.includes('body')) return 'body';
  if (key.includes('caption') || key.includes('footnote')) return 'caption';
  if (key.includes('quote')) return 'quote';
  if (key.includes('hero') || key.includes('background') || key.includes('image')) return 'image';
  if (key.includes('stat')) return key.includes('label') ? 'stat_label' : 'stat_value';
  return key;
}

function resolveElementRole(el) {
  return inferRoleFromKeys(el?.role, el?.slotId, el?.id);
}

function slotKeyMatchesRebind(role, slotId, id) {
  const r = String(role || '').toLowerCase();
  if (REBIND_TEXT_ROLES.has(r) || REBIND_IMAGE_ROLES.has(r)) return true;
  const key = String(slotId || id || '').toLowerCase();
  if (!key) return false;
  return (
    key.includes('title') ||
    key.includes('subtitle') ||
    key.includes('headline') ||
    key.includes('body') ||
    key.includes('bullet') ||
    key.includes('caption') ||
    key.includes('quote') ||
    key.includes('hero') ||
    key.includes('background') ||
    key.includes('image') ||
    key.includes('stat') ||
    key.includes('table')
  );
}

function isImagePlaceholderElement(el) {
  if (!el || el.type !== 'shape') return false;
  const c = el.content || {};
  const label = String(c.label || c.text || '').trim();
  if (label === 'Image placeholder') return true;
  const role = resolveElementRole(el);
  const slotId = String(el.slotId || el.id || '').toLowerCase();
  return (
    role === 'image' ||
    role === 'background' ||
    role === 'hero' ||
    slotId.includes('hero') ||
    slotId.includes('background') ||
    (slotId.includes('image') && !slotId.includes('caption'))
  );
}

function fontFamilyForRole(role, themeTokens) {
  const fonts = themeTokens?.fonts || {};
  const r = String(role || '').toLowerCase();
  if (r === 'title' || r === 'heading' || r === 'headline' || r === 'stat_value') {
    return fonts.heading || null;
  }
  if (r === 'subtitle' || r === 'subheading') {
    return fonts.subheading || fonts.heading || null;
  }
  return fonts.body || fonts.subheading || null;
}

function applyThemeFontsToText(el, themeTokens, role) {
  if (!themeTokens?.fonts || (el.type !== 'text' && el.type !== 'textbox')) return;
  const fontFamily = fontFamilyForRole(role, themeTokens);
  if (fontFamily) {
    el.content = { ...(el.content || {}), fontFamily };
  }
}

function applyThemeColorsToText(el, themeTokens, role) {
  if (!themeTokens?.palette || (el.type !== 'text' && el.type !== 'textbox')) return;
  const existingRole = el.content?.colorRole;
  if (existingRole === 'textOnImage' || existingRole === 'textOnImageMuted') return;
  const palette = themeTokens.palette;
  const r = String(role || '').toLowerCase();
  let colorRole = el.content?.colorRole || 'text';
  if (!el.content?.colorRole) {
    if (r === 'caption' || r === 'stat_label' || r === 'attribution') colorRole = 'muted';
    else if (r === 'cta' || r === 'stat_value') colorRole = 'accent';
    else colorRole = 'text';
  }
  const color = paletteColor(palette, colorRole, el.content?.color || null);
  if (color) {
    el.content = { ...(el.content || {}), color, colorRole };
  }
}

function mediaRoleForSlot(slotId, role) {
  const lower = String(slotId || '').toLowerCase();
  const r = String(role || '').toLowerCase();
  if (r === 'background' || lower.includes('background')) return 'background';
  return 'image';
}

/**
 * Apply pack/slide designTokens chrome (bg + accent bars) when layout has no background slot.
 */
function applySlideDesignTokens(elementsDoc, designTokens, themeTokens = {}) {
  const doc = {
    version: elementsDoc?.version || 1,
    canvas: elementsDoc?.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
    elements: Array.isArray(elementsDoc?.elements) ? [...elementsDoc.elements] : [],
  };
  const canvas = doc.canvas;
  const palette = themeTokens?.palette || {};
  const appearance =
    themeTokens?.appearance === 'dark' || themeTokens?.appearance === 'light'
      ? themeTokens.appearance
      : null;
  const defaultBg = appearance === 'light' ? '#FFFFFF' : appearance === 'dark' ? '#0B1220' : palette.bg || '#FFFFFF';
  const defaultSurface =
    appearance === 'light' ? '#F8FAFC' : appearance === 'dark' ? '#121A2B' : palette.surface || defaultBg;
  const hasBg = doc.elements.some(
    (e) => e.role === 'background' || e.role === 'design_bg' || String(e.id || '').startsWith('bg_')
  );

  if (!designTokens || typeof designTokens !== 'object') {
    if (!hasBg && palette.bg) {
      doc.elements.unshift({
        id: newElementId('bg'),
        type: 'shape',
        layer: 0,
        placement: {
          x: 0,
          y: 0,
          width: canvas.width,
          height: canvas.height,
          rotation: 0,
          opacity: 1,
        },
        content: {
          shape: 'rect',
          fill: { type: 'solid', color: palette.bg, colorRole: 'bg' },
        },
        role: 'design_bg',
      });
    }
    return doc;
  }

  if (!hasBg && (designTokens?.backgroundStyle === 'gradient' || designTokens?.backgroundStyle === 'solid' || designTokens?.backgroundStyle === 'split')) {
    const fill =
      designTokens.backgroundStyle === 'gradient'
        ? {
            type: 'gradient',
            direction: '135deg',
            stops: [
              {
                color: palette.gradientStart || palette.bg || defaultBg,
                colorRole: 'gradientStart',
                position: 0,
              },
              {
                color: palette.gradientEnd || palette.surface || defaultSurface,
                colorRole: 'gradientEnd',
                position: 100,
              },
            ],
          }
        : {
            // solid + split both get an explicit stage fill (split without bg looked empty in dark mode)
            type: 'solid',
            color: palette.bg || defaultBg,
            colorRole: 'bg',
          };
    doc.elements.unshift({
      id: newElementId('bg'),
      type: 'shape',
      layer: 0,
      placement: {
        x: 0,
        y: 0,
        width: canvas.width,
        height: canvas.height,
        rotation: 0,
        opacity: 1,
      },
      content: { shape: 'rect', fill },
      role: 'design_bg',
    });
  }

  if (!hasBg && palette.bg && !designTokens?.backgroundStyle) {
    doc.elements.unshift({
      id: newElementId('bg'),
      type: 'shape',
      layer: 0,
      placement: {
        x: 0,
        y: 0,
        width: canvas.width,
        height: canvas.height,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: { type: 'solid', color: palette.bg, colorRole: 'bg' },
      },
      role: 'design_bg',
    });
  }

  const accent = designTokens?.accentPosition || 'none';
  const accentColor = palette.primary || palette.accent || '#3B82F6';
  const barBase = {
    type: 'shape',
    layer: 1,
    content: {
      shape: 'rect',
      fill: { type: 'solid', color: accentColor, colorRole: 'primary' },
    },
    role: 'design_accent',
  };
  if (accent === 'left-bar') {
    doc.elements.push({
      ...barBase,
      id: newElementId('acc'),
      placement: { x: 0, y: 0, width: 8, height: canvas.height, rotation: 0, opacity: 1 },
    });
  } else if (accent === 'top-bar') {
    doc.elements.push({
      ...barBase,
      id: newElementId('acc'),
      placement: { x: 0, y: 0, width: canvas.width, height: 8, rotation: 0, opacity: 1 },
    });
  } else if (accent === 'bottom-bar') {
    doc.elements.push({
      ...barBase,
      id: newElementId('acc'),
      placement: {
        x: 0,
        y: canvas.height - 8,
        width: canvas.width,
        height: 8,
        rotation: 0,
        opacity: 1,
      },
    });
  }

  if (designTokens.overlayOpacity > 0 && designTokens.backgroundStyle === 'image') {
    // Scrim only when an image is present — never force a dark veil on empty stages
    // (same gate for light and dark; previously dark still injected and looked blank).
    if (!docHasLoadedOverlayImage(doc)) {
      // skip
    } else {
    const scrimColor =
      palette.overlayScrim ||
      (appearance === 'light' ? 'rgba(0,0,0,0.4)' : 'rgba(0,0,0,0.5)');
    doc.elements.push({
      id: newElementId('ovl'),
      type: 'shape',
      layer: 2,
      placement: {
        x: 0,
        y: 0,
        width: canvas.width,
        height: canvas.height,
        rotation: 0,
        opacity: Number(designTokens.overlayOpacity),
      },
      content: {
        shape: 'rect',
        fill: { type: 'solid', color: scrimColor, colorRole: 'overlayScrim' },
      },
      role: 'design_overlay',
    });
    }
  }

  return doc;
}

/**
 * Compile a DECK_LAYOUT schema + slide content into freeform canvas elements.
 * @param {object} layoutSchema
 * @param {object} content
 * @param {object|null} imageRef
 * @param {{ width?: number, height?: number }} canvasSize
 * @param {{ themeTokens?: object, designTokens?: object }} opts
 */
function layoutSlotsToElements(
  layoutSchema,
  content = {},
  imageRef = null,
  canvasSize = {},
  opts = {}
) {
  const themeTokens = opts.themeTokens || content.themeTokens || null;
  const rawDesignTokens = opts.designTokens || content.designTokens || null;
  const designTokens = mergeDesignTokensWithTheme(rawDesignTokens, themeTokens, layoutSchema);
  const palette = themeTokens?.palette || {};

  const canvas = {
    width: canvasSize.width || CANVAS_WIDTH,
    height: canvasSize.height || CANVAS_HEIGHT,
  };
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const elements = [];
  let layer = 1;

  for (const slot of slots) {
    const slotId = slot.id || `slot_${layer}`;
    if (isAiOnlyShapeSlot(slot)) continue;
    const placement = regionToPlacement(slot.region, canvas, slot, slots);
    const lower = String(slotId).toLowerCase();
    const role = String(slot.role || '').toLowerCase();
    const slotLayer = slot.layer != null ? Number(slot.layer) : layer++;

    if (
      /^METRIC_CARD_\d+_BG$/.test(String(slotId)) ||
      /^CARD_\d+_BG$/i.test(String(slotId)) ||
      /^MILESTONE_\d+_CARD_BG$/i.test(String(slotId))
    ) {
      const fill = resolveFill(slot.shape || { fillColorRole: 'cardBg' }, palette);
      elements.push({
        id: newElementId('shp'),
        slotId,
        type: 'shape',
        layer: slotLayer,
        placement,
        content: {
          shape: 'rect',
          fill,
          borderRadius: slot.shape?.borderRadius ?? 12,
          layoutSurface: true,
        },
        role: 'decoration',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (/^STEP_\d+_CIRCLE$/i.test(String(slotId)) || slot.shapeHint?.kind === 'stepCircle') {
      const fill = resolveFill(slot.shape || { fillColorRole: 'accent' }, palette);
      const size = Math.min(placement.width || 80, placement.height || 80, 64);
      const cx = (placement.x ?? 0) + (placement.width || size) / 2;
      const cy = (placement.y ?? 0) + (placement.height || size) / 2;
      elements.push({
        id: newElementId('shp'),
        slotId,
        type: 'shape',
        layer: slotLayer,
        placement: {
          x: Math.round(cx - size / 2),
          y: Math.round(cy - size / 2),
          width: size,
          height: size,
          rotation: 0,
          opacity: 1,
        },
        content: {
          shape: 'ellipse',
          fill,
          layoutSurface: true,
        },
        role: 'decoration',
      });
      const stepNum = String(slotId).match(/(\d+)/)?.[1] || '';
      if (stepNum) {
        elements.push({
          id: newElementId('txt'),
          slotId: `${slotId}_NUM`,
          type: 'text',
          layer: slotLayer + 1,
          placement: {
            x: Math.round(cx - size / 2),
            y: Math.round(cy + size / 2 + 4),
            width: size,
            height: 28,
            rotation: 0,
            opacity: 1,
          },
          content: {
            text: String(stepNum),
            align: 'center',
            fontSize: 16,
            fontWeight: 700,
            colorRole: 'text',
            color: paletteColor(palette, 'text', null),
          },
          role: 'caption',
        });
      }
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 2);
      continue;
    }

    if (/^TEXT_HALF_BG$/i.test(String(slotId))) {
      const fill = resolveFill(slot.shape || { fillColorRole: 'surface' }, palette);
      elements.push({
        id: newElementId('shp'),
        slotId,
        type: 'shape',
        layer: slotLayer,
        placement,
        content: {
          shape: 'rect',
          fill,
          borderRadius: slot.shape?.borderRadius ?? 0,
          layoutSurface: true,
        },
        role: 'decoration',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (isLogoSlot(slotId, role)) {
      elements.push({
        id: newElementId('logo'),
        type: 'image',
        layer: slotLayer,
        placement,
        content: {
          url: null,
          fit: 'contain',
          alt: 'Brand logo',
        },
        role: 'logo',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (isMediaImageSlot(slotId, role, slot)) {
      let url = resolveSlotImageUrl(slotId, content, imageRef, layoutSchema);
      const s3Key = resolveSlotImageS3Key(slotId, content, imageRef, layoutSchema);
      const frameSlot = findDeviceFrameSlot(slots, slotId);
      if (frameSlot) {
        const framePlacement = regionToPlacement(frameSlot.region, canvas, frameSlot, slots);
        const presentation = resolveImagePresentation(slot);
        const frameEls = buildDeviceFrameElements(frameSlot, slot, framePlacement, url, {
          ...(presentation.borderRadius != null ? { borderRadius: presentation.borderRadius } : {}),
          ...(presentation.shadow ? { boxShadow: presentation.shadow, shadow: presentation.shadow } : {}),
          alt: content.title || '',
          ...(s3Key ? { s3Key } : {}),
        }, themeTokens);
        elements.push(...frameEls);
        if (slot.layer == null) layer = Math.max(layer, slotLayer + 3);
        continue;
      }
      const presentation = resolveImagePresentation(slot);
      const edgeFade = resolveSplitImageEdgeFade(layoutSchema, slot);
      const imageMask = slot.imageMask && typeof slot.imageMask === 'object' ? slot.imageMask : null;
      const shaped = Boolean(imageMask && imageMask.type && imageMask.type !== 'edgeFade');
      const isFullBleedBg = String(slotId || '').toUpperCase() === 'BACKGROUND_IMAGE';
      const borderRadius =
        edgeFade != null || shaped || isFullBleedBg
          ? 0
          : slot.borderRadius != null
            ? slot.borderRadius
            : presentation.borderRadius;
      const shadow =
        edgeFade != null || shaped || isFullBleedBg
          ? undefined
          : slot.shadow ?? presentation.shadow;
      const palette = themeTokens?.palette || {};
      elements.push({
        id: newElementId('img'),
        slotId,
        type: 'image',
        layer: slotLayer,
        placement,
        content: {
          url,
          ...(s3Key ? { s3Key } : {}),
          fit: slot.fit || 'cover',
          alt: content.title || '',
          // Never leave a naked null URL — editor shows a themed skeleton instead of broken <img>.
          ...(!url
            ? {
                placeholderFill:
                  palette.surface ||
                  palette.cardBg ||
                  palette.bg ||
                  'linear-gradient(145deg, #e2e8f0 0%, #cbd5e1 100%)',
              }
            : {}),
          ...(borderRadius != null ? { borderRadius } : {}),
          ...(shadow ? { boxShadow: shadow, shadow } : {}),
          ...(edgeFade ? { edgeFade } : {}),
          ...(imageMask && !edgeFade ? { imageMask } : {}),
        },
        role: mediaRoleForSlot(slotId, role),
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (isDecorShapeSlot(slotId, role, slot)) {
      const isIconSlot = /icon|avatar/i.test(String(slotId || ''));
      const fill = resolveFill(
        slot.shape || {
          fillColorRole: role === 'divider' ? 'accent' : isIconSlot ? 'primary' : 'primary',
        },
        palette
      );
      let iconPlacement = placement;
      if (isIconSlot && !slot.shape) {
        const size = Math.round(Math.min(placement.width, placement.height) * 0.36);
        iconPlacement = {
          x: Math.round(placement.x + (placement.width - size) / 2),
          y: Math.round(placement.y + (placement.height - size) / 2),
          width: Math.max(size, 28),
          height: Math.max(size, 28),
          rotation: placement.rotation || 0,
          opacity: placement.opacity != null ? placement.opacity : 1,
        };
      }
      elements.push({
        id: newElementId('shp'),
        type: 'shape',
        layer: slotLayer,
        placement: iconPlacement,
        content: {
          shape: slot.shape?.type || (isIconSlot ? 'ellipse' : 'rect'),
          fill,
          borderRadius: slot.shape?.borderRadius,
        },
        role: role || (lower === 'accent' ? 'accent' : slotId),
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (lower === 'accent' || lower === 'band' || lower === 'axis' || slot.fit === 'fill') {
      elements.push({
        id: newElementId('shp'),
        type: 'shape',
        layer: slotLayer,
        placement,
        content: {
          shape: 'rect',
          fill: {
            type: 'solid',
            colorRole: lower === 'axis' ? 'secondary' : 'primary',
            color: paletteColor(palette, lower === 'axis' ? 'secondary' : 'primary', null),
          },
        },
        role: lower === 'accent' ? 'accent' : slotId,
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if ((lower === 'table' || role === 'table') && tableRowsOf(content).length) {
      elements.push({
        id: newElementId('tbl'),
        type: 'table',
        layer: slotLayer,
        placement,
        content: { rows: tableRowsOf(content) },
        role: 'table',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (isChartElementSlot(slotId, role)) {
      let chartData = chartForSlot(slotId, content);
      // Multi-chart layouts must still emit CHART_2/CHART_3 when datasets are missing
      if (!chartData && /^CHART_\d+$/i.test(String(slotId))) {
        const idx = Math.max(0, Number(String(slotId).match(/(\d+)/)?.[1] || 1) - 1);
        chartData = sampleChartDataset(idx, layoutSchema?.layout_id);
      }
      const brandChartColors = themeTokens?.brand?.chartColors;
      const rawChart = {
        chartType: resolveChartTypeForSlot(slot, chartData || content.chart || {}, content, layoutSchema),
        labels: chartData?.labels || content.chart?.labels || [],
        series: chartData?.series || chartData?.data || content.chart?.series || content.chart?.data || [],
        values: chartData?.values || content.chart?.values,
        colors:
          (Array.isArray(chartData?.colors) && chartData.colors.length ? chartData.colors : null) ||
          (Array.isArray(content.chart?.colors) && content.chart.colors.length ? content.chart.colors : null) ||
          (Array.isArray(content.colors) && content.colors.length ? content.colors : null) ||
          (Array.isArray(brandChartColors) && brandChartColors.length ? brandChartColors : []),
        brandChartColors,
      };
      elements.push({
        id: newElementId('cht'),
        type: 'chart',
        layer: slotLayer,
        placement,
        slotId,
        content: normalizeChartContent(rawChart, themeTokens?.palette || {}),
        role: 'chart',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    const text = coerceSlotText(textForSlot(slotId, content, layoutSchema));
    const isMainTitle = isMainTitleSlot(slotId, role);
    const style = resolveTextStyle(
      slot,
      layoutSchema,
      themeTokens,
      designTokens,
      placement,
      canvas.width
    );
    const onImage = layoutRequiresOverlayScrim(layoutSchema);
    let textContent = {
      text: text || (isMainTitle ? coerceSlotText(content.title) : ''),
      fontSize: style.fontSize,
      bold: style.bold,
      fontWeight: style.fontWeight,
      align: style.align,
    };
    if (style.color) textContent.color = style.color;
    if (style.colorRole) textContent.colorRole = style.colorRole;
    if (style.letterSpacing != null) textContent.letterSpacing = style.letterSpacing;
    if (style.lineHeight != null) textContent.lineHeight = style.lineHeight;
    textContent = applyRichTitleToTextContent(textContent, content, slotId, role, onImage);
    textContent = applyRichBulletsToTextContent(textContent, content, slotId, onImage);
    const slotRole = elementRoleFromSlot(slot, slotId);
    const fontFamily = fontFamilyForRole(slotRole, themeTokens);
    if (fontFamily) textContent.fontFamily = fontFamily;
    const pad = textPaddingForRole(slotRole || role);
    textContent.padding = pad.y;
    textContent.paddingX = pad.x;

    elements.push({
      id: newElementId('txt'),
      slotId,
      type: 'text',
      layer: slotLayer,
      placement,
      content: textContent,
      role: elementRoleFromSlot(slot, slotId),
    });
    if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
  }

  if (opts.packColumnStacks === true) {
    packColumnTextStacks(elements);
  }

  if (elements.length === 0 && (content.title || content.body)) {
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: 1,
      placement: { x: 120, y: 120, width: 1680, height: 160, rotation: 0, opacity: 1 },
      content: { text: content.title || '', fontSize: 42, bold: true, align: 'left' },
      role: 'title',
    });
    if (content.body || (content.bullets && content.bullets.length)) {
      const bodyText =
        content.body ||
        (Array.isArray(content.bullets)
          ? content.bullets.map((b) => `• ${typeof b === 'string' ? b : b?.text || ''}`).join('\n')
          : '');
      elements.push({
        id: newElementId('txt'),
        type: 'text',
        layer: 2,
        placement: { x: 120, y: 320, width: 1680, height: 600, rotation: 0, opacity: 1 },
        content: { text: bodyText, fontSize: 20, bold: false, align: 'left' },
        role: 'body',
      });
    }
  }

  const hasImageEl = elements.some((e) => e.type === 'image');
  const layoutHasImageSlot = slots.some((s) => isMediaImageSlot(s.id, s.role, s));
  const imageUrl =
    imageRef?.url ||
    imageRef?.s3Url ||
    (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null) ||
    null;
  if (imageUrl && !hasImageEl && layoutHasImageSlot) {
    elements.push({
      id: newElementId('img'),
      type: 'image',
      layer: layer++,
      placement: {
        x: Math.round(canvas.width * 0.55),
        y: Math.round(canvas.height * 0.13),
        width: Math.round(canvas.width * 0.38),
        height: Math.round(canvas.height * 0.74),
        rotation: 0,
        opacity: 1,
      },
      content: {
        url: imageUrl,
        fit: 'cover',
        alt: content.title || '',
      },
      role: 'image',
    });
  }

  let doc = { version: 1, canvas, elements };
  doc = applySlideDesignTokens(doc, designTokens, themeTokens);
  if (opts.applyShapes !== false) {
    const hasShapeDecisions =
      content?.shapeDecisions &&
      typeof content.shapeDecisions === 'object' &&
      Object.keys(content.shapeDecisions).length > 0;
    if (hasShapeDecisions) {
      doc = applyRuntimeShapeDecisions(doc, layoutSchema, content, themeTokens, canvas);
    }
    doc = finalizeElementsDoc(doc, layoutSchema, content, themeTokens, canvas);
  }
  return doc;
}

/**
 * Empty canvas for blank slides.
 */
function blankCanvas(opts = {}) {
  const withDefaultText = opts.withDefaultText === true;
  const width = Number(opts.width) > 0 ? Number(opts.width) : CANVAS_WIDTH;
  const height = Number(opts.height) > 0 ? Number(opts.height) : CANVAS_HEIGHT;
  const canvas = { width, height };
  const elements = [];
  if (withDefaultText) {
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: 1,
      placement: {
        x: Math.round(width * 0.1),
        y: Math.round(height * 0.37),
        width: Math.round(width * 0.8),
        height: Math.round(height * 0.11),
        rotation: 0,
        opacity: 1,
      },
      content: { text: 'Double-click to edit', fontSize: 32, bold: false, align: 'center' },
      role: 'title',
    });
  }
  return { version: 1, canvas, elements };
}

/**
 * Inject or replace a brand logo image element (title/closing slides).
 * @param {object} elementsDoc
 * @param {{ url?: string, s3Key?: string }|null} logo
 * @param {{ contentType?: string|null, force?: boolean }} opts
 */
function injectBrandLogo(elementsDoc, logo, opts = {}) {
  const doc =
    elementsDoc && typeof elementsDoc === 'object'
      ? {
          version: elementsDoc.version || 1,
          canvas: elementsDoc.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
          elements: Array.isArray(elementsDoc.elements) ? [...elementsDoc.elements] : [],
        }
      : blankCanvas();

  const url = logo?.url || null;
  if (!url) return doc;

  const contentType = String(opts.contentType || '').toLowerCase();
  const allowTypes = new Set(['title', 'closing', 'section_divider', '']);
  if (!opts.force && contentType && !allowTypes.has(contentType)) {
    const hasLogo = doc.elements.some(
      (e) => e?.role === 'logo' || String(e?.id || '').toLowerCase().includes('logo')
    );
    if (!hasLogo) return doc;
  }

  const canvas = doc.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  const logoPlacement = {
    x: Math.round(canvas.width * 0.04),
    y: Math.round(canvas.height * 0.04),
    width: Math.round(canvas.width * 0.14),
    height: Math.round(canvas.height * 0.1),
    rotation: 0,
    opacity: 1,
  };

  const existingIdx = doc.elements.findIndex(
    (e) => e?.role === 'logo' || String(e?.id || '').toLowerCase().includes('logo')
  );
  const logoEl = {
    id: existingIdx >= 0 ? doc.elements[existingIdx].id : newElementId('logo'),
    type: 'image',
    layer: existingIdx >= 0 ? doc.elements[existingIdx].layer : 99,
    placement:
      existingIdx >= 0 && doc.elements[existingIdx].placement
        ? doc.elements[existingIdx].placement
        : logoPlacement,
    content: {
      url,
      s3Key: logo.s3Key || null,
      fit: 'contain',
      alt: 'Brand logo',
    },
    role: 'logo',
  };

  if (existingIdx >= 0) {
    doc.elements[existingIdx] = logoEl;
  } else if (!contentType || allowTypes.has(contentType) || opts.force) {
    doc.elements.push(logoEl);
  }

  return doc;
}

/**
 * Rebind generated slide content into an existing canvas by element role.
 * Preserves placement/chrome; updates text/image payloads in place.
 */
function placementOverlapRatio(a, b) {
  const ax = a?.x ?? 0;
  const ay = a?.y ?? 0;
  const aw = a?.width ?? 0;
  const ah = a?.height ?? 0;
  const bx = b?.x ?? 0;
  const by = b?.y ?? 0;
  const bw = b?.width ?? 0;
  const bh = b?.height ?? 0;
  const overlapW = Math.max(0, Math.min(ax + aw, bx + bw) - Math.max(ax, bx));
  const overlapH = Math.max(0, Math.min(ay + ah, by + bh) - Math.max(ay, by));
  const textArea = Math.max(1, aw * ah);
  return (overlapW * overlapH) / textArea;
}

function hasOverlappingTextPlacements(elementsDoc) {
  const list = Array.isArray(elementsDoc?.elements) ? elementsDoc.elements : [];
  const textEls = list.filter((el) => el.type === 'text' || el.type === 'textbox');
  for (let i = 0; i < textEls.length; i += 1) {
    const a = textEls[i].placement || {};
    for (let j = i + 1; j < textEls.length; j += 1) {
      const b = textEls[j].placement || {};
      const overlapX = (a.x ?? 0) < (b.x ?? 0) + (b.width ?? 0) && (b.x ?? 0) < (a.x ?? 0) + (a.width ?? 0);
      const overlapY = (a.y ?? 0) < (b.y ?? 0) + (b.height ?? 0) && (b.y ?? 0) < (a.y ?? 0) + (a.height ?? 0);
      if (overlapX && overlapY) {
        const overlapArea =
          Math.max(0, Math.min((a.x ?? 0) + (a.width ?? 0), (b.x ?? 0) + (b.width ?? 0)) - Math.max(a.x ?? 0, b.x ?? 0)) *
          Math.max(0, Math.min((a.y ?? 0) + (a.height ?? 0), (b.y ?? 0) + (b.height ?? 0)) - Math.max(a.y ?? 0, b.y ?? 0));
        const minArea = Math.min((a.width ?? 1) * (a.height ?? 1), (b.width ?? 1) * (b.height ?? 1));
        if (overlapArea > minArea * 0.15) return true;
      }
    }
  }
  return false;
}

function layoutRequiresOverlayScrim(layoutSchema) {
  if (!layoutSchema || typeof layoutSchema !== 'object') return false;
  const layoutId = String(layoutSchema.layout_id || '');
  const slots = Array.isArray(layoutSchema.slots) ? layoutSchema.slots : [];
  if (
    slots.some(
      (s) =>
        s.id === 'BACKGROUND_IMAGE' || /OVERLAY_SCRIM/i.test(String(s.id || ''))
    )
  ) {
    return true;
  }
  return /full_bg|overlay|statement_top|statement_bottom/i.test(layoutId);
}

/** True only when a near-full-bleed background image is present with a URL. */
function docHasLoadedOverlayImage(doc) {
  const elements = Array.isArray(doc?.elements) ? doc.elements : [];
  const canvas = doc?.canvas || {};
  const cw = canvas.width || CANVAS_WIDTH;
  const ch = canvas.height || CANVAS_HEIGHT;
  const minArea = cw * ch * 0.7;
  return elements.some((el) => {
    if (el.type !== 'image') return false;
    if (!el.content?.url) return false;
    const slotId = String(el.slotId || '').toUpperCase();
    const role = String(el.role || '').toLowerCase();
    // BACKGROUND_IMAGE / explicit background role always qualifies.
    if (slotId === 'BACKGROUND_IMAGE' || role === 'background' || el.content?.useAsBackground) {
      return true;
    }
    // Split HERO_IMAGE (half-slide) must NOT qualify — full-slide scrim greys the empty half.
    const p = el.placement || {};
    return (p.width || 0) * (p.height || 0) >= minArea;
  });
}

function ensureOverlayScrim(doc, layoutSchema, content, themeTokens, canvas) {
  if (!doc || !layoutRequiresOverlayScrim(layoutSchema)) return doc;
  // Never darken a slide that never got an image — that produces empty dark slides.
  if (!docHasLoadedOverlayImage(doc)) return doc;
  const elements = Array.isArray(doc.elements) ? doc.elements : [];
  const hasScrim = elements.some(
    (el) =>
      el.role === 'design_overlay' ||
      String(el.slotId || '').toUpperCase() === 'OVERLAY_SCRIM'
  );
  if (hasScrim) return doc;

  const overlayDecision = content?.shapeDecisions?.__overlay__;
  const scrimOpacity =
    overlayDecision?.scrim != null ? Number(overlayDecision.scrim) : 0.45;
  const palette = themeTokens?.palette || {};
  const scrimColor = palette.overlayScrim || 'rgba(0,0,0,0.45)';

  return {
    ...doc,
    elements: [
      ...elements,
      {
        id: newElementId('shp'),
        slotId: 'OVERLAY_SCRIM',
        type: 'shape',
        layer: 1,
        placement: { x: 0, y: 0, width: canvas.width, height: canvas.height, rotation: 0, opacity: 1 },
        content: {
          shape: 'rect',
          fill: { type: 'solid', color: scrimColor, colorRole: 'overlayScrim' },
          opacity: scrimOpacity,
        },
        role: 'design_overlay',
      },
    ],
  };
}

/** Remove full-slide scrims that were injected without a full-bleed image. */
function stripInvalidOverlayScrims(doc) {
  if (!doc || docHasLoadedOverlayImage(doc)) return doc;
  const elements = Array.isArray(doc.elements) ? doc.elements : [];
  const next = elements.filter(
    (el) =>
      el.role !== 'design_overlay' &&
      String(el.slotId || '').toUpperCase() !== 'OVERLAY_SCRIM'
  );
  if (next.length === elements.length) return doc;
  return { ...doc, elements: next };
}

function applyTextOverImageContrast(elementsDoc, themeTokens = null, layoutSchema = null) {
  if (!elementsDoc || !Array.isArray(elementsDoc.elements)) return elementsDoc;
  const palette = themeTokens?.palette || {};
  const forceOverlay =
    layoutRequiresOverlayScrim(layoutSchema) && docHasLoadedOverlayImage(elementsDoc);
  const images = elementsDoc.elements.filter((el) => el.type === 'image' && el.content?.url);
  if (!images.length && !forceOverlay) return elementsDoc;

  for (const el of elementsDoc.elements) {
    if (el.type !== 'text' && el.type !== 'textbox') continue;
    const placement = el.placement || {};
    // Text sitting on a light layout surface (e.g. TRIPLE_BAND) must stay dark.
    const localBg = localBackgroundHexForText(elementsDoc, el, null);
    const localLum = localBg ? parseHexLum(localBg) : null;
    if (localLum != null && localLum >= 0.45) continue;

    let maxOverlap = forceOverlay ? 1 : 0;
    if (!forceOverlay) {
      for (const img of images) {
        const sid = String(img.slotId || '');
        const isDeviceScreen = /DEVICE_IMAGE|PHONE_IMAGE|TABLET_IMAGE|LAPTOP_IMAGE|WATCH_IMAGE/i.test(
          sid
        );
        const overlap = placementOverlapRatio(placement, img.placement || {});
        if (isDeviceScreen && overlap < 0.55) continue;
        maxOverlap = Math.max(maxOverlap, overlap);
      }
    }
    if (maxOverlap <= 0.25) continue;

    const role = String(el.role || '').toLowerCase();
    const slotId = String(el.slotId || '').toLowerCase();
    const isMuted =
      role === 'body' ||
      role === 'caption' ||
      role === 'stat_label' ||
      role === 'subheading' ||
      role === 'eyebrow' ||
      slotId.includes('body') ||
      slotId.includes('bullet');
    const colorRole = isMuted ? 'textOnImageMuted' : 'textOnImage';
    el.content = {
      ...(el.content || {}),
      colorRole,
      color: paletteColor(palette, colorRole, el.content?.color || null),
    };
    if (Array.isArray(el.content?.runs) && el.content.runs.length) {
      el.content.runs = el.content.runs.map((run, idx, arr) => ({
        ...run,
        colorRole:
          idx === arr.length - 1 && (run.colorRole === 'accent' || run.colorRole === 'primary')
            ? run.colorRole
            : isMuted
              ? 'textOnImageMuted'
              : 'textOnImage',
        color: undefined,
      }));
    }
  }
  return elementsDoc;
}

// Kept for backward-compat fallback paths.
const CREAM_ON_DARK = '#F5EDE3';
const ESPRESSO_ON_LIGHT = '#2C1810';

function slideBackgroundHex(elementsDoc, themeTokens) {
  const palette = themeTokens?.palette || {};
  const bgEl = (elementsDoc?.elements || []).find(
    (e) => e.role === 'background' || e.role === 'design_bg' || String(e.id || '').startsWith('bg_')
  );
  const fill = bgEl?.content?.fill;
  if (fill?.type === 'solid' && fill.color) return fill.color;
  if (typeof fill === 'string' && fill.startsWith('#')) return fill;
  return palette.bg || palette.background || '#F5EDE3';
}

function surfaceFillHex(el) {
  const fill = el?.content?.fill;
  if (!fill) return null;
  if (typeof fill === 'string' && fill.startsWith('#')) return fill;
  if (fill?.type === 'solid' && typeof fill.color === 'string' && fill.color.startsWith('#')) {
    return fill.color;
  }
  return null;
}

/** Prefer a light layout surface under text (e.g. TRIPLE_BAND) over the slide background. */
function localBackgroundHexForText(elementsDoc, textEl, slideBg) {
  const placement = textEl?.placement || {};
  let bestHex = null;
  let bestScore = 0;
  for (const el of elementsDoc?.elements || []) {
    if (el === textEl || el.type !== 'shape') continue;
    if (el.role === 'device_frame') continue;
    const hex = surfaceFillHex(el);
    if (!hex) continue;
    if (!el.content?.layoutSurface && el.role !== 'decoration' && el.role !== 'design_bg') continue;
    const overlap = placementOverlapRatio(placement, el.placement || {});
    if (overlap < 0.35) continue;
    const area = Math.max(1, (el.placement?.width || 0) * (el.placement?.height || 0));
    const score = overlap * area;
    if (score > bestScore) {
      bestScore = score;
      bestHex = hex;
    }
  }
  return bestHex || slideBg;
}

function applyReadableTextContrast(elementsDoc, themeTokens = null, layoutSchema = null) {
  if (!elementsDoc || !Array.isArray(elementsDoc.elements)) return elementsDoc;
  const palette = themeTokens?.palette || {};
  const theme = resolveSemanticTheme(themeTokens);
  const bg = slideBackgroundHex(elementsDoc, themeTokens);
  const overlay = layoutRequiresOverlayScrim(layoutSchema);

  for (const el of elementsDoc.elements) {
    if (el.type !== 'text' && el.type !== 'textbox') continue;
    if (
      /^CYCLE_NUM_[1-4]$/i.test(String(el.slotId || '')) ||
      /^FUNNEL_NUM_[1-4]$/i.test(String(el.slotId || '')) ||
      /^PYRAMID_NUM_[1-5]$/i.test(String(el.slotId || '')) ||
      /^SWOT_LETTER_[1-4]$/i.test(String(el.slotId || '')) ||
      /^SWOT_HUB_(TITLE|SUB)$/i.test(String(el.slotId || '')) ||
      /^funnel_[1-5]_title$/i.test(String(el.slotId || '')) ||
      /^Q[1-4]_(TITLE|BODY)$/i.test(String(el.slotId || '')) ||
      /^MATRIX_(CENTER|X_LABEL|Y_LABEL)$/i.test(String(el.slotId || ''))
    ) continue;
    const role = String(el.content?.colorRole || '').toLowerCase();
    if (overlay && (role === 'textonimage' || role === 'textonimagemuted')) continue;
    // Keep on-accent CTA labels set by pill shape decisions (cream/white on accent fill).
    const elRole = String(el.role || '').toLowerCase();
    const slotKey = String(el.slotId || '').toUpperCase();
    if (
      (elRole === 'cta' || slotKey === 'CTA' || /^CTA(_|$)/.test(slotKey)) &&
      (role === 'textonimage' || role === 'textonimagemuted')
    ) {
      continue;
    }
    const colorRoleRaw = String(el.content?.colorRole || '');

    // Semantic repair target:
    // - "muted" and muted-ish roles go to body/muted token
    // - default text + heading goes to heading token
    // - accent/primary are left alone (but still repaired if contrast is insufficient)
    const normalizedColorRole = colorRoleRaw.toLowerCase();
    let desiredTextRole = 'heading';
    if (normalizedColorRole.includes('muted')) desiredTextRole = 'body';
    if (normalizedColorRole.includes('accent')) desiredTextRole = 'accent';
    if (normalizedColorRole.includes('primary')) desiredTextRole = 'primary';
    if (normalizedColorRole === 'textonimage') desiredTextRole = 'heading';

    const localBg = localBackgroundHexForText(elementsDoc, el, bg);
    const bgLum = relativeLuminance(localBg);
    const backgroundMode =
      overlay && parseHexLum(localBg) != null && parseHexLum(localBg) < 0.45
        ? 'image'
        : bgLum == null
          ? 'light'
          : bgLum < 0.45
            ? 'dark'
            : 'light';

    const beforeColor =
      el.content?.color || paletteColor(palette, el.content?.colorRole || 'text', null);

    // If the color cannot be resolved, skip (layoutToElements already sets most roles deterministically).
    if (!beforeColor) continue;

    let attempt = resolveTextColor({
      theme,
      textRole: desiredTextRole,
      backgroundMode,
      backgroundHex: localBg,
    });

    let ratio = contrastRatioCss(attempt.color, localBg);
    if (ratio == null || ratio < AA_CONTRAST_RATIO) {
      // Try the safer monotone pair.
      const fallbackRole = desiredTextRole === 'heading' || desiredTextRole === 'accent' ? 'body' : 'heading';
      attempt = resolveTextColor({
        theme,
        textRole: fallbackRole,
        backgroundMode,
        backgroundHex: localBg,
      });
      ratio = contrastRatioCss(attempt.color, localBg);
    }

    if (ratio != null && ratio >= AA_CONTRAST_RATIO) {
      const repairedRole =
        attempt.colorRole === 'muted' ? 'muted' : attempt.colorRole === 'text' ? 'text' : attempt.colorRole;
      el.content = {
        ...(el.content || {}),
        color: attempt.color,
        colorRole: repairedRole,
      };
      if (Array.isArray(el.content.runs) && el.content.runs.length) {
        el.content.runs = el.content.runs.map((run) => {
          const runRole = String(run.colorRole || '').toLowerCase();
          if (runRole === 'accent' || runRole === 'primary') return run;
          if (runRole === 'muted' && attempt.colorRole === 'muted') return run;
          return {
            ...run,
            color: attempt.color,
            colorRole: repairedRole,
          };
        });
      }
    } else {
      // Last resort: keep legacy fixed contrast colors (should rarely trigger after semantic token repair).
      const darkBg = bgLum == null ? false : bgLum < 0.45;
      const nextColor = darkBg ? CREAM_ON_DARK : ESPRESSO_ON_LIGHT;
      el.content = {
        ...(el.content || {}),
        color: nextColor,
        colorRole: darkBg ? 'textOnImage' : 'text',
      };
    }
  }
  return elementsDoc;
}

function resolveImageGenSize(slot, canvas = {}, allSlots = null) {
  if (!slot?.region) return '1024x1024';
  const slots = Array.isArray(allSlots) && allSlots.length ? allSlots : [slot];
  const placement = regionToPlacement(slot.region, canvas, slot, slots);
  const w = Number(placement.width) || 1024;
  const h = Number(placement.height) || 1024;
  const ratio = w / Math.max(1, h);
  // Prefer landscape/portrait sizes that match the slot so object-fit:cover doesn't over-zoom.
  // Half-slide heroes (~0.89) should be portrait, not square.
  if (ratio >= 1.15) return '1536x1024';
  if (ratio <= 0.95) return '1024x1536';
  return '1024x1024';
}

function isRichTitleSlot(slotId, role) {
  // Only slide-level title/quote slots get titleRuns — never CARD_/COL_/ROW_ headings.
  const id = String(slotId || '').toUpperCase();
  const r = String(role || '').toLowerCase();
  if (['MAIN_TITLE', 'HEADLINE', 'TITLE', 'QUOTE', 'STATEMENT', 'HEADING'].includes(id)) {
    return true;
  }
  if (r === 'quote' && /^(QUOTE|STATEMENT)$/i.test(id)) return true;
  // Do not treat generic role===heading as rich (would stamp slide titleRuns on every card).
  return false;
}

function deriveTitleRunsFallback(content, onImage = false) {
  const title = content?.title || content?.quote || '';
  if (!title || String(title).length < 20) return null;
  const parts = String(title).match(/[^.!?]+[.!?]+|[^.!?]+$/g) || [title];
  if (parts.length < 2) return null;
  const lead = parts.slice(0, -1).join('');
  const last = parts[parts.length - 1];
  return [
    { text: lead, colorRole: onImage ? 'textOnImage' : 'text' },
    { text: last, colorRole: 'accent', fontWeight: 700 },
  ];
}

function buildRichTitleContent(content, onImage = false) {
  let runs = Array.isArray(content?.titleRuns) ? content.titleRuns.filter((r) => r?.text) : null;
  if (!runs?.length) runs = deriveTitleRunsFallback(content, onImage);
  if (!runs?.length) return null;
  const text = runs.map((r) => String(r.text || '')).join('');
  return {
    text,
    runs: runs.map((r) => ({
      text: String(r.text || ''),
      ...(r.colorRole ? { colorRole: r.colorRole } : {}),
      ...(r.color ? { color: r.color } : {}),
      ...(r.fontWeight != null ? { fontWeight: r.fontWeight } : {}),
      ...(r.italic != null ? { italic: r.italic } : {}),
      ...(r.fontFamily ? { fontFamily: r.fontFamily } : {}),
    })),
  };
}

function applyRichTitleToTextContent(textContent, content, slotId, role, onImage = false) {
  if (!isRichTitleSlot(slotId, role)) return textContent;
  const rich = buildRichTitleContent(content, onImage);
  if (!rich) return textContent;
  return { ...textContent, text: rich.text, runs: rich.runs };
}

function cardGroupKey(slotId) {
  const id = String(slotId || '');
  let m = id.match(/^milestone_(\d+)(?:_(label|detail))?$/i);
  if (m) return `milestone_${m[1]}`;
  m = id.match(/^step_(\d+)_(title|body)$/i);
  if (m) return `step_${m[1]}`;
  m = id.match(/^STEP_(\d+)_(TITLE|BODY)$/);
  if (m) return `step_${m[1]}`;
  m = id.match(/^CARD_(\d+)_(TITLE|BODY)$/i);
  if (m) return `card_${m[1]}`;
  m = id.match(/^ROW_(\d+)_(TITLE|BODY)$/i);
  if (m) return `row_${m[1]}`;
  m = id.match(/^BULLET_(\d+)$/i);
  if (m) return `bullet_${m[1]}`;
  m = id.match(/^ITEM_(\d+)$/i);
  if (m) return `item_${m[1]}`;
  m = id.match(/^(LEFT|RIGHT)_(TITLE|BODY)$/i);
  if (m) return `${m[1].toLowerCase()}_col`;
  m = id.match(/^(PROS|CONS)(?:_TITLE)?$/i);
  if (m) return m[1].toLowerCase();
  return null;
}

function layoutHasExplicitCardBg(layoutSchema, groupKey) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const m = String(groupKey || '').match(/^(card|row|bullet|item|milestone|step)_(\d+)$/i);
  if (!m) return false;
  const kind = m[1].toLowerCase();
  const n = m[2];
  return slots.some((s) => {
    const id = String(s.id || '');
    return (
      new RegExp(`^CARD_${n}_BG$`, 'i').test(id) ||
      new RegExp(`^${kind}_${n}_BG$`, 'i').test(id) ||
      new RegExp(`^MILESTONE_${n}_CARD_BG$`, 'i').test(id) ||
      new RegExp(`^STEP_${n}_CIRCLE$`, 'i').test(id) ||
      new RegExp(`^STEP_${n}_CARD_BG$`, 'i').test(id)
    );
  });
}

function countCardGroupsInSchema(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const keys = new Set();
  for (const slot of slots) {
    const key = cardGroupKey(slot.id);
    if (key) keys.add(key);
  }
  return keys.size;
}

function isCardBackgroundElement(el) {
  if (!el || el.type !== 'shape') return false;
  const sid = String(el.slotId || '');
  if (/^(CARD|ROW)_\d+_BG$/i.test(sid)) return true;
  if (/^MILESTONE_\d+_CARD_BG$/i.test(sid)) return true;
  if (/^AUTO_CARD_BG_/i.test(sid)) return true;
  if (/__(?:shape_bg)$/i.test(sid) && cardGroupKey(sid.replace(/__shape_bg$/i, ''))) return true;
  return Boolean(el.content?.layoutSurface && /card|row|bullet|item|milestone/i.test(sid));
}

/** Separate overlapping/abutting card boxes with a gap and keep clear of slide edges. */
function separateCardBoxes(boxes, canvas, { edgeInset = 56, gap = 24 } = {}) {
  if (!boxes.length) return boxes;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sorted = [...boxes].sort((a, b) => a.x - b.x);

  for (let i = 1; i < sorted.length; i += 1) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    const prevRight = prev.x + prev.width;
    if (cur.x < prevRight + gap) {
      const mid = (prevRight + cur.x) / 2;
      const newPrevRight = mid - gap / 2;
      const newCurLeft = mid + gap / 2;
      prev.width = Math.max(40, newPrevRight - prev.x);
      const shrinkLeft = newCurLeft - cur.x;
      cur.x = newCurLeft;
      cur.width = Math.max(40, cur.width - shrinkLeft);
    }
  }

  return sorted.map((box) => {
    let x = Math.max(edgeInset, box.x);
    let y = Math.max(edgeInset * 0.35, box.y);
    let width = box.width;
    let height = box.height;
    if (x + width > canvasW - edgeInset) {
      width = Math.max(40, canvasW - edgeInset - x);
    }
    if (y + height > canvasH - edgeInset * 0.35) {
      height = Math.max(40, canvasH - edgeInset * 0.35 - y);
    }
    return { ...box, x, y, width, height };
  });
}

function centerMultiCardHeading(doc, cardGroupCount, layoutSchema = null) {
  if (!doc || cardGroupCount < 2) return doc;
  const layoutId = String(layoutSchema?.layout_id || '').toLowerCase();
  // Timeline / process layouts keep schema align (typically left) — don't force center
  if (/timeline|process_linear|process_linner|diagram_process|process_steps/.test(layoutId)) return doc;

  const canvasW = doc.canvas?.width || 1920;
  const edgeInset = 56;
  const elements = (doc.elements || []).map((el) => {
    if (el.type !== 'text' && el.type !== 'textbox') return el;
    const sid = String(el.slotId || '').toUpperCase();
    const role = String(el.role || '').toLowerCase();
    const isMainHeading =
      sid === 'HEADING' ||
      sid === 'TITLE' ||
      sid === 'MAIN_TITLE' ||
      (role === 'heading' && !/^(CARD_|ROW_|BULLET_|ITEM_|COL_|STEP_|MILESTONE_)/i.test(sid));
    if (!isMainHeading) return el;
    const p = el.placement || {};
    return {
      ...el,
      placement: {
        ...p,
        x: edgeInset,
        width: Math.max(120, canvasW - edgeInset * 2),
      },
      content: {
        ...(el.content || {}),
        align: 'center',
      },
    };
  });
  return { ...doc, elements };
}

/** Keep explicit / auto card backgrounds as separate inset cards (never one edge-to-edge bar). */
function refineExistingCardBackgrounds(doc, canvas) {
  if (!doc?.elements?.length) return doc;
  const elements = [...doc.elements];
  const idxs = [];
  const boxes = [];
  elements.forEach((el, i) => {
    if (!isCardBackgroundElement(el)) return;
    const p = el.placement || {};
    const w = Number(p.width) || 0;
    const canvasW = canvas.width || 1920;
    // Oversized bands are handled by splitOversizedCardBand
    if (w >= canvasW * 0.82) return;
    idxs.push(i);
    boxes.push({
      elIndex: i,
      x: Number(p.x) || 0,
      y: Number(p.y) || 0,
      width: w,
      height: Number(p.height) || 0,
    });
  });
  if (boxes.length < 2) return doc;
  const separated = separateCardBoxes(boxes, canvas, { edgeInset: 56, gap: 24 });
  separated.forEach((box) => {
    const el = elements[box.elIndex];
    if (!el) return;
    elements[box.elIndex] = {
      ...el,
      placement: {
        ...(el.placement || {}),
        x: Math.round(box.x),
        y: Math.round(box.y),
        width: Math.round(box.width),
        height: Math.round(box.height),
      },
      content: {
        ...(el.content || {}),
        borderRadius: el.content?.borderRadius ?? 12,
        layoutSurface: true,
      },
    };
  });
  return { ...doc, elements };
}

/**
 * If a single near-full-width surface sits behind multiple columns, split it into
 * separate inset cards (fixes the "one mint bar" look).
 */
function splitOversizedCardBand(doc, layoutSchema, themeTokens, canvas) {
  if (!doc?.elements?.length || !layoutSchema?.slots?.length) return doc;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const elements = [...doc.elements];
  const oversizedIdx = elements.findIndex((el) => {
    if (el.type !== 'shape') return false;
    const p = el.placement || {};
    const w = Number(p.width) || 0;
    const h = Number(p.height) || 0;
    if (w < canvasW * 0.82) return false;
    if (h >= canvasH * 0.88) return false; // full-bleed bg / scrim
    const sid = String(el.slotId || '');
    return (
      isCardBackgroundElement(el) ||
      /BG|shape_bg|surface|card/i.test(sid) ||
      el.content?.layoutSurface
    );
  });
  if (oversizedIdx < 0) return doc;

  const slots = layoutSchema.slots;
  const slotById = Object.fromEntries(slots.map((s) => [s.id, s]));
  const groups = new Map();
  for (const slot of slots) {
    const key = cardGroupKey(slot.id);
    if (!key) continue;
    const role = String(slot.role || '').toLowerCase();
    if (!['heading', 'body', 'subheading', 'stat'].includes(role)) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(slot);
  }
  if (groups.size < 2) return doc;

  const band = elements[oversizedIdx].placement || {};
  const pendingBoxes = [];
  for (const [key, groupSlots] of groups.entries()) {
    const placements = groupSlots
      .map((s) => {
        const el = elements.find((e) => e.slotId === s.id);
        if (el?.placement) return el.placement;
        return regionToPlacement(s.region, canvas, s, slots);
      })
      .filter(Boolean);
    if (!placements.length) continue;
    const x = Math.min(...placements.map((p) => p.x ?? 0));
    const x2 = Math.max(...placements.map((p) => (p.x ?? 0) + (p.width ?? 0)));
    const padX = 14;
    pendingBoxes.push({
      key,
      x: x - padX,
      y: Number(band.y) || Math.min(...placements.map((p) => p.y ?? 0)) - 16,
      width: Math.max(40, x2 - x + padX * 2),
      height: Number(band.height) || 320,
    });
  }
  if (pendingBoxes.length < 2) return doc;

  const separated = separateCardBoxes(pendingBoxes, canvas, { edgeInset: 56, gap: 24 });
  const palette = themeTokens?.palette || {};
  const template = elements[oversizedIdx];
  elements.splice(oversizedIdx, 1);
  for (const box of separated.reverse()) {
    elements.unshift({
      id: newElementId('shp'),
      type: 'shape',
      layer: template.layer ?? 0,
      placement: {
        x: Math.round(box.x),
        y: Math.round(box.y),
        width: Math.round(box.width),
        height: Math.round(box.height),
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: template.content?.fill || {
          type: 'solid',
          colorRole: 'cardBg',
          color: paletteColor(palette, 'cardBg', null),
        },
        borderRadius: template.content?.borderRadius ?? 12,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: `AUTO_CARD_BG_${box.key}`,
    });
  }
  return { ...doc, elements };
}

function applyDefaultCardShapes(doc, layoutSchema, content, themeTokens, canvas) {
  if (!doc || !layoutSchema?.slots?.length) return doc;
  if (isProcessLinnerLayout(layoutSchema.layout_id)) return doc;
  const decisions = content?.shapeDecisions && typeof content.shapeDecisions === 'object'
    ? content.shapeDecisions
    : {};
  const slots = layoutSchema.slots;
  const slotById = Object.fromEntries(slots.map((s) => [s.id, s]));
  const elements = [...(doc.elements || [])];
  const groups = new Map();
  const schemaCardCount = countCardGroupsInSchema(layoutSchema);

  for (const slot of slots) {
    const key = cardGroupKey(slot.id);
    if (!key) continue;
    if (layoutHasExplicitCardBg(layoutSchema, key)) continue;
    const role = String(slot.role || '').toLowerCase();
    if (!['heading', 'body', 'subheading', 'stat'].includes(role) && !/^milestone_/i.test(slot.id)) continue;
    if (decisions[slot.id]?.behind === 'none') continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(slot);
  }

  const pendingBoxes = [];
  for (const [key, groupSlots] of groups.entries()) {
    if (elements.some((el) => String(el.slotId || '') === `AUTO_CARD_BG_${key}`)) continue;
    const targetIds = groupSlots.map((s) => s.id);
    if (targetIds.some((id) => decisions[id]?.behind === 'none')) continue;
    const placements = targetIds
      .map((id) => {
        const el = elements.find((e) => e.slotId === id);
        if (el?.placement) return el.placement;
        const slot = slotById[id];
        return slot ? regionToPlacement(slot.region, canvas, slot, slots) : null;
      })
      .filter(Boolean);
    if (!placements.length) continue;

    const x = Math.min(...placements.map((p) => p.x ?? 0));
    const y = Math.min(...placements.map((p) => p.y ?? 0));
    const x2 = Math.max(...placements.map((p) => (p.x ?? 0) + (p.width ?? 0)));
    const y2 = Math.max(...placements.map((p) => (p.y ?? 0) + (p.height ?? 0)));
    const padX = 14;
    const padY = 16;
    pendingBoxes.push({
      key,
      x: x - padX,
      y: y - padY,
      width: Math.max(40, x2 - x + padX * 2),
      height: Math.max(40, y2 - y + padY * 2),
    });
  }

  const separated = separateCardBoxes(pendingBoxes, canvas, { edgeInset: 56, gap: 24 });
  const palette = themeTokens?.palette || {};

  for (const box of separated) {
    elements.unshift({
      id: newElementId('shp'),
      type: 'shape',
      layer: 0,
      placement: {
        x: Math.round(box.x),
        y: Math.round(box.y),
        width: Math.round(box.width),
        height: Math.round(box.height),
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: {
          type: 'solid',
          colorRole: 'cardBg',
          color: paletteColor(palette, 'cardBg', null),
        },
        borderRadius: 12,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: `AUTO_CARD_BG_${box.key}`,
    });
  }

  let next = { ...doc, elements };
  next = refineExistingCardBackgrounds(next, canvas);
  next = splitOversizedCardBand(next, layoutSchema, themeTokens, canvas);
  next = centerMultiCardHeading(next, Math.max(separated.length, schemaCardCount), layoutSchema);
  return next;
}

function applySplitHeroDecorShape(doc, layoutSchema, themeTokens, canvas) {
  if (!doc || !layoutSchema?.slots?.length) return doc;
  const layoutId = String(layoutSchema.layout_id || '').toLowerCase();
  const slots = layoutSchema.slots;
  const heroSlot = slots.find((s) => String(s.id || '').toUpperCase() === 'HERO_IMAGE');
  if (!heroSlot) return doc;

  const hasDecorSlot = slots.some((s) => /HERO_DECOR|IMAGE_DECOR|DECOR_SHAPE/i.test(String(s.id || '')));
  if (!hasDecorSlot && !/bullet_split_image/.test(layoutId)) return doc;

  const elements = [...(doc.elements || [])];
  const heroEl = elements.find((el) => el.slotId === heroSlot.id || el.slotId === 'HERO_IMAGE');
  const placement = heroEl?.placement || regionToPlacement(heroSlot.region, canvas, heroSlot, slots);
  if (!placement) return doc;

  const palette = themeTokens?.palette || {};
  const accent = paletteColor(palette, 'accent', paletteColor(palette, 'secondary', '#E8A798'));
  const decorWidth = Math.max(120, (placement.width || 400) * 1.35);
  const decorHeight = Math.max(120, (placement.height || 500) * 1.15);
  const decorX = (placement.x ?? 0) - decorWidth * 0.18;
  const decorY = (placement.y ?? 0) + (placement.height || 0) * 0.08;

  elements.unshift({
    id: newElementId('shp'),
    type: 'shape',
    layer: Math.max(0, (heroSlot.layer || 2) - 1),
    placement: {
      x: Math.max(0, decorX),
      y: Math.max(0, decorY),
      width: decorWidth,
      height: decorHeight,
      rotation: 0,
      opacity: 0.35,
    },
    content: {
      shape: 'ellipse',
      fill: {
        type: 'solid',
        colorRole: 'accent',
        color: accent,
      },
      layoutSurface: true,
    },
    role: 'decoration',
  });

  return { ...doc, elements };
}

function isProcessLinnerLayout(layoutId) {
  return /^process_linner_/i.test(String(layoutId || ''));
}

function isProcessLinnerHortiLayout(layoutId) {
  return /^process_linner_horti/i.test(String(layoutId || ''));
}

function isProcessLinnerNumericLayout(layoutId) {
  return /^process_linner_numeric/i.test(String(layoutId || ''));
}

function findStepTitleElements(elements) {
  return elements
    .filter(
      (el) =>
        (el.type === 'text' || el.type === 'textbox') &&
        /^STEP_\d+_TITLE$/i.test(String(el.slotId || ''))
    )
    .sort((a, b) => (a.placement?.x ?? 0) - (b.placement?.x ?? 0));
}

function applyProcessLinnerHortiShapes(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc || !layoutSchema?.slots?.length) return doc;
  const layoutId = String(layoutSchema.layout_id || '');
  if (!isProcessLinnerHortiLayout(layoutId)) return doc;
  if ((doc.elements || []).some((el) => String(el.slotId || '') === 'PROCESS_LINNER_SPINE')) return doc;

  const palette = themeTokens?.palette || {};
  const spineColor = paletteColor(palette, 'text', '#0F172A');
  const phaseFill = paletteColor(palette, 'cardBg', 'color-mix(in srgb, #e8b4a0 42%, #ffffff)');
  const primaryColor = paletteColor(palette, 'primary', paletteColor(palette, 'accent', '#2563EB'));
  const white = '#FFFFFF';

  let elements = [...(doc.elements || [])];
  const titleEls = findStepTitleElements(elements);
  if (titleEls.length < 2) return doc;

  const SPINE_NODE = 28;
  const NUM_H = 18;
  const minTitleY = Math.min(...titleEls.map((t) => t.placement?.y ?? 0));
  const spineY = Math.max(96, minTitleY - 100);

  const centers = titleEls.map((el, i) => {
    const p = el.placement || {};
    return {
      x: (p.x ?? 0) + (p.width ?? 0) / 2,
      titleSlotId: el.slotId,
      index: i + 1,
    };
  });

  const spineX1 = centers[0].x;
  const spineX2 = centers[centers.length - 1].x;
  elements.unshift({
    id: newElementId('shp'),
    type: 'shape',
    layer: 1,
    placement: {
      x: Math.round(spineX1),
      y: Math.round(spineY - 1),
      width: Math.round(Math.max(8, spineX2 - spineX1)),
      height: 2,
      rotation: 0,
      opacity: 1,
    },
    content: { shape: 'rect', fill: { type: 'solid', color: spineColor, colorRole: 'text' }, layoutSurface: true },
    role: 'decoration',
    slotId: 'PROCESS_LINNER_SPINE',
  });

  centers.forEach((c) => {
    const phaseRadius = c.index % 2 === 0 ? 105 : 90;
    const phaseSize = phaseRadius * 2;
    const phaseY = spineY + SPINE_NODE / 2 + 28 + phaseRadius;
    const phaseBottom = phaseY + phaseRadius;

    elements.unshift({
      id: newElementId('shp'),
      type: 'shape',
      layer: 3,
      placement: {
        x: Math.round(c.x - SPINE_NODE / 2),
        y: Math.round(spineY - SPINE_NODE / 2),
        width: SPINE_NODE,
        height: SPINE_NODE,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'ellipse',
        fill: { type: 'solid', color: spineColor, colorRole: 'text' },
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: `STEP_${c.index}_SPINE_NODE`,
    });

    elements.unshift({
      id: newElementId('txt'),
      type: 'text',
      layer: 4,
      placement: {
        x: Math.round(c.x - SPINE_NODE / 2),
        y: Math.round(spineY - NUM_H / 2),
        width: SPINE_NODE,
        height: NUM_H,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: String(c.index),
        align: 'center',
        fontSize: 12,
        fontWeight: 700,
        color: white,
      },
      role: 'caption',
      slotId: `STEP_${c.index}_SPINE_NUM`,
    });

    elements.unshift({
      id: newElementId('shp'),
      type: 'graphic',
      layer: 2,
      placement: {
        x: Math.round(c.x - phaseRadius),
        y: Math.round(phaseY - phaseRadius),
        width: phaseSize,
        height: phaseSize,
        rotation: 0,
        opacity: 1,
      },
      content: timelineGraphicContent(processPhaseCircleInlineSvg(), { type: 'solid', color: phaseFill, colorRole: 'cardBg' }, `Phase ${c.index}`),
      role: 'decoration',
      slotId: `STEP_${c.index}_PHASE_CIRCLE`,
    });

    const titleIdx = elements.findIndex((el) => el.slotId === c.titleSlotId);
    if (titleIdx >= 0) {
      const titleEl = elements[titleIdx];
      const titleHeight = Math.max(28, titleEl.placement?.height ?? 32);
      elements[titleIdx] = {
        ...titleEl,
        layer: 5,
        placement: {
          ...titleEl.placement,
          x: Math.round(c.x - phaseRadius + 16),
          y: Math.round(phaseY - titleHeight / 2),
          width: Math.round(phaseSize - 32),
          height: titleHeight,
        },
        content: {
          ...(titleEl.content || {}),
          align: 'center',
          color: primaryColor,
          colorRole: 'primary',
        },
      };
    }

    const ANCHOR = 14;
    const anchorY = phaseBottom + 36;
    const connectorHeight = Math.max(12, anchorY - ANCHOR / 2 - phaseBottom - 4);

    elements.unshift({
      id: newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: {
        x: Math.round(c.x - 1),
        y: Math.round(phaseBottom + 4),
        width: 2,
        height: Math.round(connectorHeight),
        rotation: 0,
        opacity: 1,
      },
      content: { shape: 'rect', fill: { type: 'solid', color: spineColor, colorRole: 'text' }, layoutSurface: true },
      role: 'decoration',
      slotId: `STEP_${c.index}_CONNECTOR`,
    });

    elements.unshift({
      id: newElementId('shp'),
      type: 'shape',
      layer: 2,
      placement: {
        x: Math.round(c.x - ANCHOR / 2),
        y: Math.round(anchorY - ANCHOR / 2),
        width: ANCHOR,
        height: ANCHOR,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'ellipse',
        fill: { type: 'solid', color: 'transparent' },
        stroke: spineColor,
        strokeWidth: 2,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: `STEP_${c.index}_ANCHOR`,
    });

    const bodySlotId = `STEP_${c.index}_BODY`;
    const bodyIdx = elements.findIndex((el) => el.slotId === bodySlotId);
    if (bodyIdx >= 0) {
      const bodyEl = elements[bodyIdx];
      const titleWidth = elements.find((el) => el.slotId === c.titleSlotId)?.placement?.width;
      const bodyWidth = Math.max(bodyEl.placement?.width ?? 0, titleWidth ?? 200);
      const bodyTop = anchorY + ANCHOR / 2 + 14;
      elements[bodyIdx] = {
        ...bodyEl,
        placement: {
          ...bodyEl.placement,
          x: Math.round(c.x - bodyWidth / 2),
          y: Math.round(bodyTop),
          width: bodyWidth,
        },
        content: {
          ...(bodyEl.content || {}),
          align: 'center',
        },
      };
    }
  });

  return { ...doc, elements };
}

function applyProcessLinnerNumericShapes(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc || !layoutSchema?.slots?.length) return doc;
  const layoutId = String(layoutSchema.layout_id || '');
  if (!isProcessLinnerNumericLayout(layoutId)) return doc;

  const palette = themeTokens?.palette || {};
  const lineColor = paletteColor(palette, 'text', '#0F172A');
  const shadowColor = 'rgba(15, 23, 42, 0.12)';
  let elements = [...(doc.elements || [])];

  const numberEls = elements
    .filter((el) => el.type === 'text' && /^STEP_\d+_NUMBER$/i.test(String(el.slotId || '')))
    .sort((a, b) => (a.placement?.x ?? 0) - (b.placement?.x ?? 0));

  numberEls.forEach((numEl) => {
    const m = String(numEl.slotId || '').match(/^STEP_(\d+)_NUMBER$/i);
    if (!m) return;
    const n = m[1];
    const p = numEl.placement || {};
    const slotLineY = (p.y ?? 0) + (p.height ?? 0) - 8;
    const lineWidth = Math.max(60, (p.width ?? 0) * 0.85);
    const lineX = (p.x ?? 0) + ((p.width ?? 0) - lineWidth) / 2;

    if (!elements.some((el) => el.slotId === `STEP_${n}_NUMBER_SLOT`)) {
      elements.unshift({
        id: newElementId('shp'),
        type: 'shape',
        layer: 1,
        placement: {
          x: Math.round(lineX),
          y: Math.round(slotLineY),
          width: Math.round(lineWidth),
          height: 3,
          rotation: 0,
          opacity: 1,
        },
        content: { shape: 'rect', fill: { type: 'solid', color: lineColor, colorRole: 'text' }, layoutSurface: true },
        role: 'decoration',
        slotId: `STEP_${n}_NUMBER_SLOT`,
      });

      elements.unshift({
        id: newElementId('shp'),
        type: 'shape',
        layer: 0,
        placement: {
          x: Math.round((p.x ?? 0) + 4),
          y: Math.round(slotLineY + 2),
          width: Math.round(lineWidth - 8),
          height: 6,
          rotation: 0,
          opacity: 0.35,
        },
        content: { shape: 'rect', fill: { type: 'solid', color: shadowColor }, borderRadius: 3, layoutSurface: true },
        role: 'decoration',
        slotId: `STEP_${n}_NUMBER_SHADOW`,
      });
    }

    const iconSlotId = `STEP_${n}_ICON`;
    const iconIdx = elements.findIndex((el) => el.slotId === iconSlotId);
    if (iconIdx >= 0 && elements[iconIdx].type === 'text') {
      const iconEl = elements[iconIdx];
      const ip = iconEl.placement || {};
      const size = Math.min(ip.width ?? 48, ip.height ?? 48, 48);
      const cx = (ip.x ?? 0) + (ip.width ?? size) / 2;
      const cy = (ip.y ?? 0) + (ip.height ?? size) / 2;
      elements.splice(iconIdx, 1);
      elements.push({
        id: newElementId('shp'),
        type: 'shape',
        slotId: iconSlotId,
        layer: iconEl.layer ?? 8,
        placement: {
          x: Math.round(cx - size / 2),
          y: Math.round(cy - size / 2),
          width: size,
          height: size,
          rotation: 0,
          opacity: 1,
        },
        content: {
          shape: 'circle',
          fill: {
            type: 'solid',
            color: paletteColor(palette, 'iconFill', 'color-mix(in srgb, #64748b 18%, transparent)'),
          },
          stroke: paletteColor(palette, 'iconRing', 'color-mix(in srgb, #6366f1 32%, transparent)'),
          strokeWidth: 1.5,
          layoutSurface: true,
        },
        role: 'decoration',
      });
    }
  });

  return { ...doc, elements };
}

function isProcessFlowLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  if (/^process_linner_horti/.test(id)) return false;
  return (
    /timeline/.test(id) ||
    /process_linear/.test(id) ||
    /diagram_process/.test(id) ||
    /process_steps/.test(id) ||
    /agenda_timeline|agenda_vertical_roadmap|agenda_curved_timeline/.test(id)
  );
}

function isDiagramProcessStepsLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return /diagram_process_steps|diagram_process_horizontal|diagram_process_vertical|timeline_process_steps/.test(id);
}

function timelineGraphicContent(svg, fill, alt = '') {
  return { svg, colorMode: 'recolorable', fill, alt };
}

function isHorizontalCycleLayout(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  return variant === 'horizontal' || (id.includes('cycle') && id.includes('horizontal'));
}

function isRingCycleLayout(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  return variant === 'ring' || (id.includes('cycle') && id.includes('ring'));
}

function layoutDiagramCycleHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const n = 5;
  const insetX = 40;
  const headingY = 28;
  const headingH = 56;
  const node = 440;
  const colW = Math.round(node * 0.76);
  const rowW = node + colW * (n - 1);
  const startX = Math.round((canvasW - rowW) / 2);
  const titleH = 44;
  const bodyH = 96;
  const titleW = Math.max(160, colW - 32);
  const stepsH = node + 48 + titleH + 10 + bodyH;
  const nodeY = Math.round((canvasH - stepsH) / 2);
  const titleY = nodeY + node + 48;
  const bodyY = titleY + titleH + 10;

  const CYCLE_DECO = /^(CYCLE_(RING|HUB|LOOP|SEG_|BAR_|DROP_|DOT_|ICON_|FLOW_|ARC_)|AUTO_CARD_BG_)/i;
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^CYCLE_(LOOP|BAR_|DROP_|DOT_|ICON_|FLOW_|SEG_|HUB|ARC_)/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !CYCLE_DECO.test(String(el.slotId || '')));

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        layer: 50,
        placement: {
          x: insetX,
          y: headingY,
          width: canvasW - insetX * 2,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 32,
          fontWeight: 800,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    if (/^CYCLE_(CENTER|NUM_)/i.test(sid)) {
      return { ...el, placement: { ...(el.placement || {}), opacity: 0, width: 1, height: 1, x: 0, y: 0 } };
    }
    const m = sid.match(/^Q([1-5])_(TITLE|BODY)$/i);
    if (!m) return el;
    const idx = Number(m[1]) - 1;
    const isTitle = String(m[2]).toUpperCase() === 'TITLE';
    const x = startX + idx * colW;
    const tx = Math.round(x + (node - titleW) / 2);
    if (isTitle) {
      return {
        ...el,
        layer: 50,
        placement: {
          x: tx,
          y: Math.round(titleY),
          width: titleW,
          height: titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 17,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
        },
      };
    }
    return {
      ...el,
      layer: 50,
      placement: {
        x: tx,
        y: Math.round(bodyY),
        width: titleW,
        height: bodyH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: 'center',
        verticalAlign: 'flex-start',
        fontSize: 14,
        fontWeight: 400,
        lineHeight: 1.45,
        color: muted,
        wrap: 'wrap',
        clipToSlot: false,
      },
    };
  });

  const chrome = [];
  for (let i = 0; i < n; i += 1) {
    const pal = cycleNodePalette(i);
    const x = startX + i * colW;
    const topId = `CYCLE_ARC_TOP_${i + 1}`;
    const botId = `CYCLE_ARC_BOT_${i + 1}`;
    const iconId = `CYCLE_ICON_${i + 1}`;
    const prevT = prevBySlot.get(topId);
    const prevB = prevBySlot.get(botId);
    const prevI = prevBySlot.get(iconId);
    const pad = Math.round(node * 0.06);
    const box = {
      x: Math.round(x - pad),
      y: Math.round(nodeY - pad),
      width: node + pad * 2,
      height: node + pad,
      rotation: 0,
      opacity: 1,
    };
    chrome.push({
      id: prevT?.id || newElementId('shp-ctop'),
      type: 'graphic',
      layer: 3 + i * 3,
      placement: { ...box },
      content: {
        svg: cycleNodeTopArcSvg(),
        colorMode: 'recolorable',
        fill: pal.top,
        alt: 'Top arc',
      },
      role: 'decoration',
      slotId: topId,
    });
    chrome.push({
      id: prevB?.id || newElementId('shp-cbot'),
      type: 'graphic',
      layer: 4 + i * 3,
      placement: { ...box },
      content: {
        svg: cycleNodeBotArcSvg(),
        colorMode: 'recolorable',
        fill: pal.bot,
        alt: 'Bottom arc',
      },
      role: 'decoration',
      slotId: botId,
    });
    const icon = 112;
    chrome.push({
      id: prevI?.id || newElementId('shp-cico'),
      type: 'graphic',
      layer: 20 + i,
      placement: {
        x: Math.round(x + (node - icon) / 2),
        y: Math.round(nodeY + (node - icon) / 2),
        width: icon,
        height: icon,
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: cycleNodeIconSvg(i),
        colorMode: 'recolorable',
        fill: pal.accent,
        alt: 'Step icon',
      },
      role: 'decoration',
      slotId: iconId,
    });
    const hasT = elements.some((el) => String(el.slotId || '').toUpperCase() === `Q${i + 1}_TITLE`);
    const hasBd = elements.some((el) => String(el.slotId || '').toUpperCase() === `Q${i + 1}_BODY`);
    if (!hasT) {
      elements.push({
        id: newElementId('txt-cq'),
        type: 'text',
        layer: 50,
        slotId: `Q${i + 1}_TITLE`,
        role: 'heading',
        placement: {
          x: Math.round(x + (node - titleW) / 2),
          y: Math.round(titleY),
          width: titleW,
          height: titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: 'Your Text Here',
          align: 'center',
          verticalAlign: 'center',
          fontSize: 18,
          fontWeight: 800,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
        },
      });
    }
    if (!hasBd) {
      elements.push({
        id: newElementId('txt-cb'),
        type: 'text',
        layer: 50,
        slotId: `Q${i + 1}_BODY`,
        role: 'body',
        placement: {
          x: Math.round(x + (node - titleW) / 2),
          y: Math.round(bodyY),
          width: titleW,
          height: bodyH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: 'Describe this step in a few lines.',
          align: 'center',
          verticalAlign: 'flex-start',
          fontSize: 14,
          fontWeight: 400,
          lineHeight: 1.45,
          color: muted,
          wrap: 'wrap',
          clipToSlot: false,
        },
      });
    }
  }

  return { ...doc, elements: [...chrome, ...elements] };
}

function isDiagramCycleLayout(layoutId) {
  return /diagram_cycle/.test(String(layoutId || '').toLowerCase());
}

function layoutDiagramCycleRing(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const n = CYCLE_RING_N;
  const insetX = 40;
  const headingY = 40;
  const headingH = 64;
  const cycleSize = 580;
  const cycleX = Math.round((canvasW - cycleSize) / 2);
  const cycleY = Math.min(
    canvasH - cycleSize - 140,
    Math.max(headingY + headingH + 72, Math.round((canvasH - cycleSize) / 2 + 72))
  );
  const scale = cycleSize / CYCLE_RING_GEOM.view;
  const cx = cycleX + cycleSize / 2;
  const cy = cycleY + cycleSize / 2;
  const rOut = CYCLE_RING_GEOM.rOut * scale;
  const hubR = CYCLE_RING_GEOM.hubR * scale;
  const callouts = cycleRingCallouts(cx, cy, rOut);

  const CYCLE_DECO =
    /^(CYCLE_(RING|HUB|LOOP|SEG_|BAR_|DROP_|DOT_|ICON_|FLOW_|ARC_|LEAD_|DIAMOND)|AUTO_CARD_BG_)/i;
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^CYCLE_(SEG_|HUB|LEAD_|DIAMOND|ICON_)/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !CYCLE_DECO.test(String(el.slotId || '')));

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        layer: 50,
        placement: {
          x: insetX,
          y: headingY,
          width: canvasW - insetX * 2,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 28,
          fontWeight: 800,
          lineHeight: 1.25,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    if (/^CYCLE_(CENTER|NUM_)/i.test(sid) || /^Q[1-5]_BODY$/i.test(sid)) return null;
    const m = sid.match(/^Q([1-5])_TITLE$/i);
    if (!m) return el;
    const idx = Number(m[1]) - 1;
    const c = callouts[idx];
    if (!c) return el;
    return {
      ...el,
      layer: 50,
      placement: {
        x: c.text.x,
        y: c.text.y,
        width: c.text.width,
        height: c.text.height,
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: c.text.align,
        verticalAlign: 'center',
        fontSize: 17,
        fontWeight: 600,
        color: textColor,
        wrap: 'wrap',
        clipToSlot: false,
        lineHeight: 1.2,
      },
    };
  }).filter(Boolean);

  const chrome = [];
  for (let i = 0; i < n; i += 1) {
    const slotId = `CYCLE_SEG_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const fill = prev?.content?.fill || CYCLE_RING_COLORS[i];
    chrome.push({
      id: prev?.id || newElementId('shp-rseg'),
      type: 'graphic',
      layer: 2 + i,
      placement: cycleRingSegPlacement(cycleX, cycleY, cycleSize, i),
      content: {
        svg: cycleRingSegSvg(i),
        colorMode: 'recolorable',
        fill,
        alt: `Cycle ring ${i + 1}`,
      },
      role: 'decoration',
      slotId,
    });
    const leadId = `CYCLE_LEAD_${i + 1}`;
    const prevL = prevBySlot.get(leadId);
    const call = callouts[i];
    chrome.push({
      id: prevL?.id || newElementId('shp-rlead'),
      type: 'graphic',
      layer: 12 + i,
      placement: { ...call.box },
      content: {
        svg: cycleRingCalloutSvg(call.localPts, call.localBar, call.box.width, call.box.height),
        colorMode: 'recolorable',
        fill: prevL?.content?.fill || CYCLE_RING_COLORS[i],
        alt: `Callout ${i + 1}`,
      },
      role: 'decoration',
      slotId: leadId,
    });
    const hasT = elements.some((el) => String(el.slotId || '').toUpperCase() === `Q${i + 1}_TITLE`);
    if (!hasT) {
      elements.push({
        id: newElementId('txt-rlabel'),
        type: 'text',
        layer: 50,
        slotId: `Q${i + 1}_TITLE`,
        role: 'heading',
        placement: {
          x: call.text.x,
          y: call.text.y,
          width: call.text.width,
          height: call.text.height,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: 'Sample text here',
          align: call.text.align,
          verticalAlign: 'center',
          fontSize: 17,
          fontWeight: 600,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
          lineHeight: 1.2,
        },
      });
    }
  }

  const prevHub = prevBySlot.get('CYCLE_HUB');
  chrome.push({
    id: prevHub?.id || newElementId('shp-rhub'),
    type: 'shape',
    layer: 8,
    placement: {
      x: Math.round(cx - hubR),
      y: Math.round(cy - hubR),
      width: Math.round(hubR * 2),
      height: Math.round(hubR * 2),
      rotation: 0,
      opacity: 1,
    },
    content: { shape: 'ellipse', fill: prevHub?.content?.fill || '#ffffff' },
    role: 'decoration',
    slotId: 'CYCLE_HUB',
  });
  const prevD = prevBySlot.get('CYCLE_DIAMOND');
  const dia = Math.round(hubR * 0.72);
  chrome.push({
    id: prevD?.id || newElementId('shp-rdia'),
    type: 'graphic',
    layer: 20,
    placement: {
      x: Math.round(cx - dia / 2),
      y: Math.round(cy - dia / 2),
      width: dia,
      height: dia,
      rotation: 0,
      opacity: 1,
    },
    content: {
      svg: cycleRingDiamondSvg(),
      colorMode: 'recolorable',
      fill: prevD?.content?.fill || '#9CA3AF',
      alt: 'Center icon',
    },
    role: 'decoration',
    slotId: 'CYCLE_DIAMOND',
  });

  return { ...doc, elements: [...chrome, ...elements] };
}

function layoutDiagramCycle(doc, layoutSchema, themeTokens, canvas = {}) {
  if (isHorizontalCycleLayout(layoutSchema)) {
    return layoutDiagramCycleHorizontal(doc, layoutSchema, themeTokens, canvas);
  }
  if (isRingCycleLayout(layoutSchema)) {
    return layoutDiagramCycleRing(doc, layoutSchema, themeTokens, canvas);
  }
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const colors = [
    paletteColor(palette, 'accent', CYCLE_SEGMENT_COLORS[0]),
    paletteColor(palette, 'secondary', CYCLE_SEGMENT_COLORS[1]),
    paletteColor(palette, 'primary', CYCLE_SEGMENT_COLORS[2]),
    paletteColor(palette, 'highlight', CYCLE_SEGMENT_COLORS[3]),
  ];

  const insetX = 56;
  const headingH = 72;
  const headingY = 52;
  const bottomPad = 56;
  const cycleSize = Math.min(620, canvasH - headingY - headingH - bottomPad - 24);
  const cycleX = Math.round((canvasW - cycleSize) / 2);
  const spaceBelowTitle = canvasH - headingY - headingH - bottomPad;
  const cycleY = Math.round(headingY + headingH + Math.max(24, (spaceBelowTitle - cycleSize) / 2));
  const sideW = Math.max(260, cycleX - insetX - 28);
  const titleH = 44;
  const bodyH = 88;
  const topBlockY = cycleY + Math.round(cycleSize * 0.16);
  const bottomBlockY = cycleY + Math.round(cycleSize * 0.58);

  const overlay = cycleOverlayPlacements(cycleX, cycleY, cycleSize);

  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^CYCLE_(SEG_[1-4]|HUB)$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) => !/^CYCLE_(RING|SEG_[1-4]|HUB)$/i.test(String(el.slotId || ''))
  );
  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: insetX,
          y: headingY,
          width: canvasW - insetX * 2,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: Math.min(Number(el.content?.fontSize) || 34, 36),
          fontWeight: 800,
          color: textColor,
        },
      };
    }
    if (sid.toUpperCase() === 'CYCLE_CENTER') {
      return {
        ...el,
        layer: 12,
        placement: { ...(el.placement || {}), ...overlay.center, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: el.content?.text || 'CYCLE',
          align: 'center',
          verticalAlign: 'center',
          fontSize: 20,
          fontWeight: 800,
          letterSpacing: '0.12em',
          wrap: 'nowrap',
          color: textColor,
        },
      };
    }
    const numM = sid.match(/^CYCLE_NUM_([1-4])$/i);
    if (numM) {
      const idx = Number(numM[1]) - 1;
      return {
        ...el,
        layer: 12,
        placement: { ...(el.placement || {}), ...overlay.numbers[idx], rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: el.content?.text || String(idx + 1),
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1,
          wrap: 'nowrap',
          color: '#ffffff',
        },
      };
    }
    const m = sid.match(/^Q([1-4])_(TITLE|BODY)$/i);
    if (!m) return el;
    const q = Number(m[1]);
    const isTitle = String(m[2]).toUpperCase() === 'TITLE';
    const leftSide = q === 3 || q === 4;
    const topSide = q === 1 || q === 4;
    const x = leftSide ? insetX : canvasW - insetX - sideW;
    const y = topSide ? topBlockY : bottomBlockY;
    if (isTitle) {
      return {
        ...el,
        layer: Math.max(el.layer || 0, 10),
        placement: {
          ...(el.placement || {}),
          x,
          y,
          width: sideW,
          height: titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: leftSide ? 'right' : 'left',
          verticalAlign: 'flex-end',
          fontSize: 22,
          fontWeight: 700,
          color: textColor,
        },
      };
    }
    return {
      ...el,
      layer: Math.max(el.layer || 0, 10),
      placement: {
        ...(el.placement || {}),
        x,
        y: y + titleH + 6,
        width: sideW,
        height: bodyH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: leftSide ? 'right' : 'left',
        verticalAlign: 'flex-start',
        fontSize: 16,
        fontWeight: 400,
        color: muted,
        lineHeight: 1.4,
      },
    };
  });

  const extras = [];
  if (!elements.some((el) => String(el.slotId || '').toUpperCase() === 'CYCLE_CENTER')) {
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId: 'CYCLE_CENTER',
      role: 'heading',
      layer: 12,
      placement: { ...overlay.center, rotation: 0, opacity: 1 },
      content: {
        text: 'CYCLE',
        align: 'center',
        verticalAlign: 'center',
        fontSize: 20,
        fontWeight: 800,
        letterSpacing: '0.12em',
        wrap: 'nowrap',
        color: textColor,
        padding: 0,
        paddingX: 0,
      },
    });
  }
  for (let i = 0; i < 4; i += 1) {
    const slotId = `CYCLE_NUM_${i + 1}`;
    if (elements.some((el) => String(el.slotId || '').toUpperCase() === slotId)) continue;
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId,
      role: 'caption',
      layer: 12,
      placement: { ...overlay.numbers[i], rotation: 0, opacity: 1 },
      content: {
        text: String(i + 1),
        align: 'center',
        verticalAlign: 'center',
        fontSize: 36,
        fontWeight: 800,
        lineHeight: 1,
        wrap: 'nowrap',
        color: '#ffffff',
        padding: 0,
        paddingX: 0,
      },
    });
  }

  const segs = [0, 1, 2, 3].map((i) => {
    const slotId = `CYCLE_SEG_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const fill = prev?.content?.fill || colors[i];
    return {
      id: prev?.id || newElementId('shp'),
      type: 'graphic',
      layer: 2 + i,
      placement: { ...cycleSegmentPlacement(cycleX, cycleY, cycleSize, i), rotation: 0, opacity: 1 },
      content: {
        svg: cycleSegmentInlineSvg(i),
        colorMode: 'recolorable',
        fill,
        stroke: typeof fill === 'string' ? fill : fill?.color,
        alt: `Cycle segment ${i + 1}`,
      },
      role: 'decoration',
      slotId,
    };
  });
  const prevHub = prevBySlot.get('CYCLE_HUB');
  const hub = {
    id: prevHub?.id || newElementId('shp'),
    type: 'shape',
    layer: 8,
    placement: { ...overlay.hub, rotation: 0, opacity: 1 },
    content: {
      shape: 'ellipse',
      fill: prevHub?.content?.fill || '#ffffff',
    },
    role: 'decoration',
    slotId: 'CYCLE_HUB',
  };

  return { ...doc, elements: [...segs, hub, ...elements, ...extras] };
}

function isDiagramFunnelLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return /diagram_funnel/.test(id) && !/pyramid/.test(id);
}

function isDiagramPyramidLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return /diagram_pyramid/.test(id);
}

function layoutDiagramPyramid(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const mode = pyramidModeFromSchema(layoutSchema);
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const frame = pyramidGraphicBox(canvasW, canvasH, mode);
  const legend = pyramidLegendPlacements(frame, mode);
  const colors = [
    paletteColor(palette, 'accent', PYRAMID_COLORS[0]),
    paletteColor(palette, 'secondary', PYRAMID_COLORS[1]),
    paletteColor(palette, 'primary', PYRAMID_COLORS[2]),
    paletteColor(palette, 'highlight', PYRAMID_COLORS[3]),
    paletteColor(palette, 'accent', PYRAMID_COLORS[4]),
  ];
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^PYRAMID_(SEG|BADGE)_[1-5]$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !/^PYRAMID_(SEG|BADGE|BAR)_/i.test(String(el.slotId || '')));
  const extras = [];

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: 56,
          y: frame.headingY,
          width: canvasW - 112,
          height: frame.headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    const numM = sid.match(/^PYRAMID_NUM_([1-5])$/i);
    if (numM) {
      const i = Number(numM[1]) - 1;
      return {
        ...el,
        layer: 12,
        placement: { ...legend[i].num, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: el.content?.text || String(i + 1).padStart(2, '0'),
          align: 'center',
          verticalAlign: 'center',
          fontSize: mode === 'layers' ? 26 : 15,
          fontWeight: 800,
          wrap: 'nowrap',
          lineHeight: 1,
          color: '#ffffff',
          clipToSlot: false,
        },
      };
    }
    const titleM = sid.match(/^funnel_([1-5])_title$/i);
    if (titleM) {
      const i = Number(titleM[1]) - 1;
      return {
        ...el,
        layer: 10,
        placement: { ...legend[i].title, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 22,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    const bodyM = sid.match(/^funnel_([1-5])_body$/i);
    if (bodyM) {
      const i = Number(bodyM[1]) - 1;
      return {
        ...el,
        layer: 10,
        placement: { ...legend[i].body, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 15,
          fontWeight: 400,
          color: muted,
          lineHeight: 1.35,
        },
      };
    }
    return el;
  });

  for (let i = 0; i < PYRAMID_N; i += 1) {
    const numId = `PYRAMID_NUM_${i + 1}`;
    if (elements.some((el) => String(el.slotId || '').toUpperCase() === numId)) continue;
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId: numId,
      role: 'caption',
      layer: 12,
      placement: { ...legend[i].num, rotation: 0, opacity: 1 },
      content: {
        text: String(i + 1).padStart(2, '0'),
        align: 'center',
        verticalAlign: 'center',
        fontSize: mode === 'layers' ? 26 : 15,
        fontWeight: 800,
        wrap: 'nowrap',
        lineHeight: 1,
        color: '#ffffff',
        padding: 0,
        paddingX: 0,
        clipToSlot: false,
      },
    });
  }

  const { graphicX, graphicY, graphicW, graphicH } = frame;
  const segs = [0, 1, 2, 3, 4].map((i) => {
    const slotId = `PYRAMID_SEG_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const fill = prev?.content?.fill || colors[i];
    return {
      id: prev?.id || newElementId('shp'),
      type: 'graphic',
      layer: 3 + i,
      placement: { ...pyramidStagePlacement(graphicX, graphicY, graphicW, graphicH, i, mode), rotation: 0, opacity: 1 },
      content: {
        svg: pyramidStageInlineSvg(i, mode),
        colorMode: 'recolorable',
        fill,
        alt: `Pyramid stage ${i + 1}`,
      },
      role: 'decoration',
      slotId,
    };
  });

  const badges = mode === 'layers'
    ? []
    : [0, 1, 2, 3, 4].map((i) => {
    const slotId = `PYRAMID_BADGE_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    return {
      id: prev?.id || newElementId('shp'),
      type: 'shape',
      layer: 4,
      placement: { ...legend[i].badge, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        fill: prev?.content?.fill || colors[i],
        clipPath: PYRAMID_BADGE_CLIP,
      },
      role: 'decoration',
      slotId,
    };
  });

  return { ...doc, elements: [...segs, ...badges, ...elements, ...extras] };
}

function isHorizontalFunnelLayout(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  return variant === 'horizontal' || (id.includes('funnel') && id.includes('horizontal'));
}

function layoutDiagramFunnelHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');

  const colors = FUNNEL_STAGE_COLORS.slice();
  const cardFills = ['#EEF1F6', '#E8F0FE', '#FFF3EB', '#F1F5F9'];

  const headingH = 80;
  const cardH = 176;
  const barH = 8;
  const headingGap = 16;
  const cardGapY = 28;
  const cardGapX = 18;
  const padX = 16;
  const titleH = 34;
  const topInset = 56;
  const bottomInset = 40;
  const maxBlock = canvasH - topInset - bottomInset;
  const graphicH = Math.min(
    Math.round((canvasW - 140) * (FUNNEL_H_GEOM.viewH / FUNNEL_H_GEOM.viewW)),
    maxBlock - headingH - cardH - headingGap - cardGapY,
  );
  const graphicW = Math.round(graphicH * (FUNNEL_H_GEOM.viewW / FUNNEL_H_GEOM.viewH));
  const blockH = headingH + headingGap + graphicH + cardGapY + cardH;
  const headingY = topInset + Math.max(0, Math.round((maxBlock - blockH) / 2));
  const graphicX = Math.round((canvasW - graphicW) / 2);
  const graphicY = headingY + headingH + headingGap;
  const overlay = funnelHOverlayPlacements(graphicX, graphicY, graphicW, graphicH);
  const cardY = graphicY + graphicH + cardGapY;
  const cardW = (graphicW - cardGapX * 3) / 4;

  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^(FUNNEL_SEG_[1-4]|FUNNEL_CARD_[1-4]|FUNNEL_BAR_[1-4])$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !/^FUNNEL_(SEG|TAB|LID|SHADE|RING|CARD|BAR)_/i.test(String(el.slotId || '')) &&
      String(el.slotId || '') !== 'FUNNEL_RING'
  );
  const extras = [];

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: 80,
          y: headingY,
          width: canvasW - 160,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 40,
          fontWeight: 800,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    const numM = sid.match(/^FUNNEL_NUM_([1-4])$/i);
    if (numM) {
      const i = Number(numM[1]) - 1;
      return {
        ...el,
        layer: 12,
        placement: { ...overlay.stages[i].num, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: el.content?.text || String(i + 1).padStart(2, '0'),
          align: 'center',
          verticalAlign: 'center',
          fontSize: 20,
          fontWeight: 800,
          wrap: 'nowrap',
          lineHeight: 1,
          color: '#ffffff',
        },
      };
    }
    const titleM = sid.match(/^funnel_([1-4])_title$/i);
    if (titleM) {
      const i = Number(titleM[1]) - 1;
      const x = graphicX + i * (cardW + cardGapX);
      return {
        ...el,
        layer: 10,
        placement: {
          x: Math.round(x + padX),
          y: cardY + barH + 12,
          width: Math.round(cardW - padX * 2),
          height: titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 18,
          fontWeight: 800,
          color: FUNNEL_TITLE_COLORS[i],
        },
      };
    }
    const bodyM = sid.match(/^funnel_([1-4])_body$/i);
    if (bodyM) {
      const i = Number(bodyM[1]) - 1;
      const x = graphicX + i * (cardW + cardGapX);
      return {
        ...el,
        layer: 10,
        placement: {
          x: Math.round(x + padX),
          y: cardY + barH + 12 + titleH + 4,
          width: Math.round(cardW - padX * 2),
          height: cardH - barH - titleH - 28,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'flex-start',
          fontSize: 14,
          fontWeight: 400,
          color: muted,
          lineHeight: 1.4,
        },
      };
    }
    return el;
  });

  for (let i = 0; i < 4; i += 1) {
    const numId = `FUNNEL_NUM_${i + 1}`;
    if (elements.some((el) => String(el.slotId || '').toUpperCase() === numId)) continue;
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId: numId,
      role: 'caption',
      layer: 12,
      placement: { ...overlay.stages[i].num, rotation: 0, opacity: 1 },
      content: {
        text: String(i + 1).padStart(2, '0'),
        align: 'center',
        verticalAlign: 'center',
        fontSize: 20,
        fontWeight: 800,
        wrap: 'nowrap',
        lineHeight: 1,
        color: '#ffffff',
        padding: 0,
        paddingX: 0,
      },
    });
  }

  const chrome = [];
  for (let i = 0; i < 4; i += 1) {
    const x = Math.round(graphicX + i * (cardW + cardGapX));
    const fill = prevBySlot.get(`FUNNEL_SEG_${i + 1}`)?.content?.fill || colors[i];
    const cardId = `FUNNEL_CARD_${i + 1}`;
    const barId = `FUNNEL_BAR_${i + 1}`;
    const prevC = prevBySlot.get(cardId);
    const prevB = prevBySlot.get(barId);
    chrome.push({
      id: prevC?.id || newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: {
        x,
        y: cardY,
        width: Math.round(cardW),
        height: cardH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: prevC?.content?.fill || cardFills[i],
        borderRadius: 16,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: cardId,
    });
    chrome.push({
      id: prevB?.id || newElementId('shp'),
      type: 'shape',
      layer: 2,
      placement: {
        x,
        y: cardY,
        width: Math.round(cardW),
        height: barH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: prevB?.content?.fill || fill,
        borderRadius: 16,
      },
      role: 'decoration',
      slotId: barId,
    });
  }

  const segs = [0, 1, 2, 3].map((i) => {
    const slotId = `FUNNEL_SEG_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const fill = prev?.content?.fill || colors[i];
    return {
      id: prev?.id || newElementId('shp'),
      type: 'graphic',
      layer: 4 + i,
      placement: { ...funnelHSegPlacement(graphicX, graphicY, graphicW, graphicH, i), rotation: 0, opacity: 1 },
      content: {
        svg: funnelHSegInlineSvg(i),
        colorMode: 'recolorable',
        fill,
        stroke: typeof fill === 'string' ? fill : fill?.color,
        alt: `Funnel stage ${i + 1}`,
      },
      role: 'decoration',
      slotId,
    };
  });

  return { ...doc, elements: [...chrome, ...segs, ...elements, ...extras] };
}

function layoutDiagramFunnel(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  if (isHorizontalFunnelLayout(layoutSchema)) {
    return layoutDiagramFunnelHorizontal(doc, layoutSchema, themeTokens, canvas);
  }
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');

  const headingY = 36;
  const headingH = 72;
  const bottomPad = 48;
  const bodyByStage = [0, 1, 2, 3].map((i) => {
    const el = (doc.elements || []).find((e) =>
      new RegExp(`^funnel_${i + 1}_body$`, 'i').test(String(e.slotId || ''))
    );
    return String(el?.content?.text || '').trim();
  });

  let graphicScale = 0.82;
  let graphicH = 0;
  let graphicW = 0;
  let graphicY = 0;
  let graphicX = 72;
  let overlay = { stages: [] };
  let textX = 0;
  let textWidth = 400;
  let packed = { packs: [], bodyFontSize: 16, titleFontSize: 22, titleH: 34 };

  for (let attempt = 0; attempt < 4; attempt += 1) {
    graphicH = Math.min(Math.round(860 * graphicScale), canvasH - headingY - headingH - bottomPad);
    graphicW = Math.round(graphicH * (FUNNEL_GEOM.viewW / FUNNEL_GEOM.viewH));
    graphicY = headingY + headingH + 6;
    graphicX = 72;
    overlay = funnelOverlayPlacements(graphicX, graphicY, graphicW, graphicH);
    textX = graphicX + graphicW + 36;
    textWidth = Math.max(320, canvasW - textX - 64);
    packed = packFunnelStageTextBlocks({
      stages: overlay.stages,
      bodies: bodyByStage,
      textWidth,
      titleH: 34,
      titleBodyGap: 6,
      stageGap: 20,
      bodyFontSize: 15,
      titleFontSize: 20,
      bodyLineHeight: 1.35,
      regionBottomMax: canvasH - bottomPad,
    });
    const last = packed.packs[packed.packs.length - 1];
    const fits = last && last.bodyY + last.bodyH <= canvasH - bottomPad + 2;
    if (fits && packed.bodyFontSize >= 13) break;
    graphicScale -= 0.08;
  }

  const textPack = packed.packs;
  const bodyFontSize = packed.bodyFontSize;
  const titleFontSize = packed.titleFontSize;
  const bgLum = parseHexLum(palette.bg || palette.background);
  const darkDeck = bgLum != null && bgLum < 0.45;
  const titleColors = darkDeck
    ? [
        paletteColor(palette, 'secondary', '#93C5FD'),
        paletteColor(palette, 'primary', '#BFDBFE'),
        paletteColor(palette, 'accent', '#FDBA74'),
        paletteColor(palette, 'muted', '#CBD5E1'),
      ]
    : FUNNEL_TITLE_COLORS;

  const colors = [
    paletteColor(palette, 'accent', FUNNEL_STAGE_COLORS[0]),
    paletteColor(palette, 'secondary', FUNNEL_STAGE_COLORS[1]),
    paletteColor(palette, 'primary', FUNNEL_STAGE_COLORS[2]),
    paletteColor(palette, 'highlight', FUNNEL_STAGE_COLORS[3]),
  ];
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^FUNNEL_SEG_[1-4]$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !/^FUNNEL_(SEG|TAB|LID|SHADE|RING)_/i.test(String(el.slotId || '')) &&
      String(el.slotId || '') !== 'FUNNEL_RING'
  );
  const extras = [];

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: 64,
          y: headingY,
          width: canvasW - 128,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          color: textColor,
          clipToSlot: true,
        },
      };
    }
    const numM = sid.match(/^FUNNEL_NUM_([1-4])$/i);
    if (numM) {
      const i = Number(numM[1]) - 1;
      return {
        ...el,
        layer: 12,
        placement: { ...overlay.stages[i].num, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: el.content?.text || String(i + 1).padStart(2, '0'),
          align: 'center',
          verticalAlign: 'center',
          fontSize: Math.max(18, Math.round(26 * graphicScale)),
          fontWeight: 800,
          wrap: 'nowrap',
          lineHeight: 1,
          color: '#ffffff',
        },
      };
    }
    const titleM = sid.match(/^funnel_([1-4])_title$/i);
    if (titleM) {
      const i = Number(titleM[1]) - 1;
      const pack = textPack[i] || { titleY: overlay.stages[i].y, titleH: packed.titleH };
      return {
        ...el,
        layer: 10,
        placement: {
          x: textX,
          y: pack.titleY,
          width: textWidth,
          height: pack.titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: titleFontSize,
          fontWeight: 700,
          color: titleColors[i],
          clipToSlot: true,
        },
      };
    }
    const bodyM = sid.match(/^funnel_([1-4])_body$/i);
    if (bodyM) {
      const i = Number(bodyM[1]) - 1;
      const pack = textPack[i] || {
        bodyY: overlay.stages[i].y + 40,
        bodyH: Math.max(40, overlay.stages[i].h - 88),
      };
      return {
        ...el,
        layer: 10,
        placement: {
          x: textX,
          y: pack.bodyY,
          width: textWidth,
          height: pack.bodyH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: bodyFontSize,
          fontWeight: 400,
          color: muted,
          lineHeight: 1.35,
          clipToSlot: true,
          wrap: 'pre-wrap',
        },
      };
    }
    return el;
  });

  for (let i = 0; i < 4; i += 1) {
    const numId = `FUNNEL_NUM_${i + 1}`;
    if (elements.some((el) => String(el.slotId || '').toUpperCase() === numId)) continue;
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId: numId,
      role: 'caption',
      layer: 12,
      placement: { ...overlay.stages[i].num, rotation: 0, opacity: 1 },
      content: {
        text: String(i + 1).padStart(2, '0'),
        align: 'center',
        verticalAlign: 'center',
        fontSize: 28,
        fontWeight: 800,
        wrap: 'nowrap',
        lineHeight: 1,
        color: '#ffffff',
        padding: 0,
        paddingX: 0,
      },
    });
  }

  const segs = [0, 1, 2, 3].map((i) => {
    const slotId = `FUNNEL_SEG_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const fill = prev?.content?.fill || colors[i];
    return {
      id: prev?.id || newElementId('shp'),
      type: 'graphic',
      layer: 2 + i,
      placement: { ...funnelStagePlacement(graphicX, graphicY, graphicW, graphicH, i), rotation: 0, opacity: 1 },
      content: {
        svg: funnelStageInlineSvg(i),
        colorMode: 'recolorable',
        fill,
        stroke: typeof fill === 'string' ? fill : fill?.color,
        alt: `Funnel stage ${i + 1}`,
      },
      role: 'decoration',
      slotId,
    };
  });

  return { ...doc, elements: [...segs, ...elements, ...extras] };
}
function isDiagramMatrixLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return /diagram_matrix/.test(id);
}

function isMatrixGridLayout(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  return variant === 'grid' || (id.includes('matrix') && id.includes('grid'));
}

function isMatrixQuadrantLayout(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  return variant === 'quadrant' || (id.includes('matrix') && id.includes('quadrant'));
}

function layoutDiagramMatrixGrid(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const colors = MATRIX_GRID_COLORS.slice();
  const headingY = 48;
  const headingH = 72;
  const insetX = 72;
  const gap = 22;
  const gridTop = headingY + headingH + 28;
  const gridH = canvasH - gridTop - 48;
  const gridW = canvasW - insetX * 2;
  const cellW = (gridW - gap) / 2;
  const cellH = (gridH - gap) / 2;
  const padX = 36;
  const titleH = 48;

  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^MATRIX_QUAD_[1-4]$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !/^MATRIX_(RING|QUAD_[1-4]|ARROW_[XY]|HUB|CROSS)$/i.test(String(el.slotId || '')) &&
      !/^MATRIX_(CENTER|X_LABEL|Y_LABEL)$/i.test(String(el.slotId || ''))
  );

  const cellBox = (i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    return {
      x: Math.round(insetX + col * (cellW + gap)),
      y: Math.round(gridTop + row * (cellH + gap)),
      w: Math.round(cellW),
      h: Math.round(cellH),
    };
  };

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          x: insetX,
          y: headingY,
          width: canvasW - insetX * 2,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    const qM = sid.match(/^Q([1-4])_(TITLE|BODY)$/i);
    if (qM) {
      const i = Number(qM[1]) - 1;
      const isTitle = String(qM[2]).toUpperCase() === 'TITLE';
      const c = cellBox(i);
      return {
        ...el,
        layer: 12,
        placement: {
          x: c.x + padX,
          y: isTitle ? c.y + Math.round(c.h * 0.28) : c.y + Math.round(c.h * 0.28) + titleH + 8,
          width: c.w - padX * 2,
          height: isTitle ? titleH : Math.round(c.h * 0.32),
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: isTitle ? 'center' : 'flex-start',
          fontSize: isTitle ? 24 : 16,
          fontWeight: isTitle ? 800 : 400,
          color: '#ffffff',
          lineHeight: isTitle ? 1.15 : 1.4,
        },
      };
    }
    return el;
  });

  const quads = [0, 1, 2, 3].map((i) => {
    const c = cellBox(i);
    const slotId = `MATRIX_QUAD_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    return {
      id: prev?.id || newElementId('shp'),
      type: 'shape',
      layer: 3,
      placement: { x: c.x, y: c.y, width: c.w, height: c.h, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        borderRadius: 28,
        fill: prev?.content?.fill || colors[i],
      },
      role: 'decoration',
      slotId,
    };
  });

  return { ...doc, elements: [...quads, ...elements] };
}

function layoutDiagramMatrixQuadrant(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const tints = MATRIX_Q_TINTS.slice();
  const titles = MATRIX_Q_TITLE.slice();
  const headingY = 80;
  const headingH = 88;
  const yLabelW = 56;
  const xLabelH = 44;
  const plotX = 88 + yLabelW;
  const plotY = headingY + headingH + 12;
  const plotW = canvasW - plotX - 72;
  const plotH = canvasH - plotY - 36 - xLabelH;
  const cellW = plotW / 2;
  const cellH = plotH / 2;
  const padX = 48;
  const titleH = 42;
  const bodyH = 70;
  const stackGap = 8;

  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^(MATRIX_QUAD_[1-4]|MATRIX_CROSS)$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !/^MATRIX_(RING|QUAD_[1-4]|ARROW_[XY]|HUB|CROSS)$/i.test(String(el.slotId || '')) &&
      String(el.slotId || '').toUpperCase() !== 'MATRIX_CENTER'
  );

  const cellBox = (i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    return {
      x: Math.round(plotX + col * cellW),
      y: Math.round(plotY + row * cellH),
      w: Math.round(cellW),
      h: Math.round(cellH),
    };
  };

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          x: 72,
          y: headingY,
          width: canvasW - 144,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 32,
          fontWeight: 800,
          lineHeight: 1.1,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    const qM = sid.match(/^Q([1-4])_(TITLE|BODY)$/i);
    if (qM) {
      const i = Number(qM[1]) - 1;
      const isTitle = String(qM[2]).toUpperCase() === 'TITLE';
      const c = cellBox(i);
      const stackH = titleH + stackGap + bodyH;
      const stackY = c.y + Math.round((c.h - stackH) / 2);
      return {
        ...el,
        layer: 12,
        placement: {
          x: c.x + padX,
          y: isTitle ? stackY : stackY + titleH + stackGap,
          width: c.w - padX * 2,
          height: isTitle ? titleH : bodyH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: isTitle ? 20 : 15,
          fontWeight: isTitle ? 800 : 400,
          color: isTitle ? titles[i] : '#4B5563',
          lineHeight: isTitle ? 1.2 : 1.4,
        },
      };
    }
    if (sid.toUpperCase() === 'MATRIX_Y_LABEL') {
      return {
        ...el,
        layer: 12,
        placement: {
          x: Math.round(88 + yLabelW / 2 - plotH * 0.28),
          y: Math.round(plotY + plotH / 2 - 22),
          width: Math.round(plotH * 0.56),
          height: 44,
          rotation: -90,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 16,
          fontWeight: 700,
          color: MATRIX_Q_AXIS,
          wrap: 'nowrap',
        },
      };
    }
    if (sid.toUpperCase() === 'MATRIX_X_LABEL') {
      return {
        ...el,
        layer: 12,
        placement: {
          x: plotX,
          y: plotY + plotH + 8,
          width: plotW,
          height: xLabelH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 16,
          fontWeight: 700,
          color: MATRIX_Q_AXIS,
          wrap: 'nowrap',
        },
      };
    }
    return el;
  });

  const extras = [];
  if (!elements.some((el) => String(el.slotId || '').toUpperCase() === 'MATRIX_Y_LABEL')) {
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId: 'MATRIX_Y_LABEL',
      role: 'caption',
      layer: 12,
      placement: {
        x: Math.round(88 + yLabelW / 2 - plotH * 0.28),
        y: Math.round(plotY + plotH / 2 - 22),
        width: Math.round(plotH * 0.56),
        height: 44,
        rotation: -90,
        opacity: 1,
      },
      content: {
        text: 'Impact',
        align: 'center',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 700,
        color: MATRIX_Q_AXIS,
        wrap: 'nowrap',
        padding: 0,
      },
    });
  }
  if (!elements.some((el) => String(el.slotId || '').toUpperCase() === 'MATRIX_X_LABEL')) {
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId: 'MATRIX_X_LABEL',
      role: 'caption',
      layer: 12,
      placement: {
        x: plotX,
        y: plotY + plotH + 8,
        width: plotW,
        height: xLabelH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: 'Effort',
        align: 'center',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 700,
        color: MATRIX_Q_AXIS,
        wrap: 'nowrap',
        padding: 0,
      },
    });
  }

  const quads = [0, 1, 2, 3].map((i) => {
    const c = cellBox(i);
    const slotId = `MATRIX_QUAD_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    return {
      id: prev?.id || newElementId('shp'),
      type: 'shape',
      layer: 2,
      placement: { x: c.x, y: c.y, width: c.w, height: c.h, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        borderRadius: 0,
        fill: prev?.content?.fill || tints[i],
      },
      role: 'decoration',
      slotId,
    };
  });
  const prevCross = prevBySlot.get('MATRIX_CROSS');
  const cross = {
    id: prevCross?.id || newElementId('shp'),
    type: 'graphic',
    layer: 6,
    placement: { x: plotX, y: plotY, width: plotW, height: plotH, rotation: 0, opacity: 1 },
    content: {
      svg: matrixQuadrantCrossInlineSvg(),
      colorMode: 'recolorable',
      fill: prevCross?.content?.fill || MATRIX_Q_AXIS,
      alt: 'Quadrant axes',
    },
    role: 'decoration',
    slotId: 'MATRIX_CROSS',
  };

  return { ...doc, elements: [...quads, cross, ...elements, ...extras] };
}

function layoutDiagramMatrix(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  if (isMatrixGridLayout(layoutSchema)) return layoutDiagramMatrixGrid(doc, layoutSchema, themeTokens, canvas);
  if (isMatrixQuadrantLayout(layoutSchema)) return layoutDiagramMatrixQuadrant(doc, layoutSchema, themeTokens, canvas);
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');

  const headingY = 56;
  const headingH = 72;
  const graphicY = headingY + headingH + 28;
  const graphicH = Math.min(820, canvasH - graphicY - 48);
  const graphicW = Math.round(graphicH * (MATRIX_GEOM.viewW / MATRIX_GEOM.viewH));
  const graphicX = Math.round((canvasW - graphicW) / 2);
  const overlay = matrixOverlayPlacements(graphicX, graphicY, graphicW, graphicH);
  const colors = [
    paletteColor(palette, 'accent', MATRIX_QUAD_COLORS[0]),
    paletteColor(palette, 'secondary', MATRIX_QUAD_COLORS[1]),
    paletteColor(palette, 'primary', MATRIX_QUAD_COLORS[2]),
    paletteColor(palette, 'highlight', MATRIX_QUAD_COLORS[3]),
  ];
  const arrowFill = paletteColor(palette, 'accent', MATRIX_ARROW_COLOR);

  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^MATRIX_(QUAD_[1-4]|ARROW_[XY]|HUB)$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) => !/^MATRIX_(RING|QUAD_[1-4]|ARROW_[XY]|HUB)$/i.test(String(el.slotId || ''))
  );
  const extras = [];
  const textBase = (el) => ({
    ...(el.content || {}),
    letterSpacing: '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  });

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = textBase(el);
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          x: 72,
          y: headingY,
          width: canvasW - 144,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          color: textColor,
        },
      };
    }
    const qM = sid.match(/^Q([1-4])_(TITLE|BODY)$/i);
    if (qM) {
      const i = Number(qM[1]) - 1;
      const isTitle = String(qM[2]).toUpperCase() === 'TITLE';
      const box = isTitle ? overlay.cells[i].title : overlay.cells[i].body;
      return {
        ...el,
        layer: 12,
        placement: { ...box, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'center',
          verticalAlign: isTitle ? 'flex-end' : 'flex-start',
          fontSize: isTitle ? 22 : 15,
          fontWeight: isTitle ? 800 : 400,
          color: '#ffffff',
          lineHeight: isTitle ? 1.15 : 1.35,
        },
      };
    }
    if (sid.toUpperCase() === 'MATRIX_CENTER') {
      return {
        ...el,
        layer: 14,
        placement: { ...overlay.center, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 16,
          fontWeight: 800,
          color: '#111827',
          lineHeight: 1.2,
        },
      };
    }
    if (sid.toUpperCase() === 'MATRIX_Y_LABEL') {
      return {
        ...el,
        layer: 12,
        placement: { ...overlay.yLabel, opacity: 1 },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 16,
          fontWeight: 700,
          color: '#ffffff',
          wrap: 'nowrap',
        },
      };
    }
    if (sid.toUpperCase() === 'MATRIX_X_LABEL') {
      return {
        ...el,
        layer: 12,
        placement: { ...overlay.xLabel, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 16,
          fontWeight: 700,
          color: '#ffffff',
          wrap: 'nowrap',
        },
      };
    }
    return el;
  });

  const ensureText = (slotId, placement, content) => {
    if (elements.some((el) => String(el.slotId || '').toUpperCase() === slotId)) return;
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId,
      role: 'caption',
      layer: 12,
      placement: { ...placement, rotation: placement.rotation || 0, opacity: 1 },
      content: { padding: 0, paddingX: 0, ...content },
    });
  };
  ensureText('MATRIX_CENTER', overlay.center, {
    text: 'Insert your desired text here.',
    align: 'center',
    verticalAlign: 'center',
    fontSize: 16,
    fontWeight: 800,
    color: '#111827',
    lineHeight: 1.2,
  });
  ensureText('MATRIX_Y_LABEL', overlay.yLabel, {
    text: 'Placeholder',
    align: 'center',
    verticalAlign: 'center',
    fontSize: 16,
    fontWeight: 700,
    color: '#ffffff',
    wrap: 'nowrap',
  });
  ensureText('MATRIX_X_LABEL', overlay.xLabel, {
    text: 'Placeholder',
    align: 'center',
    verticalAlign: 'center',
    fontSize: 16,
    fontWeight: 700,
    color: '#ffffff',
    wrap: 'nowrap',
  });

  const quads = [0, 1, 2, 3].map((i) => {
    const slotId = `MATRIX_QUAD_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const place = matrixQuadPlacement(graphicX, graphicY, graphicW, graphicH, i);
    const { borderRadius, ...placement } = place;
    return {
      id: prev?.id || newElementId('shp'),
      type: 'shape',
      layer: 3,
      placement: { ...placement, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        borderRadius,
        fill: prev?.content?.fill || colors[i],
      },
      role: 'decoration',
      slotId,
    };
  });
  const prevAy = prevBySlot.get('MATRIX_ARROW_Y');
  const prevAx = prevBySlot.get('MATRIX_ARROW_X');
  const arrows = [
    {
      id: prevAy?.id || newElementId('shp'),
      type: 'graphic',
      layer: 2,
      placement: { ...matrixArrowPlacement(graphicX, graphicY, graphicW, graphicH, 'y'), rotation: 0, opacity: 1 },
      content: {
        svg: matrixArrowInlineSvg('y'),
        colorMode: 'recolorable',
        fill: prevAy?.content?.fill || arrowFill,
        alt: 'Matrix Y axis',
      },
      role: 'decoration',
      slotId: 'MATRIX_ARROW_Y',
    },
    {
      id: prevAx?.id || newElementId('shp'),
      type: 'graphic',
      layer: 2,
      placement: { ...matrixArrowPlacement(graphicX, graphicY, graphicW, graphicH, 'x'), rotation: 0, opacity: 1 },
      content: {
        svg: matrixArrowInlineSvg('x'),
        colorMode: 'recolorable',
        fill: prevAx?.content?.fill || arrowFill,
        alt: 'Matrix X axis',
      },
      role: 'decoration',
      slotId: 'MATRIX_ARROW_X',
    },
  ];
  const prevHub = prevBySlot.get('MATRIX_HUB');
  const hub = {
    id: prevHub?.id || newElementId('shp'),
    type: 'shape',
    layer: 8,
    placement: { ...overlay.hub, rotation: 0, opacity: 1 },
    content: {
      shape: 'ellipse',
      fill: prevHub?.content?.fill || '#ffffff',
    },
    role: 'decoration',
    slotId: 'MATRIX_HUB',
  };

  return { ...doc, elements: [...arrows, ...quads, hub, ...elements, ...extras] };
}

function isDiagramSwotLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return /diagram_swot/.test(id);
}

const SWOT_CHROME =
  /^(SWOT_SEG_[1-4]|SWOT_ICON_[1-4]|SWOT_DASH_[1-4]|SWOT_HUB|SWOT_LETTER_[1-4]|SWOT_CARD_[1-4]|SWOT_BAR_[1-4])$/i;

function layoutDiagramSwotGrid(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const frame = swotQuadFrame(canvasW, canvasH, 'grid');
  const colors = SWOT_COLORS.slice();
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^SWOT_CARD_[1-4]$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !SWOT_CHROME.test(String(el.slotId || '')));
  const seenLetter = new Set(
    elements.filter((el) => /^SWOT_LETTER_[1-4]$/i.test(String(el.slotId || ''))).map((el) => String(el.slotId).toUpperCase())
  );

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: frame.insetX,
          y: frame.headingY,
          width: canvasW - frame.insetX * 2,
          height: frame.headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    if (/^SWOT_HUB_(TITLE|SUB)$/i.test(sid)) {
      return { ...el, placement: { x: -40, y: -40, width: 1, height: 1, rotation: 0, opacity: 0 } };
    }
    const letterM = sid.match(/^SWOT_LETTER_([1-4])$/i);
    const titleM = sid.match(/^Q([1-4])_TITLE$/i);
    const bodyM = sid.match(/^Q([1-4])_BODY$/i);
    const num = Number((letterM || titleM || bodyM)?.[1]);
    if (!num) return el;
    const i = num - 1;
    const cell = frame.cells[i];
    const pad = 28;
    const letterW = 96;
    const letterH = 88;
    if (letterM) {
      return {
        ...el,
        layer: 12,
        placement: { x: cell.x + pad, y: cell.y + pad, width: letterW, height: letterH, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: SWOT_LETTERS[i],
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          wrap: 'nowrap',
          lineHeight: 1,
          color: '#ffffff',
          clipToSlot: false,
        },
      };
    }
    if (titleM) {
      const raw = String(el.content?.text || '').trim();
      const text = !raw || /text here|double-click/i.test(raw) ? SWOT_LABELS[i] : raw;
      return {
        ...el,
        layer: 10,
        placement: {
          x: cell.x + pad + letterW + 12,
          y: cell.y + pad + 8,
          width: cell.width - pad * 2 - letterW - 12,
          height: 56,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          text,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 26,
          fontWeight: 800,
          color: '#ffffff',
          clipToSlot: false,
        },
      };
    }
    return {
      ...el,
      layer: 10,
      placement: {
        x: cell.x + pad,
        y: cell.y + pad + letterH + 12,
        width: cell.width - pad * 2,
        height: Math.max(80, cell.height - pad * 2 - letterH - 12),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: 'left',
        verticalAlign: 'flex-start',
        fontSize: 16,
        fontWeight: 400,
        lineHeight: 1.4,
        color: '#ffffff',
        wrap: 'wrap',
        clipToSlot: false,
      },
    };
  });

  const chrome = [];
  for (let i = 0; i < 4; i += 1) {
    const cell = frame.cells[i];
    const slotId = `SWOT_CARD_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    chrome.push({
      id: prev?.id || newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: { ...cell, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: prev?.content?.fill || colors[i], borderRadius: 20, layoutSurface: true },
      role: 'decoration',
      slotId,
    });
    const letterId = `SWOT_LETTER_${i + 1}`;
    if (!seenLetter.has(letterId)) {
      chrome.push({
        id: newElementId('txt'),
        type: 'text',
        layer: 12,
        placement: { x: cell.x + 28, y: cell.y + 28, width: 96, height: 88, rotation: 0, opacity: 1 },
        content: {
          text: SWOT_LETTERS[i],
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          wrap: 'nowrap',
          lineHeight: 1,
          color: '#ffffff',
          padding: 0,
          clipToSlot: false,
        },
        role: 'caption',
        slotId: letterId,
      });
    }
  }
  return { ...doc, elements: [...chrome, ...elements] };
}

function layoutDiagramSwotCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const frame = swotQuadFrame(canvasW, canvasH, 'cards');
  const colors = SWOT_COLORS.slice();
  const barH = 92;
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^SWOT_(CARD|BAR)_[1-4]$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !SWOT_CHROME.test(String(el.slotId || '')));
  const seenLetter = new Set(
    elements.filter((el) => /^SWOT_LETTER_[1-4]$/i.test(String(el.slotId || ''))).map((el) => String(el.slotId).toUpperCase())
  );

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: frame.insetX,
          y: frame.headingY,
          width: canvasW - frame.insetX * 2,
          height: frame.headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    if (/^SWOT_HUB_(TITLE|SUB)$/i.test(sid)) {
      return { ...el, placement: { x: -40, y: -40, width: 1, height: 1, rotation: 0, opacity: 0 } };
    }
    const letterM = sid.match(/^SWOT_LETTER_([1-4])$/i);
    const titleM = sid.match(/^Q([1-4])_TITLE$/i);
    const bodyM = sid.match(/^Q([1-4])_BODY$/i);
    const num = Number((letterM || titleM || bodyM)?.[1]);
    if (!num) return el;
    const i = num - 1;
    const cell = frame.cells[i];
    const pad = 28;
    if (letterM) {
      return {
        ...el,
        layer: 12,
        placement: { x: cell.x + pad, y: cell.y + 10, width: 64, height: barH - 20, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: SWOT_LETTERS[i],
          align: 'center',
          verticalAlign: 'center',
          fontSize: 32,
          fontWeight: 800,
          wrap: 'nowrap',
          color: '#ffffff',
          clipToSlot: false,
        },
      };
    }
    if (titleM) {
      const raw = String(el.content?.text || '').trim();
      const text = !raw || /text here|double-click/i.test(raw) ? SWOT_LABELS[i] : raw;
      return {
        ...el,
        layer: 10,
        placement: {
          x: cell.x + pad + 72,
          y: cell.y + 10,
          width: cell.width - pad * 2 - 72,
          height: barH - 20,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          text,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 22,
          fontWeight: 800,
          color: '#ffffff',
          clipToSlot: false,
        },
      };
    }
    return {
      ...el,
      layer: 10,
      placement: {
        x: cell.x + pad,
        y: cell.y + barH + 24,
        width: cell.width - pad * 2,
        height: Math.max(64, cell.height - barH - 48),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: 'left',
        verticalAlign: 'flex-start',
        fontSize: 16,
        fontWeight: 400,
        lineHeight: 1.45,
        color: muted,
        wrap: 'wrap',
        clipToSlot: false,
      },
    };
  });

  const chrome = [];
  for (let i = 0; i < 4; i += 1) {
    const cell = frame.cells[i];
    const cardId = `SWOT_CARD_${i + 1}`;
    const barId = `SWOT_BAR_${i + 1}`;
    const prevC = prevBySlot.get(cardId);
    const prevB = prevBySlot.get(barId);
    chrome.push({
      id: prevC?.id || newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: { ...cell, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: prevC?.content?.fill || '#F8FAFC', borderRadius: 20, layoutSurface: true },
      role: 'decoration',
      slotId: cardId,
    });
    chrome.push({
      id: prevB?.id || newElementId('shp'),
      type: 'shape',
      layer: 2,
      placement: { x: cell.x, y: cell.y, width: cell.width, height: barH, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: prevB?.content?.fill || colors[i], borderRadius: 20, layoutSurface: true },
      role: 'decoration',
      slotId: barId,
    });
    const letterId = `SWOT_LETTER_${i + 1}`;
    if (!seenLetter.has(letterId)) {
      chrome.push({
        id: newElementId('txt'),
        type: 'text',
        layer: 12,
        placement: { x: cell.x + 28, y: cell.y + 10, width: 64, height: barH - 20, rotation: 0, opacity: 1 },
        content: {
          text: SWOT_LETTERS[i],
          align: 'center',
          verticalAlign: 'center',
          fontSize: 32,
          fontWeight: 800,
          wrap: 'nowrap',
          color: '#ffffff',
          padding: 0,
          clipToSlot: false,
        },
        role: 'caption',
        slotId: letterId,
      });
    }
  }
  return { ...doc, elements: [...chrome, ...elements] };
}

function layoutDiagramSwot(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const mode = swotModeFromSchema(layoutSchema);
  if (mode === 'grid') return layoutDiagramSwotGrid(doc, layoutSchema, themeTokens, canvas);
  if (mode === 'cards') return layoutDiagramSwotCards(doc, layoutSchema, themeTokens, canvas);
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const frame = swotGraphicBox(canvasW, canvasH);
  const overlay = swotOverlayPlacements(frame);
  const colors = [
    paletteColor(palette, 'accent', SWOT_COLORS[0]),
    paletteColor(palette, 'secondary', SWOT_COLORS[1]),
    paletteColor(palette, 'primary', SWOT_COLORS[2]),
    paletteColor(palette, 'highlight', SWOT_COLORS[3]),
  ];
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^SWOT_(SEG|ICON)_[1-4]$/i.test(String(el.slotId || '')) || String(el.slotId || '').toUpperCase() === 'SWOT_HUB')
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !/^(SWOT_SEG_[1-4]|SWOT_ICON_[1-4]|SWOT_DASH_[1-4]|SWOT_HUB|SWOT_LETTER_[1-4]|SWOT_CARD_[1-4]|SWOT_BAR_[1-4])$/i.test(String(el.slotId || '')));
  const extras = [];

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: { ...(el.placement || {}), x: 48, y: frame.headingY, width: canvasW - 96, height: frame.headingH, rotation: 0, opacity: 1 },
        content: { ...base, align: 'left', verticalAlign: 'center', fontSize: 28, fontWeight: 800, color: textColor, lineHeight: 1.2 },
      };
    }
    if (sid.toUpperCase() === 'SWOT_HUB_TITLE') {
      return {
        ...el,
        layer: 14,
        placement: { ...overlay.hubTitle, rotation: 0, opacity: 1 },
        content: { ...base, text: el.content?.text || 'SWOT', align: 'center', verticalAlign: 'center', fontSize: 36, fontWeight: 800, wrap: 'nowrap', lineHeight: 1, color: '#111827' },
      };
    }
    if (sid.toUpperCase() === 'SWOT_HUB_SUB') {
      return {
        ...el,
        layer: 14,
        placement: { ...overlay.hubSub, rotation: 0, opacity: 1 },
        content: { ...base, text: el.content?.text || 'Analysis', align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 600, lineHeight: 1.15, color: muted },
      };
    }
    const titleM = sid.match(/^Q([1-4])_TITLE$/i);
    if (titleM) {
      const i = Number(titleM[1]) - 1;
      return {
        ...el,
        layer: 10,
        placement: { ...overlay.rows[i].title, rotation: 0, opacity: 1 },
        content: { ...base, align: 'left', verticalAlign: 'center', fontSize: 20, fontWeight: 800, color: colors[i] },
      };
    }
    const bodyM = sid.match(/^Q([1-4])_BODY$/i);
    if (bodyM) {
      const i = Number(bodyM[1]) - 1;
      return {
        ...el,
        layer: 10,
        placement: { ...overlay.rows[i].body, rotation: 0, opacity: 1 },
        content: { ...base, align: 'left', verticalAlign: 'flex-start', fontSize: 15, fontWeight: 400, color: muted, lineHeight: 1.35 },
      };
    }
    return el;
  });

  const ensure = (slotId, placement, content) => {
    if (elements.some((el) => String(el.slotId || '').toUpperCase() === slotId)) return;
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId,
      role: 'caption',
      layer: 12,
      placement: { ...placement, rotation: 0, opacity: 1 },
      content: { padding: 0, paddingX: 0, ...content },
    });
  };
  ensure('SWOT_HUB_TITLE', overlay.hubTitle, { text: 'SWOT', align: 'center', verticalAlign: 'center', fontSize: 36, fontWeight: 800, wrap: 'nowrap', lineHeight: 1, color: '#111827' });
  ensure('SWOT_HUB_SUB', overlay.hubSub, { text: 'Analysis', align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 600, lineHeight: 1.15, color: muted });

  const { graphicX, graphicY, graphicW, graphicH } = frame;
  const petals = [0, 1, 2, 3].map((i) => {
    const slotId = `SWOT_SEG_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const fill = prev?.content?.fill || colors[i];
    return {
      id: prev?.id || newElementId('shp'),
      type: 'graphic',
      layer: 3,
      placement: { ...swotPetalPlacement(graphicX, graphicY, graphicW, graphicH, i), rotation: 0, opacity: 1 },
      content: { svg: swotPetalInlineSvg(i), colorMode: 'recolorable', fill, alt: `SWOT ${SWOT_LETTERS[i]}` },
      role: 'decoration',
      slotId,
    };
  });
  const prevHub = prevBySlot.get('SWOT_HUB');
  const hub = {
    id: prevHub?.id || newElementId('shp'),
    type: 'shape',
    layer: 8,
    placement: { ...overlay.hub, rotation: 0, opacity: 1 },
    content: { shape: 'ellipse', fill: prevHub?.content?.fill || '#ffffff' },
    role: 'decoration',
    slotId: 'SWOT_HUB',
  };
  const icons = [0, 1, 2, 3].map((i) => {
    const slotId = `SWOT_ICON_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    const fill = prev?.content?.fill || colors[i];
    return {
      id: prev?.id || newElementId('shp'),
      type: 'graphic',
      layer: 5,
      placement: { ...overlay.rows[i].icon, rotation: 0, opacity: 1 },
      content: { svg: swotIconInlineSvg(i), colorMode: 'recolorable', fill, alt: SWOT_LABELS[i] },
      role: 'decoration',
      slotId,
    };
  });
  const dashes = [0, 1, 2, 3].map((i) => ({
    id: newElementId('shp'),
    type: 'graphic',
    layer: 2,
    placement: { ...overlay.rows[i].dash, rotation: 0, opacity: 1 },
    content: { svg: swotDashInlineSvg(), colorMode: 'fixed', alt: '' },
    role: 'decoration',
    slotId: `SWOT_DASH_${i + 1}`,
  }));

  return { ...doc, elements: [...dashes, ...petals, hub, ...icons, ...elements, ...extras] };
}

function isDiagramVennLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return /diagram_venn/.test(id);
}

function layoutDiagramVennOverlap(doc, layoutSchema, themeTokens, canvas, kind) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const frame = kind === 'stacked' ? vennStackedFrame(canvasW, canvasH) : vennThreeCircleFrame(canvasW, canvasH);
  const colors = VENN_COLORS.slice();
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^VENN_OUTER_[1-3]$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !/^(VENN_(OUTER|MID|CORE|ICON)_[1-3])$/i.test(String(el.slotId || '')) &&
      !(kind === 'stacked' && String(el.slotId || '').toUpperCase() === 'CENTER_BODY')
  );
  const hasCenter = kind !== 'stacked' && elements.some((el) => String(el.slotId || '').toUpperCase() === 'CENTER_BODY');

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: 56,
          y: frame.headingY,
          width: canvasW - 112,
          height: frame.headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    if (sid.toUpperCase() === 'CENTER_BODY') {
      return {
        ...el,
        layer: 12,
        placement: { ...frame.center, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text: el.content?.text || 'Shared overlap',
          align: 'center',
          verticalAlign: 'center',
          fontSize: kind === 'stacked' ? 16 : 18,
          fontWeight: 700,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
        },
      };
    }
    const titleM = sid.match(/^Q([1-3])_TITLE$/i);
    const bodyM = sid.match(/^Q([1-3])_BODY$/i);
    const num = Number((titleM || bodyM)?.[1]);
    if (!num) return el;
    const i = num - 1;
    if (titleM) {
      return {
        ...el,
        layer: 10,
        placement: { ...frame.labels[i].title, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: kind === 'stacked' || i !== 2 ? 'left' : 'center',
          verticalAlign: 'center',
          fontSize: 22,
          fontWeight: 800,
          lineHeight: 1.2,
          color: colors[i],
          clipToSlot: false,
        },
      };
    }
    return {
      ...el,
      layer: 10,
      placement: { ...frame.labels[i].body, rotation: 0, opacity: 1 },
      content: {
        ...base,
        align: kind === 'stacked' || i !== 2 ? 'left' : 'center',
        verticalAlign: 'flex-start',
        fontSize: 15,
        fontWeight: 400,
        lineHeight: 1.4,
        color: muted,
        wrap: 'wrap',
        clipToSlot: false,
      },
    };
  });

  const extras = [];
  if (kind !== 'stacked' && !hasCenter) {
    extras.push({
      id: newElementId('txt'),
      type: 'text',
      slotId: 'CENTER_BODY',
      role: 'caption',
      layer: 12,
      placement: { ...frame.center, rotation: 0, opacity: 1 },
      content: {
        text: 'Shared overlap',
        align: 'center',
        verticalAlign: 'center',
        fontSize: kind === 'stacked' ? 16 : 18,
        fontWeight: 700,
        color: textColor,
        padding: 0,
        clipToSlot: false,
      },
    });
  }

  const rings = [0, 1, 2].map((i) => {
    const slotId = `VENN_OUTER_${i + 1}`;
    const prev = prevBySlot.get(slotId);
    return {
      id: prev?.id || newElementId('shp'),
      type: 'shape',
      layer: 2 + i,
      placement: { ...frame.circles[i], rotation: 0, opacity: 0.62 },
      content: { shape: 'ellipse', fill: prev?.content?.fill || colors[i] },
      role: 'decoration',
      slotId,
    };
  });
  return { ...doc, elements: [...rings, ...elements, ...extras] };
}

function layoutDiagramVenn(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const mode = vennModeFromSchema(layoutSchema);
  if (mode === 'three_circle') return layoutDiagramVennOverlap(doc, layoutSchema, themeTokens, canvas, 'three_circle');
  if (mode === 'stacked') return layoutDiagramVennOverlap(doc, layoutSchema, themeTokens, canvas, 'stacked');
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const frame = vennFrame(canvasW, canvasH);
  const colors = [
    paletteColor(palette, 'secondary', VENN_COLORS[0]),
    paletteColor(palette, 'accent', VENN_COLORS[1]),
    paletteColor(palette, 'primary', VENN_COLORS[2]),
  ];
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => /^VENN_(OUTER|MID|CORE)_[1-3]$/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !/^(VENN_(OUTER|MID|CORE|ICON)_[1-3])$/i.test(String(el.slotId || '')) &&
      String(el.slotId || '').toUpperCase() !== 'CENTER_BODY'
  );
  const geoms = [0, 1, 2].map((i) => vennSetGeom(i, frame));

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: { ...(el.placement || {}), x: 56, y: frame.headingY, width: canvasW - 112, height: frame.headingH, rotation: 0, opacity: 1 },
        content: { ...base, align: 'left', verticalAlign: 'center', fontSize: 36, fontWeight: 800, lineHeight: 1.15, color: textColor },
      };
    }
    const titleM = sid.match(/^Q([1-3])_TITLE$/i);
    if (titleM) {
      const i = Number(titleM[1]) - 1;
      return {
        ...el,
        layer: 10,
        placement: { ...geoms[i].title, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 22,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          wrap: 'wrap',
        },
      };
    }
    const bodyM = sid.match(/^Q([1-3])_BODY$/i);
    if (bodyM) {
      const i = Number(bodyM[1]) - 1;
      return {
        ...el,
        layer: 10,
        placement: { ...geoms[i].body, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'flex-start',
          fontSize: 16,
          fontWeight: 400,
          color: muted,
          lineHeight: 1.45,
          wrap: 'wrap',
        },
      };
    }
    return el;
  });

  const rings = [];
  for (let i = 0; i < VENN_N; i += 1) {
    const g = geoms[i];
    const base = colors[i];
    const outerId = `VENN_OUTER_${i + 1}`;
    const midId = `VENN_MID_${i + 1}`;
    const coreId = `VENN_CORE_${i + 1}`;
    const prevO = prevBySlot.get(outerId);
    const prevM = prevBySlot.get(midId);
    const prevC = prevBySlot.get(coreId);
    rings.push({
      id: prevO?.id || newElementId('shp'),
      type: 'shape',
      layer: 2,
      placement: { ...g.outer, rotation: 0, opacity: 0.88 },
      content: { shape: 'ellipse', fill: prevO?.content?.fill || vennRingColor(base, 'outer') },
      role: 'decoration',
      slotId: outerId,
    });
    rings.push({
      id: prevM?.id || newElementId('shp'),
      type: 'shape',
      layer: 4,
      placement: { ...g.mid, rotation: 0, opacity: 0.94 },
      content: { shape: 'ellipse', fill: prevM?.content?.fill || vennRingColor(base, 'mid') },
      role: 'decoration',
      slotId: midId,
    });
    rings.push({
      id: prevC?.id || newElementId('shp'),
      type: 'graphic',
      layer: 7,
      placement: { ...g.core, rotation: 0, opacity: 1 },
      content: {
        svg: vennCoreInlineSvg(),
        colorMode: 'recolorable',
        fill: prevC?.content?.fill || vennRingColor(base, 'core'),
        alt: `Venn core ${i + 1}`,
      },
      role: 'decoration',
      slotId: coreId,
    });
    rings.push({
      id: newElementId('shp'),
      type: 'graphic',
      layer: 8,
      placement: { ...g.icon, rotation: 0, opacity: 1 },
      content: { svg: vennIconInlineSvg(i), colorMode: 'fixed', alt: '' },
      role: 'decoration',
      slotId: `VENN_ICON_${i + 1}`,
    });
  }

  return { ...doc, elements: [...rings, ...elements] };
}

function isQuoteGridLayout(layoutId) {
  return /quote_grid/.test(String(layoutId || '').toLowerCase());
}

function isQuotePortraitLayout(layoutId) {
  return /quote_portrait/.test(String(layoutId || '').toLowerCase());
}

function isQuoteTestimonialLayout(layoutId) {
  return /quote_testimonial/.test(String(layoutId || '').toLowerCase());
}

function isStatementLargeLayout(layoutId) {
  return /statement_large/.test(String(layoutId || '').toLowerCase());
}

function isStatementLeftLayout(layoutId) {
  return /statement_left/.test(String(layoutId || '').toLowerCase());
}

function isQuoteAttributionLayout(layoutId) {
  return /quote_attribution_v1|quote_with_attribution/.test(String(layoutId || '').toLowerCase());
}

function isQuoteSingleCardFromSlots(schema) {
  const ids = (schema?.slots || []).map((s) => String(s.id || '').toUpperCase());
  if (ids.some((id) => /^QUOTE_[123]$/.test(id))) return false;
  const hasQuote = ids.includes('QUOTE') || ids.includes('STATEMENT');
  const hasPerson = ids.includes('NAME') || ids.includes('ATTRIBUTION') || ids.includes('ROLE');
  const hasPhoto = ids.some((id) => id === 'PORTRAIT_IMAGE' || id === 'AVATAR' || /^AVATAR_\d+$/.test(id));
  return hasQuote && hasPerson && hasPhoto;
}

const QUOTE_PORTRAIT_DECO = /^(QUOTE_CARD|QUOTE_MARK|QUOTE_AVATAR_BG)$/i;

function layoutQuotePortrait(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const cardFill = paletteColor(palette, 'cardBg', '#FFFFFF');
  const markFill = paletteColor(palette, 'primary', QUOTE_MARK_COLOR);
  const compact = isQuoteTestimonialLayout(layoutSchema?.layout_id);
  const large = isStatementLargeLayout(layoutSchema?.layout_id);
  const fromSlots = isQuoteSingleCardFromSlots(layoutSchema);
  const left =
    isStatementLeftLayout(layoutSchema?.layout_id) ||
    (fromSlots &&
      !compact &&
      !large &&
      !isQuotePortraitLayout(layoutSchema?.layout_id) &&
      !isQuoteAttributionLayout(layoutSchema?.layout_id));
  const g = compact
    ? quoteTestimonialGeom(canvasW, canvasH)
    : left
      ? quoteStatementLeftGeom(canvasW, canvasH)
      : quotePortraitGeom(canvasW, canvasH);
  const quoteSize = compact ? 26 : large ? 36 : left ? 30 : 32;
  const quoteWeight = compact ? 600 : 700;
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => QUOTE_PORTRAIT_DECO.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !QUOTE_PORTRAIT_DECO.test(String(el.slotId || '')) &&
      !/^(HEADING|BODY|EYEBROW)$/i.test(String(el.slotId || ''))
  );
  const hasName = elements.some((el) => /^NAME(_\d+)?$/i.test(String(el.slotId || '')));
  if (hasName) {
    elements = elements.filter((el) => {
      const sid = String(el.slotId || '').toUpperCase();
      return !/^(ATTRIBUTION|ATTR|AUTHOR|AUTHOR_NAME)$/i.test(sid);
    });
  }
  elements = elements.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
      fontStyle: 'normal',
    };
    if (sid === 'QUOTE' || sid === 'STATEMENT') {
      return {
        ...el,
        layer: 10,
        placement: { ...g.quote, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: quoteSize,
          fontWeight: quoteWeight,
          lineHeight: 1.4,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
          fontStyle: 'italic',
        },
      };
    }
    if (sid === 'NAME' || sid === 'AUTHOR_NAME' || sid === 'ATTRIBUTION') {
      return {
        ...el,
        layer: 12,
        placement: { ...g.name, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 18,
          fontWeight: 700,
          lineHeight: 1.35,
          color: textColor,
          wrap: 'nowrap',
          clipToSlot: false,
          verticalAlign: 'flex-start',
        },
      };
    }
    if (sid === 'ROLE' || sid === 'AUTHOR_TITLE') {
      return {
        ...el,
        layer: 12,
        placement: { ...g.role, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 15,
          fontWeight: 400,
          lineHeight: 1.3,
          color: muted,
          wrap: 'wrap',
          clipToSlot: false,
        },
      };
    }
    if (/^(PORTRAIT_IMAGE|AVATAR|AVATAR_\d+)$/i.test(sid)) {
      return {
        ...el,
        layer: 13,
        placement: { ...g.avatar, rotation: 0, opacity: 1 },
        content: {
          ...(el.content || {}),
          fit: 'cover',
          borderRadius: 999,
          placeholderFill: '#C5CDD8',
          shadow: undefined,
          boxShadow: undefined,
        },
      };
    }
    return el;
  });
  const hasAvatar = elements.some((el) => /^(PORTRAIT_IMAGE|AVATAR)$/i.test(String(el.slotId || '')));
  const prevC = prevBySlot.get('QUOTE_CARD');
  const prevM = prevBySlot.get('QUOTE_MARK');
  const deco = [
    {
      id: prevC?.id || newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: { ...g.card, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        fill: prevC?.content?.fill || cardFill,
        borderRadius: 22,
        stroke: QUOTE_CARD_BORDER,
        strokeWidth: 1.5,
        boxShadow: compact ? '0 12px 32px rgba(15, 23, 42, 0.08)' : undefined,
        shadow: compact ? '0 12px 32px rgba(15, 23, 42, 0.08)' : undefined,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: 'QUOTE_CARD',
    },
    {
      id: prevM?.id || newElementId('shp'),
      type: 'graphic',
      layer: 8,
      placement: { ...g.mark, rotation: 0, opacity: 1 },
      content: {
        svg: quoteMarkInlineSvg(),
        colorMode: 'recolorable',
        fill: prevM?.content?.fill || markFill,
        alt: 'Quote',
      },
      role: 'decoration',
      slotId: 'QUOTE_MARK',
    },
    {
      id: newElementId('shp'),
      type: 'shape',
      layer: 11,
      placement: { ...g.avatar, rotation: 0, opacity: 1 },
      content: {
        shape: 'ellipse',
        fill: '#C5CDD8',
        stroke: '#9AA3B2',
        strokeWidth: 2,
      },
      role: 'decoration',
      slotId: 'QUOTE_AVATAR_BG',
    },
  ];
  if (!hasAvatar) {
    deco.push({
      id: newElementId('img'),
      type: 'image',
      layer: 13,
      placement: { ...g.avatar, rotation: 0, opacity: 1 },
      content: { fit: 'cover', borderRadius: 999, placeholderFill: '#C5CDD8' },
      role: 'image',
      slotId: 'PORTRAIT_IMAGE',
    });
  }
  return { ...doc, elements: [...deco, ...elements] };
}

function layoutQuoteAttributionSplit(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const cardFill = paletteColor(palette, 'cardBg', '#FFFFFF');
  const markFill = paletteColor(palette, 'primary', QUOTE_MARK_COLOR);
  const g = quoteAttributionSplitGeom(canvasW, canvasH);
  const decoIds = /^(QUOTE_CARD|QUOTE_MARK|QUOTE_AVATAR_BG)$/i;
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => decoIds.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter(
    (el) =>
      !decoIds.test(String(el.slotId || '')) &&
      !/^(HEADING|BODY|EYEBROW)$/i.test(String(el.slotId || ''))
  );
  const hasName = elements.some((el) => /^NAME(_\d+)?$/i.test(String(el.slotId || '')));
  if (hasName) {
    elements = elements.filter((el) => !/^(ATTRIBUTION|ATTR|AUTHOR|AUTHOR_NAME)$/i.test(String(el.slotId || '')));
  }
  elements = elements.filter((el) => {
    if (el.type !== 'image' && el.type !== 'icon') return true;
    const sid = String(el.slotId || '').toUpperCase();
    return sid === 'PORTRAIT_IMAGE' || sid === 'AVATAR';
  });
  elements = elements.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
      fontStyle: 'normal',
    };
    if (sid === 'QUOTE' || sid === 'STATEMENT') {
      return {
        ...el,
        layer: 10,
        placement: { ...g.quote, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 30,
          fontWeight: 700,
          lineHeight: 1.4,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
          fontStyle: 'italic',
        },
      };
    }
    if (sid === 'NAME' || sid === 'AUTHOR_NAME' || sid === 'ATTRIBUTION') {
      return {
        ...el,
        layer: 12,
        placement: { ...g.name, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 18,
          fontWeight: 700,
          lineHeight: 1.35,
          color: textColor,
          wrap: 'nowrap',
          clipToSlot: false,
        },
      };
    }
    if (sid === 'ROLE' || sid === 'AUTHOR_TITLE') {
      return {
        ...el,
        layer: 12,
        placement: { ...g.role, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 15,
          fontWeight: 400,
          lineHeight: 1.3,
          color: muted,
          wrap: 'wrap',
          clipToSlot: false,
        },
      };
    }
    if (sid === 'AVATAR') {
      return {
        ...el,
        layer: 14,
        placement: { ...g.avatar, rotation: 0, opacity: 1 },
        content: {
          ...(el.content || {}),
          fit: 'cover',
          borderRadius: 999,
          placeholderFill: '#C5CDD8',
        },
      };
    }
    if (sid === 'PORTRAIT_IMAGE') {
      return {
        ...el,
        layer: 13,
        placement: { ...g.image, rotation: 0, opacity: 1 },
        content: {
          ...(el.content || {}),
          fit: 'cover',
          borderRadius: '0 22px 22px 0',
        },
      };
    }
    return el;
  });
  const hasHero = elements.some((el) => String(el.slotId || '').toUpperCase() === 'PORTRAIT_IMAGE');
  const hasAvatar = elements.some((el) => String(el.slotId || '').toUpperCase() === 'AVATAR');
  const prevC = prevBySlot.get('QUOTE_CARD');
  const prevM = prevBySlot.get('QUOTE_MARK');
  const deco = [
    {
      id: prevC?.id || newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: { ...g.card, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        fill: prevC?.content?.fill || cardFill,
        borderRadius: 22,
        stroke: QUOTE_CARD_BORDER,
        strokeWidth: 1.5,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: 'QUOTE_CARD',
    },
    {
      id: prevM?.id || newElementId('shp'),
      type: 'graphic',
      layer: 8,
      placement: { ...g.mark, rotation: 0, opacity: 1 },
      content: {
        svg: quoteMarkInlineSvg(),
        colorMode: 'recolorable',
        fill: prevM?.content?.fill || markFill,
        alt: 'Quote',
      },
      role: 'decoration',
      slotId: 'QUOTE_MARK',
    },
    {
      id: (prevBySlot.get('QUOTE_AVATAR_BG') || {}).id || newElementId('shp'),
      type: 'shape',
      layer: 11,
      placement: { ...g.avatar, rotation: 0, opacity: 1 },
      content: {
        shape: 'ellipse',
        fill: '#C5CDD8',
        stroke: '#9AA3B2',
        strokeWidth: 2,
      },
      role: 'decoration',
      slotId: 'QUOTE_AVATAR_BG',
    },
  ];
  if (!hasHero) {
    deco.push({
      id: newElementId('img'),
      type: 'image',
      layer: 13,
      placement: { ...g.image, rotation: 0, opacity: 1 },
      content: { fit: 'cover', borderRadius: '0 22px 22px 0' },
      role: 'image',
      slotId: 'PORTRAIT_IMAGE',
    });
  }
  if (!hasAvatar) {
    deco.push({
      id: newElementId('img'),
      type: 'image',
      layer: 14,
      placement: { ...g.avatar, rotation: 0, opacity: 1 },
      content: { fit: 'cover', borderRadius: 999, placeholderFill: '#C5CDD8' },
      role: 'image',
      slotId: 'AVATAR',
    });
  }
  return { ...doc, elements: [...deco, ...elements] };
}

const QUOTE_GRID_DECO = /^(QUOTE_CARD_|QUOTE_MARK_|QUOTE_AVATAR_BG_)/i;

function layoutQuoteGrid(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const cardFill = paletteColor(palette, 'cardBg', '#FFFFFF');
  const markFill = paletteColor(palette, 'primary', QUOTE_MARK_COLOR);
  const frame = quoteGridFrame(canvasW, canvasH, QUOTE_GRID_N);
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => QUOTE_GRID_DECO.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !QUOTE_GRID_DECO.test(String(el.slotId || '')));
  const hasName = elements.some((el) => /^NAME_[1-3]$/i.test(String(el.slotId || '')));
  if (hasName) {
    elements = elements.filter((el) => !/^ATTR_[1-3]$/i.test(String(el.slotId || '')));
  }
  const geoms = [0, 1, 2].map((i) => quoteGridCardGeom(i, frame));

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
      fontStyle: 'normal',
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: frame.insetX,
          y: frame.insetY,
          width: canvasW - frame.insetX * 2,
          height: frame.headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.15,
          color: textColor,
        },
      };
    }
    const quoteM = sid.match(/^QUOTE_([1-3])$/i);
    if (quoteM) {
      const i = Number(quoteM[1]) - 1;
      return {
        ...el,
        layer: 10,
        placement: { ...geoms[i].quote, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 22,
          fontWeight: 700,
          lineHeight: 1.45,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
          fontStyle: 'italic',
        },
      };
    }
    const nameM = sid.match(/^(NAME|ATTR)_([1-3])$/i);
    if (nameM) {
      const i = Number(nameM[2]) - 1;
      return {
        ...el,
        layer: 11,
        placement: { ...geoms[i].name, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 16,
          fontWeight: 700,
          lineHeight: 1.2,
          color: textColor,
          wrap: 'wrap',
          clipToSlot: false,
        },
      };
    }
    const roleM = sid.match(/^ROLE_([1-3])$/i);
    if (roleM) {
      const i = Number(roleM[1]) - 1;
      return {
        ...el,
        layer: 11,
        placement: { ...geoms[i].role, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 13,
          fontWeight: 400,
          lineHeight: 1.3,
          color: muted,
          wrap: 'wrap',
          clipToSlot: false,
        },
      };
    }
    const avM = sid.match(/^AVATAR_([1-3])$/i);
    if (avM) {
      const i = Number(avM[1]) - 1;
      return {
        ...el,
        layer: 13,
        placement: { ...geoms[i].avatar, rotation: 0, opacity: 1 },
        content: {
          ...(el.content || {}),
          fit: 'cover',
          borderRadius: 999,
          placeholderFill: '#C5CDD8',
        },
      };
    }
    return el;
  });

  const deco = [];
  const seenAvatar = new Set(
    elements.filter((el) => /^AVATAR_[1-3]$/i.test(String(el.slotId || ''))).map((el) => String(el.slotId).toUpperCase())
  );
  for (let i = 0; i < QUOTE_GRID_N; i += 1) {
    const g = geoms[i];
    const cardId = `QUOTE_CARD_${i + 1}`;
    const markId = `QUOTE_MARK_${i + 1}`;
    const prevC = prevBySlot.get(cardId);
    const prevM = prevBySlot.get(markId);
    deco.push({
      id: prevC?.id || newElementId('shp'),
      type: 'shape',
      layer: 1,
      placement: { ...g.card, rotation: 0, opacity: 1 },
      content: {
        shape: 'rect',
        fill: prevC?.content?.fill || cardFill,
        borderRadius: 18,
        stroke: QUOTE_CARD_BORDER,
        strokeWidth: 1.5,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: cardId,
    });
    deco.push({
      id: prevM?.id || newElementId('shp'),
      type: 'graphic',
      layer: 8,
      placement: { ...g.mark, rotation: 0, opacity: 1 },
      content: {
        svg: quoteMarkInlineSvg(),
        colorMode: 'recolorable',
        fill: prevM?.content?.fill || markFill,
        alt: 'Quote',
      },
      role: 'decoration',
      slotId: markId,
    });
    const avBgId = `QUOTE_AVATAR_BG_${i + 1}`;
    const prevA = prevBySlot.get(avBgId);
    deco.push({
      id: prevA?.id || newElementId('shp'),
      type: 'shape',
      layer: 11,
      placement: { ...g.avatar, rotation: 0, opacity: 1 },
      content: {
        shape: 'ellipse',
        fill: prevA?.content?.fill || '#C5CDD8',
        stroke: '#9AA3B2',
        strokeWidth: 2,
      },
      role: 'decoration',
      slotId: avBgId,
    });
    const avId = `AVATAR_${i + 1}`;
    if (!seenAvatar.has(avId)) {
      deco.push({
        id: newElementId('img'),
        type: 'image',
        layer: 13,
        placement: { ...g.avatar, rotation: 0, opacity: 1 },
        content: { fit: 'cover', borderRadius: 999, placeholderFill: '#C5CDD8' },
        role: 'image',
        slotId: avId,
      });
    }
  }

  return { ...doc, elements: [...deco, ...elements] };
}

function isProcessHorizontalLayout(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  const isProcess = /diagram_process|timeline_process_steps/.test(id);
  return isProcess && (variant === 'horizontal' || id.includes('horizontal'));
}

function isProcessVerticalLayout(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  const isProcess = /diagram_process|timeline_process_steps/.test(id);
  return isProcess && (variant === 'vertical' || id.includes('vertical'));
}

function processStepNumsFromElements(elements) {
  return [
    ...new Set(
      (elements || [])
        .map((el) => String(el.slotId || '').match(/^step_(\d+)_(title|body|label)$/i)?.[1])
        .filter(Boolean)
        .map((n) => Number(n))
    ),
  ].sort((a, b) => a - b);
}

const PROCESS_LAYOUT_DECO =
  /^(AUTO_CARD_BG_|TIMELINE_(NODE|SEG|ARROW|SPINE)|PROCESS_(BADGE|BAR|DIVIDER|CARD|RIBBON|ICON|NODE|CONN|SPINE)_)/i;

function layoutDiagramProcessHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const palette = themeTokens?.palette || {};
  let elements = doc.elements || [];
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const colors = PROCESS_STEP_COLORS;
  const stepNums = processStepNumsFromElements(elements);
  const n = stepNums.length || 4;
  const insetX = 72;
  const headingH = 80;
  const colW = (canvasW - insetX * 2) / n;
  const nodeD = 112;
  const titleH = 44;
  const bodyH = 120;
  const gapNodeToTitle = 36;
  const gapTitleToBody = 12;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const headingY = 56;
  const diagramH = nodeD + gapNodeToTitle + titleH + gapTitleToBody + bodyH;
  const belowHeading = headingY + headingH;
  const flowY = Math.max(belowHeading + 24, belowHeading + Math.round((canvasH - belowHeading - diagramH) / 2));
  const titleY = flowY + nodeD + gapNodeToTitle;
  const bodyY = titleY + titleH + gapTitleToBody;
  const arrowH = 28;
  const padX = 16;

  const prevBySlot = new Map(
    (elements || [])
      .filter((el) => /^PROCESS_(NODE|CONN)_/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  const stripped = elements.filter((el) => !PROCESS_LAYOUT_DECO.test(String(el.slotId || '')));
  const seenLabel = new Set(
    stripped.filter((el) => /^step_\d+_label$/i.test(String(el.slotId || ''))).map((el) => String(el.slotId).toLowerCase())
  );

  const colX = (idx) => insetX + idx * colW;
  const nodeX = (idx) => Math.round(colX(idx) + (colW - nodeD) / 2);

  elements = stripped.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: insetX,
          y: headingY,
          width: canvasW - insetX * 2,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.15,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    const labelM = sid.match(/^step_(\d+)_label$/i);
    const titleM = sid.match(/^step_(\d+)_title$/i);
    const bodyM = sid.match(/^step_(\d+)_body$/i);
    const num = Number((labelM || titleM || bodyM)?.[1]);
    const idx = stepNums.indexOf(num);
    if (idx < 0) return el;
    const color = colors[idx % colors.length];
    if (labelM) {
      const pad = String(idx + 1).padStart(2, '0');
      const raw = String(el.content?.text || '').trim();
      const text = /^\d+$/.test(raw.replace(/^#/, '')) || !raw || /process/i.test(raw) ? pad : raw;
      return {
        ...el,
        layer: 12,
        placement: {
          x: nodeX(idx),
          y: Math.round(flowY),
          width: nodeD,
          height: nodeD,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          text,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 32,
          fontWeight: 800,
          lineHeight: 1,
          color: '#FFFFFF',
          wrap: 'nowrap',
          clipToSlot: false,
        },
      };
    }
    if (titleM) {
      const pad = String(idx + 1).padStart(2, '0');
      const raw = String(el.content?.text || '').trim();
      const text = !raw || /text here|double-click/i.test(raw) ? `STEP #${pad}` : raw;
      return {
        ...el,
        layer: 10,
        placement: {
          x: Math.round(colX(idx) + padX),
          y: Math.round(titleY),
          width: Math.round(colW - padX * 2),
          height: titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          text,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 22,
          fontWeight: 800,
          lineHeight: 1.2,
          color,
          wrap: 'nowrap',
          clipToSlot: false,
        },
      };
    }
    return {
      ...el,
      layer: 10,
      placement: {
        x: Math.round(colX(idx) + padX),
        y: Math.round(bodyY),
        width: Math.round(colW - padX * 2),
        height: Math.round(bodyH),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: 'center',
        verticalAlign: 'flex-start',
        fontSize: 15,
        fontWeight: 400,
        lineHeight: 1.5,
        color: muted,
        wrap: 'wrap',
        clipToSlot: false,
      },
    };
  });

  const chrome = [];
  for (let i = 0; i < n; i += 1) {
    const color = colors[i % colors.length];
    const nodeId = `PROCESS_NODE_${i + 1}`;
    const prevN = prevBySlot.get(nodeId);
    chrome.push({
      id: prevN?.id || newElementId('shp-pnode'),
      type: 'shape',
      layer: 8,
      placement: {
        x: nodeX(i),
        y: Math.round(flowY),
        width: nodeD,
        height: nodeD,
        rotation: 0,
        opacity: 1,
      },
      content: { shape: 'ellipse', fill: prevN?.content?.fill || color, layoutSurface: true },
      role: 'decoration',
      slotId: nodeId,
    });
    if (i < n - 1) {
      const ax = nodeX(i) + nodeD + 12;
      const aw = Math.max(24, nodeX(i + 1) - ax - 12);
      const connId = `PROCESS_CONN_${i + 1}`;
      const prevC = prevBySlot.get(connId);
      chrome.push({
        id: prevC?.id || newElementId('shp-pconn'),
        type: 'graphic',
        layer: 6,
        placement: {
          x: Math.round(ax),
          y: Math.round(flowY + (nodeD - arrowH) / 2),
          width: Math.round(aw),
          height: arrowH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          svg: processFlowArrowInlineSvg(),
          colorMode: 'recolorable',
          fill: prevC?.content?.fill || color,
          alt: 'Next step',
        },
        role: 'decoration',
        slotId: connId,
      });
    }
    const labelSlot = `step_${stepNums[i] || i + 1}_label`;
    if (!seenLabel.has(labelSlot.toLowerCase())) {
      chrome.push({
        id: newElementId('txt-plabel'),
        type: 'text',
        layer: 12,
        placement: {
          x: nodeX(i),
          y: Math.round(flowY),
          width: nodeD,
          height: nodeD,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: String(i + 1).padStart(2, '0'),
          align: 'center',
          verticalAlign: 'center',
          fontSize: 32,
          fontWeight: 800,
          lineHeight: 1,
          color: '#FFFFFF',
          letterSpacing: '0',
          padding: 0,
          wrap: 'nowrap',
          clipToSlot: false,
        },
        role: 'caption',
        slotId: labelSlot,
      });
    }
  }

  return { ...doc, elements: [...chrome, ...elements] };
}

function layoutDiagramProcessVertical(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  let elements = doc.elements || [];
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const colors = PROCESS_STEP_COLORS;
  const stepNums = processStepNumsFromElements(elements);
  const n = stepNums.length || 4;
  const headingY = 56;
  const headingH = 80;
  const leftX = 96;
  const nodeD = 96;
  const spineW = 8;
  const rowGap = 24;
  const contentTop = headingY + headingH + 40;
  const usableH = canvasH - contentTop - 48;
  const rowH = (usableH - rowGap * (n - 1)) / n;
  const textX = leftX + nodeD + 40;
  const textW = canvasW - textX - 80;
  const titleH = 48;

  const prevBySlot = new Map(
    (elements || [])
      .filter((el) => /^PROCESS_(NODE|SPINE)_/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  const stripped = elements.filter((el) => !PROCESS_LAYOUT_DECO.test(String(el.slotId || '')));
  const seenLabel = new Set(
    stripped.filter((el) => /^step_\d+_label$/i.test(String(el.slotId || ''))).map((el) => String(el.slotId).toLowerCase())
  );

  const rowY = (idx) => contentTop + idx * (rowH + rowGap);
  const nodeY = (idx) => Math.round(rowY(idx) + (rowH - nodeD) / 2);

  elements = stripped.map((el) => {
    const sid = String(el.slotId || '');
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    };
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: 72,
          y: headingY,
          width: canvasW - 144,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.15,
          color: textColor,
          clipToSlot: false,
        },
      };
    }
    const labelM = sid.match(/^step_(\d+)_label$/i);
    const titleM = sid.match(/^step_(\d+)_title$/i);
    const bodyM = sid.match(/^step_(\d+)_body$/i);
    const num = Number((labelM || titleM || bodyM)?.[1]);
    const idx = stepNums.indexOf(num);
    if (idx < 0) return el;
    const color = colors[idx % colors.length];
    if (labelM) {
      const pad = String(idx + 1).padStart(2, '0');
      const raw = String(el.content?.text || '').trim();
      const text = /^\d+$/.test(raw.replace(/^#/, '')) || !raw || /process/i.test(raw) ? pad : raw;
      return {
        ...el,
        layer: 12,
        placement: {
          x: leftX,
          y: nodeY(idx),
          width: nodeD,
          height: nodeD,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          text,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 28,
          fontWeight: 800,
          lineHeight: 1,
          color: '#FFFFFF',
          wrap: 'nowrap',
          clipToSlot: false,
        },
      };
    }
    if (titleM) {
      const pad = String(idx + 1).padStart(2, '0');
      const raw = String(el.content?.text || '').trim();
      const text = !raw || /text here|double-click/i.test(raw) ? `STEP #${pad}` : raw;
      return {
        ...el,
        layer: 10,
        placement: {
          x: Math.round(textX),
          y: Math.round(rowY(idx) + 16),
          width: Math.round(textW),
          height: titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          text,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 24,
          fontWeight: 800,
          lineHeight: 1.2,
          color,
          wrap: 'nowrap',
          clipToSlot: false,
        },
      };
    }
    return {
      ...el,
      layer: 10,
      placement: {
        x: Math.round(textX),
        y: Math.round(rowY(idx) + 16 + titleH + 8),
        width: Math.round(textW),
        height: Math.max(48, Math.round(rowH - 16 - titleH - 24)),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: 'left',
        verticalAlign: 'flex-start',
        fontSize: 16,
        fontWeight: 400,
        lineHeight: 1.5,
        color: muted,
        wrap: 'wrap',
        clipToSlot: false,
      },
    };
  });

  const chrome = [];
  const firstCY = nodeY(0) + nodeD / 2;
  const lastCY = nodeY(n - 1) + nodeD / 2;
  const prevSpine = prevBySlot.get('PROCESS_SPINE_1');
  chrome.push({
    id: prevSpine?.id || newElementId('shp-pspine'),
    type: 'shape',
    layer: 1,
    placement: {
      x: Math.round(leftX + nodeD / 2 - spineW / 2),
      y: Math.round(firstCY),
      width: spineW,
      height: Math.max(8, Math.round(lastCY - firstCY)),
      rotation: 0,
      opacity: 1,
    },
    content: {
      shape: 'rect',
      fill: prevSpine?.content?.fill || '#CBD5E1',
      borderRadius: 4,
      layoutSurface: true,
    },
    role: 'decoration',
    slotId: 'PROCESS_SPINE_1',
  });
  for (let i = 0; i < n; i += 1) {
    const color = colors[i % colors.length];
    const nodeId = `PROCESS_NODE_${i + 1}`;
    const prevN = prevBySlot.get(nodeId);
    chrome.push({
      id: prevN?.id || newElementId('shp-pnode'),
      type: 'shape',
      layer: 8,
      placement: {
        x: leftX,
        y: nodeY(i),
        width: nodeD,
        height: nodeD,
        rotation: 0,
        opacity: 1,
      },
      content: { shape: 'ellipse', fill: prevN?.content?.fill || color, layoutSurface: true },
      role: 'decoration',
      slotId: nodeId,
    });
    const labelSlot = `step_${stepNums[i] || i + 1}_label`;
    if (!seenLabel.has(labelSlot.toLowerCase())) {
      chrome.push({
        id: newElementId('txt-plabel'),
        type: 'text',
        layer: 12,
        placement: {
          x: leftX,
          y: nodeY(i),
          width: nodeD,
          height: nodeD,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: String(i + 1).padStart(2, '0'),
          align: 'center',
          verticalAlign: 'center',
          fontSize: 28,
          fontWeight: 800,
          lineHeight: 1,
          color: '#FFFFFF',
          letterSpacing: '0',
          padding: 0,
          wrap: 'nowrap',
          clipToSlot: false,
        },
        role: 'caption',
        slotId: labelSlot,
      });
    }
  }

  return { ...doc, elements: [...chrome, ...elements] };
}

/**
 * Equal 4-column cards: gray panel, arrow ribbon + number, STEP title, body, icon.
 */
function layoutDiagramProcessSteps(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  if (isProcessHorizontalLayout(layoutSchema)) return layoutDiagramProcessHorizontal(doc, layoutSchema, themeTokens, canvas);
  if (isProcessVerticalLayout(layoutSchema)) return layoutDiagramProcessVertical(doc, layoutSchema, themeTokens, canvas);
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  let elements = doc.elements || [];
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const cardFill = '#F2F2F2';
  const colors = PROCESS_STEP_COLORS;

  const stepNums = [
    ...new Set(
      elements
        .map((el) => String(el.slotId || '').match(/^step_(\d+)_(title|body|label)$/i)?.[1])
        .filter(Boolean)
        .map((n) => Number(n))
    ),
  ].sort((a, b) => a - b)
  const n = stepNums.length || 4
  const insetX = 48
  const insetY = 56
  const headingH = 72
  const gap = 28
  const usableW = canvasW - insetX * 2
  const cardW = (usableW - gap * (n - 1)) / n
  const cardTop = insetY + headingH + 56
  const cardH = Math.min(680, canvasH - cardTop - 56)
  const padX = 28
  const ribbonInsetR = 28
  const ribbonTopPad = 32
  const ribbonH = 148
  const ribbonY = cardTop + ribbonTopPad
  const titleH = 44
  const titleY = ribbonY + Math.round(ribbonH * (124 / 148)) + 36
  const icon = 80
  const iconY = cardTop + cardH - 40 - icon
  const bodyY = titleY + titleH + 28
  const bodyH = Math.max(64, iconY - bodyY - 20)

  const PROCESS_DECO =
    /^(AUTO_CARD_BG_|TIMELINE_(NODE|SEG|ARROW|SPINE)|PROCESS_(BADGE|BAR|DIVIDER|CARD|RIBBON|ICON|NODE|CONN|SPINE)_)/i
  const prevBySlot = new Map(
    (elements || [])
      .filter((el) => /^PROCESS_(CARD|RIBBON|ICON)_/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const stripped = elements.filter((el) => !PROCESS_DECO.test(String(el.slotId || '')))
  const seenLabel = new Set(
    stripped.filter((el) => /^step_\d+_label$/i.test(String(el.slotId || ''))).map((el) => String(el.slotId).toLowerCase())
  )

  elements = stripped.map((el) => {
    const sid = String(el.slotId || '')
    const base = {
      ...(el.content || {}),
      letterSpacing: '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    }
    if (sid.toUpperCase() === 'HEADING') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: insetX,
          y: insetY,
          width: canvasW - insetX * 2,
          height: headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.15,
          color: textColor,
          clipToSlot: false,
        },
      }
    }
    const labelM = sid.match(/^step_(\d+)_label$/i)
    const titleM = sid.match(/^step_(\d+)_title$/i)
    const bodyM = sid.match(/^step_(\d+)_body$/i)
    const num = Number((labelM || titleM || bodyM)?.[1])
    const idx = stepNums.indexOf(num)
    if (idx < 0) return el
    const cardX = insetX + idx * (cardW + gap)
    const color = colors[idx % colors.length]
    const ribbonW = cardW - ribbonInsetR
    const ribbonX = cardX
    if (labelM) {
      const box = processRibbonLabelBox(ribbonX, ribbonY, ribbonW, ribbonH)
      const pad = String(idx + 1).padStart(2, '0')
      const raw = String(el.content?.text || '').trim()
      const text = /^\d+$/.test(raw.replace(/^#/, '')) || !raw || /process/i.test(raw) ? pad : raw
      return {
        ...el,
        layer: 12,
        placement: { ...box, rotation: 0, opacity: 1 },
        content: {
          ...base,
          text,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1,
          color: '#FFFFFF',
          wrap: 'nowrap',
          clipToSlot: false,
        },
      }
    }
    if (titleM) {
      const pad = String(idx + 1).padStart(2, '0')
      const raw = String(el.content?.text || '').trim()
      const text = !raw || /text here|double-click/i.test(raw) ? `STEP #${pad}` : raw
      return {
        ...el,
        layer: 10,
        placement: {
          x: Math.round(cardX + padX),
          y: Math.round(titleY),
          width: Math.round(cardW - padX * 2),
          height: titleH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...base,
          text,
          align: 'left',
          verticalAlign: 'center',
          fontSize: 22,
          fontWeight: 800,
          lineHeight: 1.2,
          letterSpacing: '0.06em',
          color,
          wrap: 'nowrap',
          clipToSlot: false,
        },
      }
    }
    return {
      ...el,
      layer: 10,
      placement: {
        x: Math.round(cardX + padX),
        y: Math.round(bodyY),
        width: Math.round(cardW - padX * 2),
        height: Math.round(bodyH),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...base,
        align: 'left',
        verticalAlign: 'flex-start',
        fontSize: 15,
        fontWeight: 400,
        lineHeight: 1.5,
        color: muted,
        wrap: 'wrap',
        clipToSlot: false,
      },
    }
  })

  const chrome = []
  for (let i = 0; i < n; i += 1) {
    const cardX = insetX + i * (cardW + gap)
    const color = colors[i % colors.length]
    const cardId = `PROCESS_CARD_${i + 1}`
    const ribbonId = `PROCESS_RIBBON_${i + 1}`
    const iconId = `PROCESS_ICON_${i + 1}`
    const prevC = prevBySlot.get(cardId)
    const prevR = prevBySlot.get(ribbonId)
    const prevI = prevBySlot.get(iconId)
    chrome.push({
      id: prevC?.id || newElementId('shp-pcard'),
      type: 'shape',
      layer: 1,
      placement: {
        x: Math.round(cardX),
        y: Math.round(cardTop),
        width: Math.round(cardW),
        height: Math.round(cardH),
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: prevC?.content?.fill || cardFill,
        borderRadius: 16,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: cardId,
    })
    chrome.push({
      id: prevR?.id || newElementId('shp-prib'),
      type: 'graphic',
      layer: 8,
      placement: {
        x: Math.round(cardX),
        y: Math.round(ribbonY),
        width: Math.round(cardW - ribbonInsetR),
        height: ribbonH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: processRibbonInlineSvg(),
        colorMode: 'recolorable',
        fill: color,
        alt: `Step ${i + 1}`,
      },
      role: 'decoration',
      slotId: ribbonId,
    })
    chrome.push({
      id: prevI?.id || newElementId('shp-pico'),
      type: 'graphic',
      layer: 8,
      placement: {
        x: Math.round(cardX + (cardW - icon) / 2),
        y: Math.round(iconY),
        width: icon,
        height: icon,
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: processIconInlineSvg(i),
        colorMode: 'recolorable',
        fill: color,
        alt: 'Step icon',
      },
      role: 'decoration',
      slotId: iconId,
    })
    const labelSlot = `step_${stepNums[i] || i + 1}_label`
    if (!seenLabel.has(labelSlot.toLowerCase())) {
      const box = processRibbonLabelBox(cardX, ribbonY, cardW - ribbonInsetR, ribbonH)
      chrome.push({
        id: newElementId('txt-plabel'),
        type: 'text',
        layer: 12,
        placement: { ...box, rotation: 0, opacity: 1 },
        content: {
          text: String(i + 1).padStart(2, '0'),
          align: 'left',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1,
          color: '#FFFFFF',
          letterSpacing: '0',
          padding: 0,
          wrap: 'nowrap',
          clipToSlot: false,
        },
        role: 'caption',
        slotId: labelSlot,
      })
    }
  }

  return { ...doc, elements: [...chrome, ...elements] }
}

function findProcessAnchorElements(elements) {
  const anchors = elements.filter((el) => {
    if (el.type !== 'text' && el.type !== 'textbox') return false;
    const sid = String(el.slotId || '');
    return (
      /^milestone_\d+_label$/i.test(sid) ||
      /^milestone_\d+$/i.test(sid) ||
      /^step_\d+_title$/i.test(sid) ||
      /^STEP_\d+_TITLE$/i.test(sid)
    );
  });
  return anchors.sort((a, b) => {
    const ay = a.placement?.y ?? 0;
    const by = b.placement?.y ?? 0;
    const ax = a.placement?.x ?? 0;
    const bx = b.placement?.x ?? 0;
    // Prefer left-to-right; if clearly stacked vertically, top-to-bottom
    if (Math.abs(ay - by) > 80) return ay - by;
    return ax - bx;
  });
}

function applyTimelineConnectorShapes(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc || !layoutSchema?.slots?.length) return doc;
  const layoutId = String(layoutSchema.layout_id || '').toLowerCase();
  if (isProcessLinnerLayout(layoutId)) return doc;
  if (isProcessLinnerHortiLayout(layoutId)) return doc;
  if (!isProcessFlowLayout(layoutId)) return doc;

  // Idempotent — skip if flow chrome already injected
  if ((doc.elements || []).some((el) => /^TIMELINE_(NODE|SEG|ARROW|SPINE)_/i.test(String(el.slotId || '')) || String(el.slotId || '') === 'TIMELINE_SPINE')) {
    return doc;
  }

  // Skip if STEP circles already compiled (process_linear) — still add chevrons between them
  let elements = [...(doc.elements || [])];
  const palette = themeTokens?.palette || {};
  const accent = paletteColor(palette, 'accent', paletteColor(palette, 'primary', '#6366F1'));
  const muted = paletteColor(palette, 'muted', '#94A3B8');
  const textColor = paletteColor(palette, 'text', '#0F172A');
  const cardFill = paletteColor(palette, 'cardBg', '#F1F5F9');
  const canvasW = canvas.width || doc.canvas?.width || 1920;
  const canvasH = canvas.height || doc.canvas?.height || 1080;
  const { family, variant } = resolveTimelineMeta(layoutSchema);

  const imageEls = elements.filter(
    (el) => el.type === 'image' && /^IMAGE_\d+$/i.test(String(el.slotId || ''))
  );
  const labelEls = findProcessAnchorElements(elements);
  if (labelEls.length < 2) return doc;

  const isVertical = /timeline_vertical/.test(layoutId)
    || (family === 'process' && variant === 'vertical');
  const useChevrons = !['path', 'lanes', 'image_right', 'image_top'].includes(variant);
  const useCardChrome = variant === 'cards'
    || (family === 'milestones' && variant === 'default');
  const NODE = 48;
  const NUM_H = 22;

  const centers = labelEls.map((el, i) => {
    const p = el.placement || {};
    return {
      x: (p.x ?? 0) + (p.width ?? 0) / 2,
      labelTop: p.y ?? 0,
      labelBottom: (p.y ?? 0) + (p.height ?? 0),
      index: i + 1,
      slotId: el.slotId,
    };
  });

  let axisY;
  if ((/timeline_milestones_image/.test(layoutId) || family === 'milestones_image') && imageEls.length) {
    axisY =
      Math.max(...imageEls.map((el) => (el.placement?.y ?? 0) + (el.placement?.height ?? 0))) + 28;
  } else if (variant === 'image_top') {
    axisY = Math.min(...centers.map((c) => c.labelTop)) - NODE - NUM_H - 12;
    axisY = Math.max(120, axisY);
  } else if (isVertical) {
    axisY = null;
  } else {
    // Sit above card titles with room for node + number
    axisY = Math.min(...centers.map((c) => c.labelTop)) - NODE - NUM_H - 12;
    axisY = Math.max(72, axisY);
  }

  // Avoid duplicate nodes if STEP_*_CIRCLE already present
  const hasStepCircles = elements.some((el) => /^STEP_\d+_CIRCLE$/i.test(String(el.slotId || '')));

  if (family === 'roadmap' && variant === 'lanes') {
    const laneCount = 3;
    const laneH = Math.round((canvasH * 0.42) / laneCount);
    const laneY0 = Math.round(canvasH * 0.22);
    for (let lane = 0; lane < laneCount; lane += 1) {
      elements.unshift({
        id: newElementId('shp'),
        type: 'shape',
        layer: 0,
        placement: {
          x: 64,
          y: laneY0 + lane * (laneH + 8),
          width: canvasW - 128,
          height: laneH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          shape: 'rect',
          fill: { type: 'solid', color: cardFill, colorRole: 'cardBg' },
          borderRadius: 12,
          layoutSurface: true,
        },
        role: 'decoration',
        slotId: `TIMELINE_LANE_${lane + 1}`,
      });
    }
    return { ...doc, elements };
  }

  if (isVertical) {
    const spineX = Math.min(...centers.map((c) => c.x)) - 36;
    const y1 = centers[0].labelTop + 8;
    const y2 = centers[centers.length - 1].labelTop + 8;
    elements.unshift({
      id: newElementId('shp'),
      type: 'shape',
      layer: 0,
      placement: {
        x: Math.round(spineX - 1.5),
        y: Math.round(y1),
        width: 3,
        height: Math.max(40, y2 - y1),
        rotation: 0,
        opacity: 0.95,
      },
      content: {
        shape: 'rect',
        fill: { type: 'solid', color: muted, colorRole: 'muted' },
        borderRadius: 2,
        layoutSurface: true,
      },
      role: 'decoration',
      slotId: 'TIMELINE_SPINE',
    });

    centers.forEach((c) => {
      const cy = c.labelTop + 10;
      if (useCardChrome || (family === 'vertical' && variant === 'cards')) {
        elements.unshift({
          id: newElementId('shp'),
          type: 'shape',
          layer: 1,
          placement: {
            x: Math.round(spineX + 20),
            y: Math.round(cy - 28),
            width: Math.round(canvasW * 0.28),
            height: 56,
            rotation: 0,
            opacity: 1,
          },
          content: {
            shape: 'rect',
            fill: { type: 'solid', color: cardFill, colorRole: 'cardBg' },
            borderRadius: 10,
            layoutSurface: true,
          },
          role: 'decoration',
          slotId: `TIMELINE_CARD_${c.index}`,
        });
      }
      elements.unshift({
        id: newElementId('shp'),
        type: 'graphic',
        layer: 3,
        placement: {
          x: Math.round(spineX - NODE / 2),
          y: Math.round(cy - NODE / 2),
          width: NODE,
          height: NODE,
          rotation: 0,
          opacity: 1,
        },
        content: timelineGraphicContent(timelineNodeInlineSvg(), { type: 'solid', color: accent, colorRole: 'accent' }, `Timeline node ${c.index}`),
        role: 'decoration',
        slotId: `TIMELINE_NODE_${c.index}`,
      });
      elements.unshift({
        id: newElementId('txt'),
        type: 'text',
        layer: 4,
        placement: {
          x: Math.round(spineX - NODE / 2),
          y: Math.round(cy + NODE / 2 + 2),
          width: NODE,
          height: NUM_H,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: String(c.index),
          align: 'center',
          fontSize: 14,
          fontWeight: 700,
          colorRole: 'text',
          color: textColor,
        },
        role: 'caption',
        slotId: `TIMELINE_NODE_NUM_${c.index}`,
      });
    });

    return { ...doc, elements };
  }

  // Horizontal flowchart: thin segments + chevrons between nodes
  if (!hasStepCircles) {
    centers.forEach((c) => {
      if (useCardChrome) {
        const cardW = Math.round((canvasW - 128) / Math.max(centers.length, 1) * 0.82);
        elements.unshift({
          id: newElementId('shp'),
          type: 'shape',
          layer: 1,
          placement: {
            x: Math.round(c.x - cardW / 2),
            y: Math.round(axisY + NODE / 2 + 8),
            width: cardW,
            height: 88,
            rotation: 0,
            opacity: 1,
          },
          content: {
            shape: 'rect',
            fill: { type: 'solid', color: cardFill, colorRole: 'cardBg' },
            borderRadius: 10,
            layoutSurface: true,
          },
          role: 'decoration',
          slotId: `TIMELINE_CARD_${c.index}`,
        });
      }
      elements.unshift({
        id: newElementId('shp'),
        type: 'graphic',
        layer: 3,
        placement: {
          x: Math.round(c.x - NODE / 2),
          y: Math.round(axisY - NODE / 2),
          width: NODE,
          height: NODE,
          rotation: 0,
          opacity: 1,
        },
        content: timelineGraphicContent(timelineNodeInlineSvg(), { type: 'solid', color: accent, colorRole: 'accent' }, `Timeline node ${c.index}`),
        role: 'decoration',
        slotId: `TIMELINE_NODE_${c.index}`,
      });
      elements.unshift({
        id: newElementId('txt'),
        type: 'text',
        layer: 4,
        placement: {
          x: Math.round(c.x - NODE / 2),
          y: Math.round(axisY + NODE / 2 + 2),
          width: NODE,
          height: NUM_H,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: String(c.index),
          align: 'center',
          fontSize: 14,
          fontWeight: 700,
          colorRole: 'text',
          color: textColor,
        },
        role: 'caption',
        slotId: `TIMELINE_NODE_NUM_${c.index}`,
      });
    });
  }

  // Segment + chevron between consecutive centers
  for (let i = 0; i < centers.length - 1; i += 1) {
    const a = centers[i];
    const b = centers[i + 1];
    const nodeR = hasStepCircles ? 32 : NODE / 2;
    const x1 = a.x + nodeR + 4;
    const x2 = b.x - nodeR - 4;
    const segW = Math.max(8, x2 - x1);
    const lineY = hasStepCircles
      ? (() => {
          const circle = elements.find(
            (el) => String(el.slotId || '').toUpperCase() === `STEP_${i + 1}_CIRCLE`
          );
          if (circle?.placement) {
            return (circle.placement.y ?? 0) + (circle.placement.height ?? 0) / 2;
          }
          return axisY;
        })()
      : axisY;

    if (variant !== 'path') {
      elements.unshift({
        id: newElementId('shp'),
        type: 'graphic',
        layer: 1,
        placement: {
          x: Math.round(x1),
          y: Math.round(lineY - 1.5),
          width: Math.round(segW),
          height: 3,
          rotation: 0,
          opacity: 0.95,
        },
        content: timelineGraphicContent(timelineSpineSegmentInlineSvg(), { type: 'solid', color: muted, colorRole: 'muted' }, 'Timeline segment'),
        role: 'decoration',
        slotId: `TIMELINE_SEG_${i + 1}`,
      });
    }

    if (!useChevrons) continue;

    const midX = (a.x + b.x) / 2;
    const chevronSize = 18;
    elements.unshift({
      id: newElementId('shp'),
      type: 'graphic',
      layer: 2,
      placement: {
        x: Math.round(midX - chevronSize / 2),
        y: Math.round(lineY - chevronSize / 2),
        width: chevronSize,
        height: chevronSize,
        rotation: 0,
        opacity: 1,
      },
      content: timelineGraphicContent(timelineChevronInlineSvg(), { type: 'solid', color: accent, colorRole: 'accent' }, 'Timeline arrow'),
      role: 'decoration',
      slotId: `TIMELINE_ARROW_${i + 1}`,
    });
  }

  // Soft clamp axis nodes inside canvas
  for (const el of elements) {
    if (!el.placement) continue;
    if (!/^TIMELINE_NODE/i.test(String(el.slotId || ''))) continue;
    el.placement.x = Math.max(56, Math.min(el.placement.x, canvasW - (el.placement.width || NODE) - 56));
    el.placement.y = Math.max(8, Math.min(el.placement.y, canvasH - (el.placement.height || NODE) - 8));
  }

  return { ...doc, elements };
}

function docHasFullBleedBackground(doc, layoutSchema) {
  // Only treat as full-bleed overlay when a real image URL is present.
  if (layoutRequiresOverlayScrim(layoutSchema) && docHasLoadedOverlayImage(doc)) return true;
  const canvas = doc?.canvas || {};
  const cw = canvas.width || CANVAS_WIDTH;
  const ch = canvas.height || CANVAS_HEIGHT;
  const minArea = cw * ch * 0.85;
  const elements = Array.isArray(doc?.elements) ? doc.elements : [];
  return elements.some((el) => {
    if (el.type !== 'image') return false;
    if (!el.content?.url) return false;
    const role = String(el.role || '').toLowerCase();
    const slotId = String(el.slotId || '').toUpperCase();
    if (slotId === 'BACKGROUND_IMAGE' || role === 'background' || el.content?.useAsBackground) {
      return true;
    }
    const p = el.placement || {};
    return (p.width || 0) * (p.height || 0) >= minArea;
  });
}

function layoutAgendaInfographic(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const canvasW = canvas.width || doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = canvas.height || doc.canvas?.height || CANVAS_HEIGHT;
  const palette = themeTokens?.palette || {};
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const accent = paletteColor(palette, 'accent', paletteColor(palette, 'primary', '#6366F1'));
  const soft = paletteColor(palette, 'cardBg', 'color-mix(in srgb, #6366f1 12%, #ffffff)');

  const { family, variant } = resolveAgendaMeta(layoutSchema);
  const layoutId = layoutSchema?.layout_id || layoutSchema?.id || layoutSchema?.layoutId || '';
  const isColouredThreeCol = isAgendaThreeColumnColouredLayout(layoutId, family, variant);
  const isThreeCards = isAgendaThreeCardsLayout(layoutId, family, variant);
  const isThreeCardsHero = isAgendaThreeCardsHeroLayout(layoutId, family, variant);
  const isHeroCards = isAgendaHeroCardsLayout(layoutId, family, variant);
  const isNumberedBlocks = isAgendaNumberedBlocksLayout(layoutId, family, variant);
  const isNumberedTimeline = isAgendaNumberedTimelineLayout(layoutId, family, variant);
  const isMinimalQuiet = isAgendaMinimalQuietLayout(layoutId, family, variant);
  const isEditorial = isAgendaEditorialLayout(layoutId, family, variant);
  const isAgendaCards = isAgendaCardsLayout(layoutId, family, variant);
  const isTwoColRibbon = isAgendaTwoColumnRibbonLayout(layoutId, family, variant);
  const isRibbonCards = isThreeCards || isThreeCardsHero;
  const stacked = isColouredThreeCol || isRibbonCards || isHeroCards || isNumberedBlocks || isNumberedTimeline;
  const itemCount = layoutSchema?.preview?.agendaItems?.length
    || layoutSchema?.preview?.milestones?.length
    || (doc.elements || []).filter((el) => /^ITEM_\d+$/i.test(String(el.slotId || ''))).length
    || 4;

  const frame = isThreeCardsHero
    ? agendaThreeCardsGraphicFrame(canvasW, canvasH, { hero: true })
    : isHeroCards
      ? agendaHeroCardsGraphicFrame(canvasW, canvasH)
      : isThreeCards
        ? agendaThreeCardsGraphicFrame(canvasW, canvasH)
        : isNumberedBlocks
          ? agendaNumberedBlocksGraphicFrame(canvasW, canvasH)
          : isNumberedTimeline
            ? agendaNumberedTimelineGraphicFrame(canvasW, canvasH)
            : isMinimalQuiet
            ? agendaMinimalQuietGraphicFrame(canvasW, canvasH)
            : isEditorial
            ? agendaEditorialGraphicFrame(canvasW, canvasH)
            : isAgendaCards
            ? agendaCardsGraphicFrame(canvasW, canvasH)
            : isTwoColRibbon
            ? agendaTwoColumnRibbonGraphicFrame(canvasW, canvasH)
            : isColouredThreeCol
            ? agendaThreeColumnGraphicFrame(canvasW, canvasH)
            : agendaGraphicFrame(canvasW, canvasH);
  const { graphicX, graphicY, graphicW, graphicH, headingY, headingH, heroH } = frame;
  const overlay = agendaOverlayPlacements(graphicX, graphicY, graphicW, graphicH, family, variant, { itemCount });
  const columnTextColor = textColor;

  const CHROME_RE = /^AGENDA_(INFOGRAPHIC_CHROME|SPINE|PATH|SPLIT_LINE|TIMELINE|CURVE|TITLE_BLOCK|VISUAL_BLOCK|ZONE_|PANEL_|CARD_|ICON_|BADGE_|DIVIDER_|ARROW_|NODE_|COL_BLOCK_|COL_BAND_|COL_ICON_|COL_NUM_|COL_RULE|COL_CHROME_|NUM_CHROME_|NUM_TL_|MIN_|ED_|CRD_|TC_)/i;
  const prevBySlot = new Map(
    (doc.elements || [])
      .filter((el) => CHROME_RE.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  let elements = (doc.elements || []).filter((el) => !CHROME_RE.test(String(el.slotId || '')));
  if (isNumberedTimeline) {
    elements = elements.filter((el) => isAgendaNumberedTimelineTextSlot(el.slotId));
  } else if (isNumberedBlocks) {
    elements = elements.filter((el) => isAgendaNumberedBlocksTextSlot(el.slotId));
  } else if (isMinimalQuiet) {
    elements = elements.filter((el) => isAgendaMinimalQuietTextSlot(el.slotId));
  } else if (isEditorial) {
    elements = elements.filter((el) => isAgendaEditorialTextSlot(el.slotId));
  } else if (isAgendaCards) {
    elements = elements.filter((el) => isAgendaCardsTextSlot(el.slotId));
  } else if (isTwoColRibbon) {
    elements = elements.filter((el) => isAgendaTwoColumnRibbonTextSlot(el.slotId));
  } else if (stacked) {
    elements = elements.filter((el) => isAgendaThreeColumnTextSlot(el.slotId) || /^HERO_IMAGE$/i.test(String(el.slotId || '')));
  }

  const textBase = (el) => ({
    ...(el.content || {}),
    letterSpacing: '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  });

  elements = elements.map((el) => {
    const sid = String(el.slotId || '');
    const base = textBase(el);
    if (sid.toUpperCase() === 'HEADING') {
      const h = isRibbonCards || isHeroCards || isNumberedBlocks || isNumberedTimeline || isMinimalQuiet || isEditorial || isAgendaCards || isTwoColRibbon
        ? (overlay.heading || { x: Math.round(canvasW * 0.06), y: headingY, width: Math.round(canvasW * 0.88), height: headingH })
        : stacked
        ? { x: Math.round(canvasW * 0.06), y: headingY, width: Math.round(canvasW * 0.88), height: headingH }
        : (overlay.heading || { x: 72, y: headingY, width: canvasW - 144, height: headingH });
      return {
        ...el,
        placement: { ...h, rotation: 0, opacity: 1 },
        content: {
          ...base,
          align: isTwoColRibbon || isEditorial ? 'left' : stacked ? 'center' : 'left',
          verticalAlign: 'center',
          fontSize: isTwoColRibbon ? 28 : isEditorial || isAgendaCards ? 32 : isMinimalQuiet ? 44 : isHeroCards || isThreeCardsHero ? 32 : isNumberedBlocks || isNumberedTimeline ? 34 : isThreeCards ? 36 : stacked ? 40 : 36,
          fontWeight: 800,
          color: textColor,
          lineHeight: 1.1,
          clipToSlot: true,
        },
      };
    }
    const itemBodyM = sid.match(/^ITEM_(\d+)_BODY$/i);
    if (itemBodyM && (isNumberedTimeline || isAgendaCards) && overlay.itemBodies?.length) {
      const box = overlay.itemBodies[Number(itemBodyM[1]) - 1];
      if (box) {
        return {
          ...el,
          layer: 12,
          placement: { ...box, rotation: 0, opacity: 1 },
          content: {
            ...colouredColumnTextContent(el.content, {
              color: '#6B7280',
              fontSize: isAgendaCards ? 14 : 13,
              fontWeight: 400,
              align: 'left',
              verticalAlign: 'flex-start',
            }),
            wrap: 'wrap',
            clipToSlot: true,
            lineHeight: 1.35,
          },
        };
      }
    }
    const itemM = sid.match(/^ITEM_(\d+)$/i);
    if (itemM && overlay.items?.length) {
      const i = Number(itemM[1]) - 1;
      const box = overlay.items[i];
      if (box) {
        return {
          ...el,
          layer: 12,
          placement: { ...box, rotation: 0, opacity: 1 },
          content: isNumberedTimeline
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#111827',
              fontSize: 16,
              fontWeight: 800,
              align: 'center',
              verticalAlign: 'center',
            }),
              wrap: 'wrap',
              clipToSlot: true,
              lineHeight: 1.15,
            }
            : isNumberedBlocks
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#4B5563',
              fontSize: 14,
              fontWeight: 400,
              align: 'left',
              verticalAlign: 'flex-start',
            }),
              wrap: 'wrap',
              clipToSlot: true,
              lineHeight: 1.35,
            }
            : isMinimalQuiet
            ? {
              ...colouredColumnTextContent(el.content, {
              color: textColor,
              fontSize: 22,
              fontWeight: 600,
              align: 'left',
              verticalAlign: 'center',
            }),
              wrap: 'nowrap',
              clipToSlot: true,
              lineHeight: 1,
            }
            : isEditorial
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#ffffff',
              fontSize: 16,
              fontWeight: 600,
              align: 'left',
              verticalAlign: 'center',
            }),
              wrap: 'nowrap',
              clipToSlot: true,
              lineHeight: 1,
              padding: 0,
              paddingX: 0,
            }
            : isAgendaCards
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#111827',
              fontSize: 20,
              fontWeight: 700,
              align: 'left',
              verticalAlign: 'center',
            }),
              wrap: 'wrap',
              clipToSlot: true,
              lineHeight: 1.2,
              padding: 0,
              paddingX: 0,
            }
            : {
              ...base,
              align: 'left',
              verticalAlign: 'center',
              fontSize: 18,
              fontWeight: 600,
              color: textColor,
            },
        };
      }
    }
    const bodyM = sid.toUpperCase() === 'BODY';
    if (bodyM && isNumberedBlocks) {
      return el;
    }
    if (bodyM && overlay.items?.length) {
      const box = overlay.items[0];
      return {
        ...el,
        layer: 12,
        placement: {
          x: box.x,
          y: box.y,
          width: overlay.items[overlay.items.length - 1]
            ? overlay.items[overlay.items.length - 1].x + overlay.items[overlay.items.length - 1].width - box.x
            : box.width,
          height: Math.max(box.height, (overlay.items.length) * 56),
          rotation: 0,
          opacity: 1,
        },
        content: { ...base, align: 'left', verticalAlign: 'flex-start', fontSize: 18, color: textColor },
      };
    }
    const colHeadM = sid.match(/^AGENDA_COL_(\d+)_HEADING$/i);
    if (colHeadM && overlay.columns?.length) {
      const i = Number(colHeadM[1]) - 1;
      const col = overlay.columns[i];
      if (col?.heading) {
        return {
          ...el,
          layer: 12,
          placement: { ...col.heading, rotation: 0, opacity: isRibbonCards ? 0 : 1 },
          content: isTwoColRibbon
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#ffffff',
              fontSize: 18,
              fontWeight: 800,
              align: 'left',
              verticalAlign: 'center',
            }),
              clipToSlot: true,
              lineHeight: 1,
            }
            : isRibbonCards
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#ffffff',
              fontSize: 20,
              fontWeight: 800,
              align: 'center',
              verticalAlign: 'center',
            }),
              clipToSlot: true,
              lineHeight: 1,
            }
            : isHeroCards
            ? colouredColumnTextContent(el.content, {
              color: '#111827',
              fontSize: 20,
              fontWeight: 800,
              align: 'center',
              verticalAlign: 'center',
            })
            : isColouredThreeCol
            ? colouredColumnTextContent(el.content, {
              color: '#111827',
              fontSize: 26,
              fontWeight: 800,
              align: 'center',
              verticalAlign: 'center',
            })
            : {
              ...base,
              align: 'center',
              fontSize: 20,
              fontWeight: 800,
              color: columnTextColor,
            },
        };
      }
    }
    const colBodyM = sid.match(/^AGENDA_COL_(\d+)_ITEM_(\d+)_BODY$/i);
    if (colBodyM && overlay.columns?.length) {
      const ci = Number(colBodyM[1]) - 1;
      const ii = Number(colBodyM[2]) - 1;
      const col = overlay.columns[ci];
      const box = col?.itemBodies?.[ii];
      if (box) {
        return {
          ...el,
          layer: 12,
          placement: { ...box, rotation: 0, opacity: 1 },
          content: {
            ...colouredColumnTextContent(el.content, {
              color: '#6B7280',
              fontSize: 12,
              fontWeight: 400,
              align: 'left',
              verticalAlign: 'flex-start',
            }),
            wrap: 'wrap',
            clipToSlot: true,
            lineHeight: 1.3,
          },
        };
      }
    }
    const colItemM = sid.match(/^AGENDA_COL_(\d+)_ITEM_(\d+)$/i);
    if (colItemM && overlay.columns?.length) {
      const ci = Number(colItemM[1]) - 1;
      const ii = Number(colItemM[2]) - 1;
      const col = overlay.columns[ci];
      const box = col?.items?.[ii] || col?.items?.[0];
      if (box) {
        return {
          ...el,
          layer: 12,
          placement: { ...box, rotation: 0, opacity: 1 },
          content: isTwoColRibbon
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#111827',
              fontSize: 14,
              fontWeight: 700,
              align: 'left',
              verticalAlign: 'center',
            }),
              wrap: 'nowrap',
              clipToSlot: true,
              lineHeight: 1.1,
            }
            : isRibbonCards
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#4B5563',
              fontSize: isThreeCardsHero ? 14 : 15,
              fontWeight: 400,
              align: 'left',
              verticalAlign: 'center',
            }),
              wrap: 'wrap',
              clipToSlot: false,
            }
            : isHeroCards
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#4B5563',
              fontSize: 14,
              fontWeight: 400,
              align: 'center',
              verticalAlign: 'center',
            }),
              wrap: 'wrap',
              clipToSlot: false,
            }
            : isColouredThreeCol
            ? {
              ...colouredColumnTextContent(el.content, {
              color: '#6B7280',
              fontSize: 16,
              fontWeight: 400,
              align: 'center',
              verticalAlign: 'center',
            }),
              wrap: 'wrap',
              clipToSlot: false,
            }
            : {
              ...base,
              align: 'center',
              fontSize: 15,
              color: columnTextColor,
            },
        };
      }
    }
    const msM = sid.match(/^milestone_(\d+)_label$/i);
    if (msM && overlay.milestones?.length) {
      const i = Number(msM[1]) - 1;
      const box = overlay.milestones[i];
      if (box) {
        return {
          ...el,
          layer: 12,
          placement: { ...box, rotation: 0, opacity: 1 },
          content: { ...base, align: 'center', fontSize: 14, fontWeight: 700, color: textColor },
        };
      }
    }
    return el;
  });

  if (isHeroCards || isThreeCardsHero) {
    const imageH = heroH || Math.round(canvasH * 0.36);
    elements = elements.map((el) => {
      if (String(el.slotId || '').toUpperCase() !== 'HERO_IMAGE') return el;
      return {
        ...el,
        layer: 1,
        placement: { x: 0, y: 0, width: canvasW, height: imageH, rotation: 0, opacity: 1 },
      };
    });
  }

  const specs = isRibbonCards
    ? agendaThreeCardsChromeSpecs({
      hero: isThreeCardsHero,
      labels: ['Morning', 'Afternoon', 'Evening'].map((fb, i) => {
        const el = elements.find((item) => String(item.slotId || '').toUpperCase() === `AGENDA_COL_${i + 1}_HEADING`);
        const c = el?.content || {};
        const text = typeof c.text === 'string'
          ? c.text
          : Array.isArray(c.runs)
            ? c.runs.map((r) => r.text || '').join('')
            : '';
        return String(text).trim() || fb;
      }),
    })
    : agendaChromeSpecs(family, variant, itemCount);
  const sx = graphicW / 1000;
  const sy = graphicH / 560;
  const chrome = specs.map((spec) => {
    const slotId = spec.slotId;
    const prev = prevBySlot.get(slotId.toUpperCase());
    const placement = {
      x: Math.round(graphicX + spec.x * sx),
      y: Math.round(graphicY + spec.y * sy),
      width: Math.max(4, Math.round(spec.w * sx)),
      height: Math.max(4, Math.round(spec.h * sy)),
      rotation: 0,
      opacity: 1,
    };
    if (spec.kind === 'shape') {
      return {
        id: prev?.id || newElementId('shp-agenda'),
        type: 'shape',
        layer: spec.layer || 3,
        placement,
        content: {
          shape: 'rect',
          borderRadius: spec.borderRadius ? Math.round(spec.borderRadius * Math.min(sx, sy)) : 12,
          fill: spec.fill || prev?.content?.fill || soft,
        },
        role: 'decoration',
        slotId,
      };
    }
    const graphic = isHeroCards
      ? specToHeroCardsContent(spec)
      : isRibbonCards
        ? specToThreeCardsContent(spec)
        : isNumberedBlocks
          ? specToNumberedBlocksContent(spec)
          : isNumberedTimeline
            ? specToNumberedTimelineContent(spec)
            : isMinimalQuiet
            ? specToMinimalQuietContent(spec)
            : isEditorial
            ? specToEditorialContent(spec)
            : isAgendaCards
            ? specToAgendaCardsContent(spec)
            : isTwoColRibbon
            ? specToTwoColumnRibbonContent(spec)
            : isColouredThreeCol
          ? specToThreeColumnContent(spec)
          : specToGraphicContent(spec, accent, soft);
    return {
      id: prev?.id || newElementId('shp-agenda'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement,
      content: {
        svg: graphic.svg,
        colorMode: graphic.colorMode || 'recolorable',
        fill: graphic.fill || { type: 'solid', color: accent, colorRole: 'accent' },
        alt: slotId,
      },
      role: 'decoration',
      slotId,
    };
  });

  return { ...doc, elements: [...chrome, ...elements] };
}

function finalizeElementsDoc(doc, layoutSchema, content, themeTokens, canvasSize = {}, slideDesignPlan = null) {
  if (!doc) return doc;
  const canvas = {
    width: canvasSize.width || doc.canvas?.width || CANVAS_WIDTH,
    height: canvasSize.height || doc.canvas?.height || CANVAS_HEIGHT,
  };
  let next = { ...doc, canvas: doc.canvas || canvas };

  const hasShapeDecisions =
    content?.shapeDecisions &&
    typeof content.shapeDecisions === 'object' &&
    Object.keys(content.shapeDecisions).length > 0;
  if (hasShapeDecisions) {
    next = applyRuntimeShapeDecisions(next, layoutSchema, content, themeTokens, canvas);
  }

  if (isDiagramProcessStepsLayout(layoutSchema?.layout_id)) {
    next = layoutDiagramProcessSteps(next, layoutSchema, themeTokens, canvas);
  } else if (isDiagramCycleLayout(layoutSchema?.layout_id)) {
    next = layoutDiagramCycle(next, layoutSchema, themeTokens, canvas);
  } else if (isDiagramFunnelLayout(layoutSchema?.layout_id)) {
    next = layoutDiagramFunnel(next, layoutSchema, themeTokens, canvas);
  } else if (isDiagramPyramidLayout(layoutSchema?.layout_id)) {
    next = layoutDiagramPyramid(next, layoutSchema, themeTokens, canvas);
  } else if (isDiagramMatrixLayout(layoutSchema?.layout_id)) {
    next = layoutDiagramMatrix(next, layoutSchema, themeTokens, canvas);
  } else if (isDiagramSwotLayout(layoutSchema?.layout_id)) {
    next = layoutDiagramSwot(next, layoutSchema, themeTokens, canvas);
  } else if (isDiagramVennLayout(layoutSchema?.layout_id)) {
    next = layoutDiagramVenn(next, layoutSchema, themeTokens, canvas);
  } else if (isDevicePhoneHighlightsLayout(layoutSchema?.layout_id)) {
    next = layoutDevicePhoneHighlights(next, layoutSchema, themeTokens, canvas, newElementId);
  } else if (isDevicePhoneTripleLayout(layoutSchema?.layout_id)) {
    next = layoutDevicePhoneTriple(next, layoutSchema, themeTokens, canvas, newElementId);
  } else if (isDeviceMultiClusterLayout(layoutSchema?.layout_id)) {
    next = layoutDeviceMultiCluster(next, layoutSchema, themeTokens, canvas, newElementId);
  } else if (isDeviceLaptopSplitLayout(layoutSchema?.layout_id)) {
    next = layoutDeviceLaptopSplit(next, layoutSchema, themeTokens, canvas, newElementId);
  } else if (isDeviceTabletSplitLayout(layoutSchema?.layout_id)) {
    next = layoutDeviceTabletSplit(next, layoutSchema, themeTokens, canvas, newElementId);
  } else if (isDeviceTabletCenteredLayout(layoutSchema?.layout_id)) {
    next = layoutDeviceTabletCentered(next, layoutSchema, themeTokens, canvas, newElementId);
  } else if (isTeamFourLayout(layoutSchema?.layout_id)) {
    next = layoutTeamFour(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamThreeHorizontalLayout(layoutSchema?.layout_id)) {
    next = layoutTeamThreeHorizontal(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamThreeVerticalLayout(layoutSchema?.layout_id)) {
    next = layoutTeamThreeVertical(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamThreeFullCardsLayout(layoutSchema?.layout_id)) {
    next = layoutTeamThreeFullCards(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamFiveLayout(layoutSchema?.layout_id)) {
    next = layoutTeamFive(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamSixLayout(layoutSchema?.layout_id)) {
    next = layoutTeamSix(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamByDepartmentLayout(layoutSchema?.layout_id)) {
    next = layoutTeamByDepartment(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamFeaturedLeadLayout(layoutSchema?.layout_id)) {
    next = layoutTeamFeaturedLead(next, layoutSchema, themeTokens, canvas);
  } else if (isTeamOrgSimpleLayout(layoutSchema?.layout_id)) {
    next = layoutTeamOrgSimple(next, layoutSchema, themeTokens, canvas);
  } else if (isAgendaMinimalLayout(layoutSchema?.layout_id)) {
    next = layoutAgendaInfographic(next, layoutSchema, themeTokens, canvas);
  } else if (isAgendaNumberedLayout(layoutSchema?.layout_id)) {
    next = layoutAgendaInfographic(next, layoutSchema, themeTokens, canvas);
  } else if (
    isAgendaHeroLayout(layoutSchema?.layout_id) ||
    isAgendaThreeColumnLayout(layoutSchema?.layout_id)
  ) {
    next = layoutAgendaInfographic(next, layoutSchema, themeTokens, canvas);
  } else if (isAgendaTimelineLayout(layoutSchema?.layout_id)) {
    next = layoutAgendaInfographic(next, layoutSchema, themeTokens, canvas);
  } else if (isAgendaTwoColumnLayout(layoutSchema?.layout_id)) {
    next = layoutAgendaInfographic(next, layoutSchema, themeTokens, canvas);
  } else if (isQuoteGridLayout(layoutSchema?.layout_id)) {
    next = layoutQuoteGrid(next, layoutSchema, themeTokens, canvas);
  } else if (isQuoteAttributionLayout(layoutSchema?.layout_id)) {
    next = layoutQuoteAttributionSplit(next, layoutSchema, themeTokens, canvas);
  } else if (
    isQuotePortraitLayout(layoutSchema?.layout_id) ||
    isQuoteTestimonialLayout(layoutSchema?.layout_id) ||
    isStatementLargeLayout(layoutSchema?.layout_id) ||
    isStatementLeftLayout(layoutSchema?.layout_id) ||
    isQuoteSingleCardFromSlots(layoutSchema)
  ) {
    next = layoutQuotePortrait(next, layoutSchema, themeTokens, canvas);
  } else {
    next = applyDefaultCardShapes(next, layoutSchema, content, themeTokens, canvas);
    next = applySplitHeroDecorShape(next, layoutSchema, themeTokens, canvas);
    next = applyProcessLinnerHortiShapes(next, layoutSchema, themeTokens, canvas);
    next = applyProcessLinnerNumericShapes(next, layoutSchema, themeTokens, canvas);
    next = applyTimelineConnectorShapes(next, layoutSchema, themeTokens, canvas);
  }

  if (docHasFullBleedBackground(next, layoutSchema)) {
    const enriched = {
      ...content,
      shapeDecisions: {
        ...(content?.shapeDecisions || {}),
        __overlay__: {
          enabled: true,
          scrim: content?.shapeDecisions?.__overlay__?.scrim ?? 0.5,
        },
      },
    };
    next = ensureOverlayScrim(next, layoutSchema, enriched, themeTokens, canvas);
  } else {
    next = ensureOverlayScrim(next, layoutSchema, content, themeTokens, canvas);
  }

  next = stripInvalidOverlayScrims(next);

  // Ensure device bezels follow theme (grey on dark decks).
  if (Array.isArray(next?.elements)) {
    next = {
      ...next,
      elements: next.elements.map((el) => paintDeviceFrameElement(el, themeTokens)),
    };
  }

  next = applyTextOverImageContrast(next, themeTokens, layoutSchema);
  next = applyReadableTextContrast(next, themeTokens, layoutSchema);
  next = applySplitImageEdgeFade(next, layoutSchema);

  if (
    !isDiagramProcessStepsLayout(layoutSchema?.layout_id) &&
    !isDiagramCycleLayout(layoutSchema?.layout_id) &&
    !isDiagramFunnelLayout(layoutSchema?.layout_id) &&
    !isDiagramMatrixLayout(layoutSchema?.layout_id)
  ) {
    next = repairElementsDoc(next, { themeTokens, layoutSchema, content, slideDesignPlan });
  }
  return next;
}

function shouldRecompileLayout(layoutSchema, elementsDoc = null) {
  const layoutId = String(layoutSchema?.layout_id || '').toLowerCase();
  if (/grid_metrics|grid_device|device_/.test(layoutId)) return true;

  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const imageSlots = slots.filter((slot) => isMediaImageSlot(slot.id, slot.role, slot));
  if (imageSlots.length > 1) return true;

  const textSlots = slots.filter((slot) => {
    const role = String(slot.role || '').toLowerCase();
    return ['heading', 'body', 'stat', 'stat_label'].includes(role);
  });
  if (textSlots.length > 3) return true;

  if (elementsDoc && hasOverlappingTextPlacements(elementsDoc)) return true;
  return false;
}

function rebindContentToElements(elementsDoc, content = {}, imageRef = null, opts = {}) {
  const forceTextReplace = opts.forceTextReplace === true;
  const themeTokens = opts.themeTokens || null;
  const layoutSchema = opts.layoutSchema || null;
  const doc = {
    version: elementsDoc?.version || 1,
    canvas: elementsDoc?.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
    elements: Array.isArray(elementsDoc?.elements)
      ? elementsDoc.elements.map((el) => ({ ...el, content: el.content ? { ...el.content } : {} }))
      : [],
  };

  const imageUrl =
    imageRef?.url ||
    imageRef?.s3Url ||
    (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null) ||
    null;

  const applyText = (el, nextText, role) => {
    if (nextText == null) return;
    const value = String(nextText);
    if (!value.length) return;
    const current = el.content?.text;
    if (forceTextReplace || !current || isPackPlaceholderText(current)) {
      el.content = { ...(el.content || {}), text: value };
      applyThemeFontsToText(el, themeTokens, role);
      applyThemeColorsToText(el, themeTokens, role);
    }
  };

  for (const el of doc.elements) {
    const role = resolveElementRole(el);
    const slotId = String(el.slotId || '').toLowerCase();
    const id = String(el.id || '').toLowerCase();
    const slotKey = slotId || id;

    if (el.type === 'text' || el.type === 'textbox') {
      let text = slotKey ? textForSlot(slotKey, content, layoutSchema) : '';
      if ((!text || !String(text).length) && id && id !== slotKey) {
        text = textForSlot(id, content, layoutSchema);
      }
      if (text != null && String(text).length) {
        applyText(el, text, role);
      } else if (isMainTitleSlot(slotKey, role) || isMainTitleSlot(id, role)) {
        applyText(el, content.title, role);
      } else if (role === 'subtitle' || role === 'subheading') {
        applyText(el, content.subtitle, role);
      } else if (role === 'caption' || role === 'footnote' || id.includes('footnote')) {
        applyText(el, content.caption || content.footnote || content.note, role);
      } else if (role === 'quote') {
        applyText(el, content.quote || content.body, role);
      } else if (
        (role === 'body' || role === 'bullets') &&
        (slotKey === 'body' || slotKey === 'bullets' || slotKey === 'statement' || !slotKey)
      ) {
        const bullets = bulletsOf(content);
        const body = content.body || (bullets.length ? bulletBlock(bullets) : '');
        applyText(el, body, role);
      } else if (isMainTitleSlot(slotKey, null) || isMainTitleSlot(id, null)) {
        applyText(el, content.title, 'title');
      }
      const onImage = layoutRequiresOverlayScrim(opts.layoutSchema);
      const rich = buildRichTitleContent(content, onImage);
      if (rich && (isMainTitleSlot(slotKey, role) || isMainTitleSlot(id, role) || role === 'quote')) {
        el.content = { ...(el.content || {}), text: rich.text, runs: rich.runs };
      }
    }

    if (el.type === 'table' && (role === 'table' || id.includes('table') || slotId.includes('table'))) {
      const rows = tableRowsOf(content);
      if (rows.length) el.content = { ...(el.content || {}), rows };
    }

    const isImageSlot =
      role === 'image' ||
      role === 'background' ||
      role === 'hero' ||
      slotId.includes('image') ||
      slotId.includes('hero') ||
      slotId.includes('background') ||
      id.includes('image') ||
      id.includes('hero') ||
      id.includes('background');

    if (
      el.type === 'image' &&
      !isLogoLikeElement(el) &&
      isImageSlot
    ) {
      const slotKey = String(el.slotId || '').trim();
      let slotUrl = slotKey
        ? resolveSlotImageUrl(slotKey, content, imageRef, layoutSchema)
        : imageUrl;
      if (!slotUrl) continue;
      const slotS3Key = slotKey
        ? resolveSlotImageS3Key(slotKey, content, imageRef, layoutSchema)
        : imageRef?.s3Key || null;
      el.content = {
        ...(el.content || {}),
        url: slotUrl,
        s3Key: slotS3Key || el.content?.s3Key || null,
        fit: el.content?.fit || 'cover',
        alt: content.title || el.content?.alt || '',
      };
    }

    if (
      isImagePlaceholderElement(el) &&
      !isLogoLikeElement(el) &&
      isImageSlot
    ) {
      const slotKey = String(el.slotId || '').trim();
      let slotUrl = slotKey
        ? resolveSlotImageUrl(slotKey, content, imageRef, layoutSchema)
        : imageUrl;
      if (!slotUrl) continue;
      const slotS3Key = slotKey
        ? resolveSlotImageS3Key(slotKey, content, imageRef, layoutSchema)
        : imageRef?.s3Key || null;
      el.type = 'image';
      el.content = {
        url: slotUrl,
        s3Key: slotS3Key || null,
        fit: 'cover',
        alt: content.title || '',
      };
      if (!el.role && isImageSlot) el.role = role || 'image';
    }
  }

  return doc;
}

function elementsHaveRebindRoles(elementsDoc) {
  const els = Array.isArray(elementsDoc?.elements) ? elementsDoc.elements : [];
  return els.some((el) => {
    const role = resolveElementRole(el);
    const slotId = String(el.slotId || '').toLowerCase();
    const id = String(el.id || '').toLowerCase();
    return slotKeyMatchesRebind(role, slotId, id) || isImagePlaceholderElement(el);
  });
}

module.exports = {
  regionToPlacement,
  layoutSlotsToElements,
  rebindContentToElements,
  elementsHaveRebindRoles,
  shouldRecompileLayout,
  hasOverlappingTextPlacements,
  applyTextOverImageContrast,
  applySlideDesignTokens,
  finalizeElementsDoc,
  resolveImageGenSize,
  blankCanvas,
  newElementId,
  injectBrandLogo,
  isPackPlaceholderText,
  isMediaImageSlot,
  textForSlot,
};
