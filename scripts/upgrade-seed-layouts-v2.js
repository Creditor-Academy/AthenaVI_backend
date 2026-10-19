/**
 * One-shot upgrade of seed-layouts.json → schemaVersion 2 with roles, typography, decorations.
 * Run: node scripts/upgrade-seed-layouts-v2.js
 */
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../src/modules/presentation/templates/seed-layouts.json');
const layouts = JSON.parse(fs.readFileSync(file, 'utf8'));

const ROLE_BY_ID = {
  title: 'heading',
  subtitle: 'subheading',
  body: 'body',
  bullets: 'body',
  bullets_left: 'body',
  bullets_right: 'body',
  quote: 'quote',
  attribution: 'attribution',
  cta: 'cta',
  contact: 'contact',
  caption: 'caption',
  eyebrow: 'eyebrow',
  stat_value: 'stat',
  stat_label: 'stat_label',
  section_number: 'stat',
  image: 'image',
  chart: 'chart',
  table: 'table',
  accent: 'decoration',
  band: 'decoration',
  axis: 'decoration',
};

const TYPO = {
  heading: { fontSize: 48, fontWeight: 800, letterSpacing: -0.02, lineHeight: 1.15, colorRole: 'text' },
  heading_display: {
    fontSize: 64,
    fontWeight: 800,
    letterSpacing: -0.03,
    lineHeight: 1.1,
    colorRole: 'text',
    align: 'center',
  },
  subheading: { fontSize: 24, fontWeight: 400, lineHeight: 1.4, colorRole: 'muted' },
  body: { fontSize: 18, fontWeight: 400, lineHeight: 1.45, colorRole: 'text' },
  stat: { fontSize: 72, fontWeight: 900, lineHeight: 1.0, colorRole: 'accent' },
  stat_label: { fontSize: 16, fontWeight: 500, lineHeight: 1.3, colorRole: 'muted' },
  quote: { fontSize: 28, fontWeight: 400, lineHeight: 1.35, colorRole: 'text' },
  attribution: { fontSize: 16, fontWeight: 400, colorRole: 'muted' },
  cta: { fontSize: 22, fontWeight: 700, align: 'center', colorRole: 'primary' },
  caption: { fontSize: 14, fontWeight: 400, colorRole: 'muted' },
};

function inferRole(id) {
  const lower = String(id || '').toLowerCase();
  if (ROLE_BY_ID[lower]) return ROLE_BY_ID[lower];
  if (/^stat_\d+$/.test(lower)) return 'stat';
  if (/^member_\d+$/.test(lower) || lower === 'lead' || lower === 'members') return 'body';
  if (/^milestone_\d+$/.test(lower) || lower === 'timeline') return 'body';
  if (/^card_\d+$/.test(lower)) return 'body';
  if (lower.includes('title')) return 'heading';
  if (lower.includes('subtitle')) return 'subheading';
  if (lower.includes('bullet')) return 'body';
  if (lower.includes('image') || lower === 'hero') return 'image';
  if (lower.includes('chart')) return 'chart';
  return 'body';
}

function typographyFor(role, layoutId, slotId) {
  const centered = /centered|thank_you|big_number|banner/.test(layoutId);
  if (role === 'heading' && (slotId === 'title' || slotId === 'headline')) {
    const base =
      /title_centered|closing_centered|stat_big/.test(layoutId) ? { ...TYPO.heading_display } : { ...TYPO.heading };
    if (centered && !base.align) base.align = 'center';
    return base;
  }
  if (role === 'subheading') {
    const t = { ...TYPO.subheading };
    if (centered) t.align = 'center';
    return t;
  }
  if (role === 'stat') return { ...TYPO.stat, align: centered ? 'center' : 'left' };
  if (role === 'stat_label') return { ...TYPO.stat_label, align: centered ? 'center' : 'left' };
  if (role === 'quote') return { ...TYPO.quote, align: centered ? 'center' : 'left' };
  if (role === 'attribution') return { ...TYPO.attribution, align: centered ? 'center' : 'left' };
  if (role === 'cta') return { ...TYPO.cta };
  if (role === 'caption' || role === 'eyebrow') return { ...TYPO.caption };
  if (role === 'body') return { ...TYPO.body };
  return null;
}

function decorationSlots(layoutId, contentType) {
  const out = [];
  const wantsBg = [
    'title',
    'closing',
    'section_divider',
    'stat',
    'quote',
  ].includes(contentType);
  const wantsAccent = ['title', 'closing', 'section_divider', 'agenda', 'stat'].includes(contentType);

  if (wantsBg) {
    out.push({
      id: 'background_gradient',
      region: 'cols 1-12, rows 1-12',
      role: 'background',
      layer: -1,
      shape: {
        type: 'rect',
        fill: {
          type: 'gradient',
          direction: '135deg',
          stops: [
            { colorRole: 'gradientStart', position: 0 },
            { colorRole: 'gradientEnd', position: 100 },
          ],
        },
      },
    });
  }

  if (wantsAccent && !/hero_image|overlay|thank_you_image/.test(layoutId)) {
    out.push({
      id: 'accent_bar',
      region: 'cols 1-1, rows 1-12',
      role: 'decoration',
      layer: 0,
      shape: { type: 'rect', fillColorRole: 'accent' },
    });
  }

  if (contentType === 'title' && /centered/.test(layoutId)) {
    out.push({
      id: 'title_divider',
      region: 'cols 5-8, rows 7-7',
      role: 'divider',
      layer: 2,
      shape: { type: 'rect', fillColorRole: 'accent', borderRadius: 2 },
    });
  }

  if (contentType === 'stat' && /three_up/.test(layoutId)) {
    out.push(
      {
        id: 'stat_card_1',
        region: 'cols 1-4, rows 4-10',
        role: 'decoration',
        layer: 0,
        shape: { type: 'rect', fillColorRole: 'cardBg', borderRadius: 8 },
      },
      {
        id: 'stat_card_2',
        region: 'cols 5-8, rows 4-10',
        role: 'decoration',
        layer: 0,
        shape: { type: 'rect', fillColorRole: 'cardBg', borderRadius: 8 },
      },
      {
        id: 'stat_card_3',
        region: 'cols 9-12, rows 4-10',
        role: 'decoration',
        layer: 0,
        shape: { type: 'rect', fillColorRole: 'cardBg', borderRadius: 8 },
      }
    );
  }

  if (contentType === 'chart') {
    out.push({
      id: 'chart_card',
      region: 'cols 1-12, rows 3-11',
      role: 'decoration',
      layer: 0,
      shape: { type: 'rect', fillColorRole: 'cardBg', borderRadius: 8 },
    });
  }

  return out;
}

const upgraded = layouts.map((row) => {
  const schema = { ...row.schema, schemaVersion: 2 };
  const layoutId = schema.layout_id;
  const contentType = schema.content_type || row.contentType;
  const existing = Array.isArray(schema.slots) ? schema.slots : [];
  const ids = new Set(existing.map((s) => s.id));

  const slots = existing.map((slot) => {
    const role = slot.role || inferRole(slot.id);
    const next = { ...slot, role };
    if (!next.typography && !['decoration', 'background', 'image', 'chart', 'table'].includes(role)) {
      const ty = typographyFor(role, layoutId, slot.id);
      if (ty) next.typography = ty;
    }
    if (slot.id === 'accent' && !slot.shape) {
      next.role = 'decoration';
      next.shape = { type: 'rect', fillColorRole: 'primary' };
    }
    return next;
  });

  for (const deco of decorationSlots(layoutId, contentType)) {
    if (!ids.has(deco.id)) {
      slots.unshift(deco);
      ids.add(deco.id);
    }
  }

  schema.slots = slots;
  return { ...row, schema };
});

fs.writeFileSync(file, JSON.stringify(upgraded, null, 2) + '\n');
console.log(`Upgraded ${upgraded.length} layouts`);
