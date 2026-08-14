/** Reference slide width — canvas-relative type scales like Replit vw on the slide box. */
const CANVAS_REF_WIDTH = 1920;

const ROLE_VW = {
  heading: 0.055,
  quote: 0.05,
  subheading: 0.035,
  body: 0.018,
  stat: 0.1,
  caption: 0.012,
  stat_label: 0.014,
  eyebrow: 0.012,
  cta: 0.022,
  attribution: 0.014,
};

function vwForSlot(role, slotId = '') {
  const id = String(slotId || '').toLowerCase();
  if (id === 'stat_value' || /^stat_\d+_value$/.test(id) || id === 'section_number') return 0.1;
  if (id === 'stat_label' || /^stat_\d+_label$/.test(id)) return 0.016;
  if (id.includes('title') && !id.includes('subtitle')) return 0.052;
  if (id.includes('subtitle')) return 0.028;
  return ROLE_VW[String(role || 'body').toLowerCase()] ?? ROLE_VW.body;
}

function fontSizeForTextSlot(slot, placement, canvasWidth = CANVAS_REF_WIDTH) {
  const role = String(slot?.role || 'body').toLowerCase();
  const slotId = slot?.id || '';
  const cw = Math.max(Number(canvasWidth) || CANVAS_REF_WIDTH, 320);
  const fromCanvas = cw * vwForSlot(role, slotId);

  const maxLines =
    slot?.max_lines ||
    (role === 'stat'
      ? 1
      : role === 'heading' || role === 'quote'
        ? 2
        : role === 'caption' || role === 'stat_label'
          ? 2
          : 4);
  const lineHeight = role === 'stat' ? 1.1 : 1.32;
  const height = Math.max(Number(placement?.height) || 0, 24);
  const maxByHeight = height / (maxLines * lineHeight) - 2;

  const minSize = role === 'stat' ? 20 : 12;
  const cap = role === 'stat' ? Math.min(220, fromCanvas) : fromCanvas;

  return Math.round(Math.max(minSize, Math.min(cap, maxByHeight)));
}

function resolveTypeScaleFontSize(role, typeScale = {}) {
  const r = String(role || '').toLowerCase();
  const map = {
    heading: typeScale.title ?? typeScale.display,
    quote: typeScale.subtitle ?? typeScale.title,
    subheading: typeScale.subtitle,
    body: typeScale.body,
    caption: typeScale.caption,
    stat_label: typeScale.caption,
    eyebrow: typeScale.caption,
    stat: typeScale.stat ?? typeScale.display,
    cta: typeScale.subtitle,
  };
  const size = map[r];
  return size != null && Number(size) > 0 ? Number(size) : null;
}

module.exports = {
  CANVAS_REF_WIDTH,
  fontSizeForTextSlot,
  resolveTypeScaleFontSize,
};
