/**
 * Things pptxgenjs can't write, added to the PPTX XML after it has been generated:
 *   - gradient fills on shapes, text and slide backgrounds (<a:gradFill>);
 *   - glow on shapes and pictures (<a:glow>);
 *   - text effects: shadow, glow, outline, hollow text, highlight.
 *
 * During the build each element that needs a patch gets a unique objectName (`athena-12`),
 * which pptxgenjs writes as <p:cNvPr name="…">; the patch finds the shape by that name.
 * Element order inside each XML node follows the DrawingML schema (fill → ln → effectLst for
 * shapes; ln → fill → effectLst → highlight → … for text runs) so PowerPoint opens the file
 * without a repair prompt.
 */

const JSZip = require('jszip');

const EMU_PER_PT = 12700;

class PptxPatches {
  constructor() {
    this.items = [];
    this.count = 0;
  }

  /** A name for the next patched object on slide `slideNumber` (1-based). */
  name() {
    this.count += 1;
    return `athena-${this.count}`;
  }

  add(slideNumber, patch) {
    this.items.push({ slideNumber, ...patch });
  }

  get size() {
    return this.items.length;
  }
}

const hex = (c) => String(c || '000000').replace(/^#/, '').toUpperCase().slice(0, 6);
const alphaXml = (alpha) => (alpha != null && alpha < 1 ? `<a:alpha val="${Math.round(Math.max(0, alpha) * 100000)}"/>` : '');
const colorXml = (color, alpha) => `<a:srgbClr val="${hex(color)}">${alphaXml(alpha)}</a:srgbClr>`.replace('"></a:srgbClr>', '"/>');

/**
 * <a:gradFill> for an editor gradient: stops [{ color, at (0–1), alpha? }], CSS angle in
 * degrees (0 = to top, 90 = to right) or radial.
 */
function gradFillXml({ stops = [], angle = 135, radial = false }) {
  const list = stops.length >= 2 ? stops : [stops[0] || { color: '#000000', at: 0 }, stops[0] || { color: '#000000', at: 1 }];
  const gs = list
    .map((s, i) => {
      const at = s.at != null ? Number(s.at) : i / (list.length - 1);
      const pos = Math.round(Math.max(0, Math.min(1, at > 1 ? at / 100 : at)) * 100000);
      return `<a:gs pos="${pos}">${colorXml(s.color, s.alpha)}</a:gs>`;
    })
    .join('');
  const shade = radial
    ? '<a:path path="circle"><a:fillToRect l="50000" t="50000" r="50000" b="50000"/></a:path>'
    : `<a:lin ang="${Math.round((((Number(angle) - 90) % 360) + 360) % 360 * 60000)}" scaled="0"/>`;
  return `<a:gradFill rotWithShape="1"><a:gsLst>${gs}</a:gsLst>${shade}</a:gradFill>`;
}

function glowXml({ color, radiusPt, alpha = 0.6 }) {
  return `<a:glow rad="${Math.max(0, Math.round(radiusPt * EMU_PER_PT))}">${colorXml(color, alpha)}</a:glow>`;
}

function outerShadowXml({ color = '#000000', alpha = 0.45, blurPt = 3, distPt = 3, angleDeg = 45 }) {
  const dir = Math.round(((((Number(angleDeg) % 360) + 360) % 360) * 60000));
  return `<a:outerShdw blurRad="${Math.round(blurPt * EMU_PER_PT)}" dist="${Math.round(distPt * EMU_PER_PT)}" dir="${dir}" algn="ctr" rotWithShape="0">${colorXml(color, alpha)}</a:outerShdw>`;
}

/** The XML of the shape / picture named `name`: { start, end } in `xml`, or null. */
function findObject(xml, name) {
  const at = xml.indexOf(`name="${name}"`);
  if (at < 0) return null;
  const candidates = ['<p:sp>', '<p:pic>']
    .map((tag) => ({ tag, start: xml.lastIndexOf(tag, at) }))
    .filter((c) => c.start >= 0)
    .sort((a, b) => b.start - a.start);
  if (!candidates.length) return null;
  const { tag, start } = candidates[0];
  const close = tag === '<p:sp>' ? '</p:sp>' : '</p:pic>';
  const end = xml.indexOf(close, at);
  return end < 0 ? null : { start, end: end + close.length };
}

/** Replace the shape fill (the first fill in spPr, before <a:ln>) with `fillXml`. */
function replaceShapeFill(obj, fillXml) {
  const sp0 = obj.indexOf('<p:spPr>');
  const sp1 = obj.indexOf('</p:spPr>', sp0);
  if (sp0 < 0 || sp1 < 0) return obj;
  let spPr = obj.slice(sp0, sp1);
  const lnAt = spPr.indexOf('<a:ln');
  const fill = /<a:solidFill>[\s\S]*?<\/a:solidFill>|<a:noFill\/>/.exec(spPr);
  if (fill && (lnAt < 0 || fill.index < lnAt)) {
    spPr = spPr.slice(0, fill.index) + fillXml + spPr.slice(fill.index + fill[0].length);
  } else {
    // No fill written: it goes right after the geometry.
    spPr = spPr.replace(/(<\/a:prstGeom>|<\/a:custGeom>)/, `$1${fillXml}`);
  }
  return obj.slice(0, sp0) + spPr + obj.slice(sp1);
}

/** Add an effect at the start of the shape's effect list (glow comes before shadows). */
function addShapeEffect(obj, effectXml) {
  const sp0 = obj.indexOf('<p:spPr');
  const sp1 = obj.indexOf('</p:spPr>', sp0);
  if (sp0 < 0 || sp1 < 0) return obj;
  let spPr = obj.slice(sp0, sp1);
  if (spPr.includes('<a:effectLst>')) {
    spPr = spPr.replace('<a:effectLst>', `<a:effectLst>${effectXml}`);
  } else if (spPr.includes('<a:effectLst/>')) {
    spPr = spPr.replace('<a:effectLst/>', `<a:effectLst>${effectXml}</a:effectLst>`);
  } else {
    // After <a:ln> (or the fill), before 3D settings.
    const lnEnd = spPr.lastIndexOf('</a:ln>');
    const insertAt = lnEnd >= 0 ? lnEnd + '</a:ln>'.length : spPr.length;
    spPr = `${spPr.slice(0, insertAt)}<a:effectLst>${effectXml}</a:effectLst>${spPr.slice(insertAt)}`;
  }
  return obj.slice(0, sp0) + spPr + obj.slice(sp1);
}

/**
 * Rewrite every text run's properties: optional outline (<a:ln>), fill (kept, gradient or none),
 * effects and highlight, in schema order, keeping the rest (fonts, links) after them.
 */
function rewriteRuns(obj, { lnXml = '', fillXml = null, effectsXml = '', highlightXml = '' }) {
  return obj.replace(/<a:rPr([^>]*?)(\/>|>([\s\S]*?)<\/a:rPr>)/g, (whole, attrs, _tail, inner = '') => {
    let rest = inner;
    rest = rest.replace(/<a:ln\b[\s\S]*?<\/a:ln>|<a:ln\b[^>]*\/>/, '');
    const fill = /<a:solidFill>[\s\S]*?<\/a:solidFill>|<a:gradFill[\s\S]*?<\/a:gradFill>|<a:noFill\/>/.exec(rest);
    const existingFill = fill ? fill[0] : '';
    if (fill) rest = rest.slice(0, fill.index) + rest.slice(fill.index + fill[0].length);
    rest = rest.replace(/<a:effectLst>[\s\S]*?<\/a:effectLst>|<a:effectLst\/>/, '').replace(/<a:highlight>[\s\S]*?<\/a:highlight>/, '');
    const fillOut = fillXml != null ? fillXml : existingFill;
    const effects = effectsXml ? `<a:effectLst>${effectsXml}</a:effectLst>` : '';
    return `<a:rPr${attrs}>${lnXml}${fillOut}${effects}${highlightXml}${rest}</a:rPr>`;
  });
}

function applyToObject(objXml, patch) {
  switch (patch.kind) {
    case 'shapeGradient':
      return replaceShapeFill(objXml, gradFillXml(patch.gradient));
    case 'glow':
      return addShapeEffect(objXml, glowXml(patch));
    case 'text': {
      const effects = [patch.glow ? glowXml(patch.glow) : '', patch.shadow ? outerShadowXml(patch.shadow) : ''].join('');
      return rewriteRuns(objXml, {
        lnXml: patch.outline
          ? `<a:ln w="${Math.max(1, Math.round(patch.outline.widthPt * EMU_PER_PT))}"><a:solidFill>${colorXml(patch.outline.color)}</a:solidFill></a:ln>`
          : '',
        fillXml: patch.gradient ? gradFillXml(patch.gradient) : patch.noFill ? '<a:noFill/>' : null,
        effectsXml: effects,
        highlightXml: patch.highlight ? `<a:highlight>${colorXml(patch.highlight)}</a:highlight>` : '',
      });
    }
    default:
      return objXml;
  }
}

function applyToSlide(xml, patches) {
  let out = xml;
  for (const patch of patches) {
    if (patch.kind === 'backgroundGradient') {
      out = out.replace(
        /<p:bg><p:bgPr>[\s\S]*?<\/p:bgPr><\/p:bg>/,
        `<p:bg><p:bgPr>${gradFillXml(patch.gradient)}<a:effectLst/></p:bgPr></p:bg>`
      );
      continue;
    }
    const found = findObject(out, patch.name);
    if (!found) continue;
    const obj = out.slice(found.start, found.end);
    out = out.slice(0, found.start) + applyToObject(obj, patch) + out.slice(found.end);
  }
  return out;
}

/** Apply the patches to a written PPTX. Returns the buffer unchanged when there are none. */
async function applyPptxPatches(buffer, patches) {
  if (!patches || !patches.size) return buffer;
  const zip = await JSZip.loadAsync(buffer);
  await applyPptxPatchesToZip(zip, patches);
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

/** Apply the patches to the slides of a loaded PPTX (JSZip), in place. */
async function applyPptxPatchesToZip(zip, patches) {
  if (!patches || !patches.size) return;
  const bySlide = new Map();
  for (const p of patches.items) {
    if (!bySlide.has(p.slideNumber)) bySlide.set(p.slideNumber, []);
    bySlide.get(p.slideNumber).push(p);
  }
  for (const [slideNumber, list] of bySlide) {
    const file = zip.file(`ppt/slides/slide${slideNumber}.xml`);
    if (!file) continue;
    const xml = await file.async('string');
    zip.file(`ppt/slides/slide${slideNumber}.xml`, applyToSlide(xml, list));
  }
}

module.exports = {
  PptxPatches,
  applyPptxPatches,
  applyPptxPatchesToZip,
  gradFillXml,
  glowXml,
  outerShadowXml,
  applyToSlide,
  EMU_PER_PT,
};
