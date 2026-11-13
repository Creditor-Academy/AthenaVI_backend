/**
 * Editor groups as native PowerPoint groups (<p:grpSp>), so grouped elements move, resize and
 * select together in PowerPoint as they do in the editor.
 *
 * A PowerPoint group sits at one place in the drawing order, so its members must be drawn one
 * after another. Editor children keep their own layers, which can interleave with other
 * elements. The members are moved together (to the topmost member's place) when nothing drawn
 * between them overlaps a member, which leaves the slide looking the same; otherwise the group
 * is left as separate objects.
 */

function overlaps(a, b) {
  if (!a || !b) return true;
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

/**
 * The drawing order with each keepable group's members next to each other.
 * @param {object[]} elements  drawn bottom to top
 * @param {(el: object) => {x:number,y:number,w:number,h:number}|null} boxOf
 * @returns {{ order: object[], groups: Array<{ groupId: string, ids: string[] }>, split: string[] }}
 *   groups: the groups that become native groups; split: groups left as separate objects.
 */
function orderForGroups(elements = [], boxOf = (el) => el?.box || null) {
  let order = [...elements];
  const members = new Map();
  for (const el of order) {
    if (!el?.groupId || el.type === 'group') continue;
    if (!members.has(el.groupId)) members.set(el.groupId, []);
    members.get(el.groupId).push(el.id);
  }
  const groups = [];
  const split = [];
  for (const [groupId, ids] of members) {
    if (ids.length < 2) continue;
    const wanted = new Set(ids);
    const at = order.map((el, i) => (wanted.has(el.id) ? i : -1)).filter((i) => i >= 0);
    const first = at[0];
    const last = at[at.length - 1];
    const between = order.slice(first, last + 1).filter((el) => !wanted.has(el.id));
    if (between.length) {
      const memberBoxes = order.filter((el) => wanted.has(el.id)).map(boxOf);
      const blocks = between.some((el) => memberBoxes.some((b) => overlaps(boxOf(el), b)));
      if (blocks) {
        split.push(groupId);
        continue;
      }
      // Lift the lower members up to the topmost one: nothing they pass covers them.
      const moved = order.filter((el) => wanted.has(el.id));
      const rest = order.filter((el) => !wanted.has(el.id));
      const anchor = rest.indexOf(order[last + 1]);
      const insertAt = anchor < 0 ? rest.length : anchor;
      order = [...rest.slice(0, insertAt), ...moved, ...rest.slice(insertAt)];
    }
    groups.push({ groupId, ids: order.filter((el) => wanted.has(el.id)).map((el) => el.id) });
  }
  // A later move can separate an earlier group again: keep only groups still drawn together.
  const kept = groups.filter((g) => {
    const idx = g.ids.map((id) => order.findIndex((el) => el.id === id)).sort((a, b) => a - b);
    const ok = idx.every((v, i) => i === 0 || v === idx[i - 1] + 1);
    if (!ok) split.push(g.groupId);
    return ok;
  });
  return { order, groups: kept, split };
}

const OBJECT_TAGS = ['p:sp', 'p:pic', 'p:graphicFrame', 'p:cxnSp', 'p:grpSp'];

/** The XML object (<p:sp>, <p:pic>, <p:graphicFrame>…) named `name`: { start, end, tag }. */
function findNamedObject(xml, name) {
  const at = xml.indexOf(`name="${name}"`);
  if (at < 0) return null;
  let best = null;
  for (const tag of OBJECT_TAGS) {
    const start = xml.lastIndexOf(`<${tag}>`, at);
    if (start >= 0 && (!best || start > best.start)) best = { tag, start };
  }
  if (!best) return null;
  const close = `</${best.tag}>`;
  const end = xml.indexOf(close, at);
  return end < 0 ? null : { start: best.start, end: end + close.length, tag: best.tag };
}

/** Offset and size (EMU) of an object, from its <a:xfrm> or <p:xfrm>. */
function objectBounds(objXml) {
  const m = /<(?:a|p):xfrm[^>]*>\s*<a:off x="(-?\d+)" y="(-?\d+)"\s*\/>\s*<a:ext cx="(\d+)" cy="(\d+)"\s*\/>/.exec(objXml);
  if (!m) return null;
  return { x: Number(m[1]), y: Number(m[2]), w: Number(m[3]), h: Number(m[4]) };
}

/**
 * Wrap the named objects of a slide in a <p:grpSp>. They must be adjacent in the slide (only
 * whitespace between them); otherwise the slide is returned unchanged.
 */
function wrapGroup(slideXml, names, groupName = 'Group') {
  const found = names.map((n) => findNamedObject(slideXml, n));
  if (found.length < 2 || found.some((f) => !f)) return slideXml;
  found.sort((a, b) => a.start - b.start);
  for (let i = 1; i < found.length; i += 1) {
    if (slideXml.slice(found[i - 1].end, found[i].start).trim()) return slideXml;
  }
  const inner = slideXml.slice(found[0].start, found[found.length - 1].end);
  const bounds = found.map((f) => objectBounds(slideXml.slice(f.start, f.end))).filter(Boolean);
  if (!bounds.length) return slideXml;
  const x = Math.min(...bounds.map((b) => b.x));
  const y = Math.min(...bounds.map((b) => b.y));
  const w = Math.max(...bounds.map((b) => b.x + b.w)) - x;
  const h = Math.max(...bounds.map((b) => b.y + b.h)) - y;
  const ids = [...slideXml.matchAll(/<p:cNvPr id="(\d+)"/g)].map((m) => Number(m[1]));
  const id = Math.max(1, ...ids) + 1;
  const safeName = String(groupName).replace(/[<>&"]/g, '');
  const group =
    `<p:grpSp><p:nvGrpSpPr><p:cNvPr id="${id}" name="${safeName}"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>` +
    `<p:grpSpPr><a:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${w}" cy="${h}"/>` +
    `<a:chOff x="${x}" y="${y}"/><a:chExt cx="${w}" cy="${h}"/></a:xfrm></p:grpSpPr>` +
    `${inner}</p:grpSp>`;
  return slideXml.slice(0, found[0].start) + group + slideXml.slice(found[found.length - 1].end);
}

module.exports = { orderForGroups, wrapGroup, findNamedObject, objectBounds };
