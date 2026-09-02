/** Group / align helpers for PPT canvas elements (kept in sync with FE pptGroupUtils / pptAlignUtils). */

function isPptGroup(el) {
  return el?.type === 'group' && Array.isArray(el.childIds);
}

function isPptGroupedChild(el) {
  return Boolean(el?.groupId);
}

function getPptUnionBounds(elements = []) {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;

  for (const el of elements) {
    const p = el.placement || {};
    const x = p.x || 0;
    const y = p.y || 0;
    const w = p.width || 100;
    const h = p.height || 40;
    minX = Math.min(minX, x);
    minY = Math.min(minY, y);
    maxX = Math.max(maxX, x + w);
    maxY = Math.max(maxY, y + h);
  }

  if (!Number.isFinite(minX)) {
    return { x: 0, y: 0, width: 100, height: 100 };
  }

  return {
    x: minX,
    y: minY,
    width: Math.max(1, maxX - minX),
    height: Math.max(1, maxY - minY),
  };
}

function canPptGroup(elements, selectedIds) {
  const selected = (elements || []).filter(
    (el) =>
      selectedIds.includes(el.id) &&
      !isPptGroupedChild(el) &&
      !isPptGroup(el) &&
      !el.locked
  );
  return selected.length >= 2;
}

function canPptUngroup(elements, selectedIds) {
  if (!selectedIds || selectedIds.length !== 1) return false;
  const el = (elements || []).find((e) => e.id === selectedIds[0]);
  return isPptGroup(el);
}

function createPptGroup(elements, selectedIds) {
  const children = (elements || []).filter(
    (el) =>
      selectedIds.includes(el.id) &&
      !isPptGroupedChild(el) &&
      !isPptGroup(el)
  );
  if (children.length < 2) return elements;

  const bounds = getPptUnionBounds(children);
  const groupId = `group_${Date.now()}`;
  const childIds = children.map((c) => c.id);
  const maxLayer = Math.max(...children.map((c) => c.layer ?? 0), 0);

  const group = {
    id: groupId,
    type: 'group',
    childIds,
    placement: {
      x: Math.round(bounds.x),
      y: Math.round(bounds.y),
      width: Math.round(bounds.width),
      height: Math.round(bounds.height),
      rotation: 0,
      opacity: 1,
    },
    layer: maxLayer,
    locked: false,
    content: {},
  };

  return elements
    .map((el) => {
      if (childIds.includes(el.id)) {
        return { ...el, groupId };
      }
      return el;
    })
    .concat(group);
}

function ungroupPptElement(elements, groupId) {
  const group = (elements || []).find((el) => el.id === groupId && isPptGroup(el));
  if (!group) return elements;

  const childIds = new Set(group.childIds || []);
  return elements
    .filter((el) => el.id !== groupId)
    .map((el) => {
      if (childIds.has(el.id)) {
        const next = { ...el };
        delete next.groupId;
        return next;
      }
      return el;
    });
}

function alignPptElements(elements = [], selectedIds = [], alignment, canvas = {}) {
  const idSet = new Set((selectedIds || []).filter(Boolean));
  const targets = elements.filter((el) => idSet.has(el.id) && !el.locked);
  if (!targets.length) return elements;

  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const bounds =
    targets.length >= 2
      ? getPptUnionBounds(targets)
      : { x: 0, y: 0, width: canvasW, height: canvasH };

  const deltas = {};
  for (const el of targets) {
    const p = el.placement || {};
    const w = p.width || 100;
    const h = p.height || 40;
    let x = p.x || 0;
    let y = p.y || 0;
    switch (alignment) {
      case 'left':
        x = bounds.x;
        break;
      case 'center':
        x = bounds.x + (bounds.width - w) / 2;
        break;
      case 'right':
        x = bounds.x + bounds.width - w;
        break;
      case 'top':
        y = bounds.y;
        break;
      case 'middle':
        y = bounds.y + (bounds.height - h) / 2;
        break;
      case 'bottom':
        y = bounds.y + bounds.height - h;
        break;
      default:
        break;
    }
    deltas[el.id] = {
      dx: Math.round(x) - (p.x || 0),
      dy: Math.round(y) - (p.y || 0),
    };
  }

  return elements.map((el) => {
    const delta = deltas[el.id] || (el.groupId ? deltas[el.groupId] : null);
    if (!delta || (!delta.dx && !delta.dy)) return el;
    const p = el.placement || {};
    return {
      ...el,
      placement: {
        ...p,
        x: Math.round((p.x || 0) + delta.dx),
        y: Math.round((p.y || 0) + delta.dy),
      },
    };
  });
}

function collectDeleteIds(elements, elementId) {
  const remove = new Set([elementId]);
  const target = (elements || []).find((el) => el.id === elementId);
  if (isPptGroup(target)) {
    for (const cid of target.childIds || []) remove.add(cid);
  }
  return remove;
}

module.exports = {
  isPptGroup,
  isPptGroupedChild,
  getPptUnionBounds,
  canPptGroup,
  canPptUngroup,
  createPptGroup,
  ungroupPptElement,
  alignPptElements,
  collectDeleteIds,
};
