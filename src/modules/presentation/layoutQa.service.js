function countWords(text) {
  if (text == null) return 0;
  const s = String(text).trim();
  if (!s) return 0;
  return s.split(/\s+/).filter(Boolean).length;
}

function truncateToWords(text, maxWords) {
  const raw = String(text ?? '');
  const words = raw.trim().split(/\s+/).filter(Boolean);
  if (words.length <= maxWords) return raw;
  return words.slice(0, maxWords).join(' ');
}

function truncateToLines(text, maxLines) {
  const raw = String(text ?? '');
  if (maxLines <= 0) return '';
  const lines = raw.split(/\r?\n/);
  if (lines.length <= maxLines) {
    // Approximate line length (~12 words/line) when single-line overflow
    const approxWords = maxLines * 12;
    if (countWords(raw) > approxWords) {
      return truncateToWords(raw, approxWords);
    }
    return raw;
  }
  return lines.slice(0, maxLines).join('\n');
}

function cloneContent(content) {
  if (!content || typeof content !== 'object') return {};
  return JSON.parse(JSON.stringify(content));
}

function slotFieldMap(slotId) {
  const id = String(slotId || '').toLowerCase();
  if (id === 'title' || id.endsWith('_title') || id === 'left_title' || id === 'right_title') {
    return { kind: 'string', key: id === 'title' ? 'title' : id };
  }
  if (id === 'subtitle') return { kind: 'string', key: 'subtitle' };
  if (id === 'body' || id === 'left_body' || id === 'right_body') {
    return { kind: id.includes('body') && id !== 'body' ? 'arrayOrString' : 'string', key: id === 'body' ? 'body' : id };
  }
  if (id === 'bullets' || id === 'bullets_left' || id === 'bullets_right') {
    return { kind: 'bullets', key: id === 'bullets' ? 'bullets' : id };
  }
  if (id === 'quote') return { kind: 'string', key: 'quote' };
  if (id === 'pros' || id === 'cons') return { kind: 'bullets', key: id };
  if (id.startsWith('card_') || id.startsWith('stat_')) {
    return { kind: 'string', key: id };
  }
  return { kind: 'string', key: id };
}

function applyStringLimits(value, slot, issues, path) {
  let next = value == null ? value : String(value);
  if (next == null) return next;

  if (slot.max_lines != null) {
    const maxLines = Math.max(0, Number(slot.max_lines) || 0);
    const before = next;
    next = truncateToLines(next, maxLines);
    if (next !== before) {
      issues.push({ path, rule: 'max_lines', max: maxLines, truncated: true });
    }
  }

  if (slot.max_words != null) {
    const maxWords = Math.max(0, Number(slot.max_words) || 0);
    const before = next;
    next = truncateToWords(next, maxWords);
    if (next !== before) {
      issues.push({ path, rule: 'max_words', max: maxWords, truncated: true });
    }
  }

  return next;
}

function applyBulletLimits(items, slot, issues, path) {
  let list = Array.isArray(items) ? items.slice() : [];
  const maxItems = slot.max_items != null ? Math.max(0, Number(slot.max_items) || 0) : null;
  const maxWords = slot.max_words != null ? Math.max(0, Number(slot.max_words) || 0) : null;

  if (maxItems != null && list.length > maxItems) {
    list = list.slice(0, maxItems);
    issues.push({ path, rule: 'max_items', max: maxItems, truncated: true });
  }

  if (maxWords != null) {
    list = list.map((item, idx) => {
      if (typeof item === 'string') {
        const next = truncateToWords(item, maxWords);
        if (next !== item) {
          issues.push({ path: `${path}[${idx}]`, rule: 'max_words', max: maxWords, truncated: true });
        }
        return next;
      }
      if (item && typeof item === 'object' && item.text != null) {
        const nextText = truncateToWords(item.text, maxWords);
        if (nextText !== item.text) {
          issues.push({
            path: `${path}[${idx}].text`,
            rule: 'max_words',
            max: maxWords,
            truncated: true,
          });
        }
        return { ...item, text: nextText };
      }
      return item;
    });
  }

  return list;
}

/**
 * Validate / truncate slide content against layout schema slot caps.
 * @returns {{ content: object, issues: Array<object> }}
 */
function validateSlide({ content, layoutSchema }) {
  const issues = [];
  const next = cloneContent(content);
  const schema = layoutSchema && typeof layoutSchema === 'object' ? layoutSchema : {};
  const slots = Array.isArray(schema.slots) ? schema.slots : [];

  // Default soft caps when schema has no slots
  if (slots.length === 0) {
    if (next.title != null) {
      next.title = applyStringLimits(next.title, { max_lines: 3, max_words: 16 }, issues, 'title');
    }
    if (Array.isArray(next.bullets) && next.bullets.length > 8) {
      next.bullets = next.bullets.slice(0, 8);
      issues.push({ path: 'bullets', rule: 'max_items', max: 8, truncated: true });
    }
    return { content: next, issues };
  }

  for (const slot of slots) {
    const mapping = slotFieldMap(slot.id);
    const key = mapping.key;

    if (mapping.kind === 'bullets') {
      const source =
        key === 'bullets'
          ? next.bullets
          : next[key] != null
            ? next[key]
            : key === 'bullets_left' || key === 'bullets_right'
              ? next.bullets
              : next[key];

      if (source == null && key !== 'bullets') continue;

      if (key === 'bullets' || next[key] != null) {
        next[key === 'bullets' ? 'bullets' : key] = applyBulletLimits(
          key === 'bullets' ? next.bullets : next[key],
          slot,
          issues,
          key === 'bullets' ? 'bullets' : key
        );
      } else if ((key === 'bullets_left' || key === 'bullets_right') && Array.isArray(next.bullets)) {
        // Leave shared bullets; layout render can split. Still enforce soft word caps on all.
        next.bullets = applyBulletLimits(next.bullets, slot, issues, 'bullets');
      }
      continue;
    }

    if (mapping.kind === 'arrayOrString') {
      if (Array.isArray(next[key])) {
        next[key] = applyBulletLimits(next[key], slot, issues, key);
      } else if (next[key] != null) {
        next[key] = applyStringLimits(next[key], slot, issues, key);
      } else if (key === 'body' || key === 'left_body' || key === 'right_body') {
        // Map common content.body through body slot
        if (key === 'body' && next.body != null) {
          next.body = applyStringLimits(next.body, slot, issues, 'body');
        }
      }
      continue;
    }

    // Prefer well-known content keys for standard slots
    let targetKey = key;
    if (slot.id === 'title' && next.title != null) targetKey = 'title';
    if (slot.id === 'subtitle' && next.subtitle != null) targetKey = 'subtitle';
    if (slot.id === 'body' && next.body != null) targetKey = 'body';
    if (slot.id === 'quote' && next.quote != null) targetKey = 'quote';

    if (next[targetKey] != null && (typeof next[targetKey] === 'string' || typeof next[targetKey] === 'number')) {
      next[targetKey] = applyStringLimits(next[targetKey], slot, issues, targetKey);
    }
  }

  return { content: next, issues };
}

module.exports = {
  validateSlide,
  truncateToWords,
  truncateToLines,
  countWords,
};
