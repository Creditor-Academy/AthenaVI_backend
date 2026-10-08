'use strict';

const { isMediaImageSlot } = require('./layoutToElements');
const { isCatalogPlaceholderText } = require('./catalogPlaceholder');
const {
  analyzeChartStory,
  inferChartTypeFromStory,
} = require('./chartStory.util');
const {
  buildSlotImagePrompt,
  appendImageNegatives,
  imagePromptEchoesCopy,
  shortVisualPhrase,
  layoutHasChartSlot,
  withDeviceUiDirective,
  resolveImagePromptAlias,
  titleWordsFromBody,
  overallThemeSubject,
} = require('./contentImagePrompt.util');
const { isDeviceScreenSlotId } = require('./diagrams/deviceChrome.util');

function runContentPreShape(content, layoutSchema) {
  if (!layoutSchema?.slots?.length) return content;
  let next = content;
  next = normalizeMultiColumnContent(next, layoutSchema);
  next = normalizeGalleryImageContent(next, layoutSchema);
  next = normalizeChartContent(next, layoutSchema);
  next = normalizeTimelineContent(next, layoutSchema);
  next = normalizeDiagramContent(next, layoutSchema);
  next = normalizeDeviceContent(next, layoutSchema);
  next = normalizeAgendaContent(next, layoutSchema);
  next = normalizeComparisonProsConsContent(next, layoutSchema);
  return next;
}

function isComparisonProsConsLayoutId(layoutId) {
  return /comparison_pros_cons/i.test(String(layoutId || ''));
}

function prosConsRowFromEntry(entry) {
  if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
    const title = String(entry.title ?? entry.label ?? entry.heading ?? entry.topic ?? '').trim();
    const body = String(entry.body ?? entry.text ?? entry.detail ?? '').trim();
    return { title, body };
  }
  const raw = typeof entry === 'string' ? entry.trim() : String(entry ?? '').trim();
  if (!raw) return { title: '', body: '' };
  const colon = raw.match(/^([^:]{2,60}):\s*(.+)$/);
  if (colon) return { title: colon[1].trim(), body: colon[2].trim() };
  return { title: raw, body: '' };
}

function normalizeProsConsList(raw) {
  const list = Array.isArray(raw) ? raw : [];
  const rows = list.map((entry) => prosConsRowFromEntry(entry));
  while (rows.length < 5) rows.push({ title: '', body: '' });
  return rows.slice(0, 5);
}

function normalizeComparisonProsConsContent(content, layoutSchema) {
  const layoutId = String(layoutSchema?.layout_id || '');
  if (!isComparisonProsConsLayoutId(layoutId) || !content || typeof content !== 'object') {
    return content;
  }
  const next = { ...content };
  const cmp = next.comparison && typeof next.comparison === 'object' ? { ...next.comparison } : {};

  if (!next.prosTitle) {
    next.prosTitle =
      cmp.prosTitle || cmp.left?.title || next.left?.title || 'Pros';
  }
  if (!next.consTitle) {
    next.consTitle =
      cmp.consTitle || cmp.right?.title || next.right?.title || 'Cons';
  }

  let prosRows = Array.isArray(next.prosRows) ? next.prosRows : null;
  let consRows = Array.isArray(next.consRows) ? next.consRows : null;
  if (!prosRows?.length) {
    if (Array.isArray(cmp.pros) && cmp.pros.length) prosRows = cmp.pros;
    else if (Array.isArray(next.pros) && next.pros.length) prosRows = next.pros;
    else if (Array.isArray(cmp.left?.bullets)) prosRows = cmp.left.bullets;
    else if (Array.isArray(next.left?.bullets)) prosRows = next.left.bullets;
  }
  if (!consRows?.length) {
    if (Array.isArray(cmp.cons) && cmp.cons.length) consRows = cmp.cons;
    else if (Array.isArray(next.cons) && next.cons.length) consRows = next.cons;
    else if (Array.isArray(cmp.right?.bullets)) consRows = cmp.right.bullets;
    else if (Array.isArray(next.right?.bullets)) consRows = next.right.bullets;
  }

  next.prosRows = normalizeProsConsList(prosRows || []);
  next.consRows = normalizeProsConsList(consRows || []);
  next.pros = next.prosRows.map((r) =>
    r.title && r.body ? `${r.title}: ${r.body}` : r.title || r.body || ''
  );
  next.cons = next.consRows.map((r) =>
    r.title && r.body ? `${r.title}: ${r.body}` : r.title || r.body || ''
  );
  next.comparison = {
    ...cmp,
    prosTitle: next.prosTitle,
    consTitle: next.consTitle,
    left: { ...(cmp.left || next.left || {}), title: next.prosTitle },
    right: { ...(cmp.right || next.right || {}), title: next.consTitle },
  };
  return next;
}

function countAgendaColumns(slots) {
  let max = 0;
  for (const slot of slots) {
    const m = String(slot.id || '').toUpperCase().match(/^AGENDA_COL_(\d+)_HEADING$/);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return max;
}

function agendaItemsPerColumn(slots) {
  const perCol = {};
  for (const slot of slots) {
    const m = String(slot.id || '').toUpperCase().match(/^AGENDA_COL_(\d+)_ITEM_(\d+)$/i);
    if (m) {
      const col = Number(m[1]);
      const item = Number(m[2]);
      perCol[col] = Math.max(perCol[col] || 0, item);
    }
  }
  return perCol;
}

function normalizeAgendaContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const needed = countAgendaColumns(layoutSchema.slots);
  if (needed < 2) return content;

  const existing = content?.agenda?.columns;
  if (
    Array.isArray(existing) &&
    existing.length >= 2 &&
    existing.some((col) => String(col?.heading ?? col?.title ?? '').trim()) &&
    existing.some((col) => Array.isArray(col?.items) && col.items.some((item) => String(item ?? '').trim()))
  ) {
    return content;
  }

  const bullets = Array.isArray(content.bullets) ? content.bullets : [];
  const summary = String(content.body || content.summary || content.subtitle || '').trim();
  const parts = summary.split(/[.;]\s+/).map((p) => p.trim()).filter(Boolean);
  const defaultHeadings = ['Morning', 'Afternoon', 'Evening'];
  const itemsPerCol = agendaItemsPerColumn(layoutSchema.slots);
  const cols = [];

  for (let i = 0; i < needed; i += 1) {
    const colNum = i + 1;
    const heading = defaultHeadings[i] || `Session ${colNum}`;
    const itemSlots = itemsPerCol[colNum] || 2;
    let items = [];
    if (bullets.length >= needed) {
      const perCol = Math.max(1, Math.ceil(bullets.length / needed));
      items = bullets
        .slice(i * perCol, (i + 1) * perCol)
        .map((b) => (typeof b === 'string' ? b.trim() : String(b?.text ?? b?.label ?? '').trim()))
        .filter(Boolean);
    } else if (parts.length >= 2) {
      items = [parts[i] || parts[i % parts.length] || `Topic ${colNum}`];
    } else if (summary) {
      items = [summary.slice(0, 80)];
    } else {
      items = [`${heading} item 1`, `${heading} item 2`];
    }
    while (items.length < itemSlots) {
      const n = items.length + 1;
      items.push(`${heading} focus ${n}`);
    }
    cols.push({ heading, items: items.slice(0, itemSlots) });
  }

  return { ...content, agenda: { ...(content.agenda || {}), columns: cols } };
}

function normalizeMultiColumnContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const slots = layoutSchema.slots;
  const needsColumns =
    slots.some((s) => /^(card|col|row)_\d+_(title|body)$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^bullet_\d+$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^body_\d+$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^image_\d+_label$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^IMAGE_\d+$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^COL_\d+_IMAGE$/i.test(String(s.id || '')));
  if (!needsColumns) return content;

  let colsKey = Array.isArray(content.columns)
    ? 'columns'
    : Array.isArray(content.cards)
      ? 'cards'
      : Array.isArray(content.features)
        ? 'features'
        : null;

  const next = { ...content };

  if (!colsKey) {
    const bullets = Array.isArray(content.bullets) ? content.bullets : [];
    const items = Array.isArray(content.items) ? content.items : [];
    const indexedSlotCount = Math.max(
      slots.filter((s) => /^bullet_\d+$/i.test(String(s.id || ''))).length,
      slots.filter((s) => /^body_\d+$/i.test(String(s.id || ''))).length,
      slots.filter((s) => /^IMAGE_\d+$/i.test(String(s.id || ''))).length
    );
    if (items.length >= 2) {
      next.columns = items.map((item, index) => {
        if (typeof item === 'string') {
          const text = item.trim();
          const split = text.split(/[:\-â€”â€“]\s*/);
          return {
            title: split.length > 1 ? split[0].trim() : titleWordsFromBody(text, `Item ${index + 1}`),
            body: split.length > 1 ? split.slice(1).join(' ').trim() : text,
          };
        }
        return {
          title: String(item.title ?? item.heading ?? item.label ?? titleWordsFromBody(item.body ?? item.text ?? '', `Item ${index + 1}`)).trim(),
          body: String(item.body ?? item.text ?? item.description ?? '').trim(),
        };
      });
      colsKey = 'columns';
    } else if (bullets.length >= 2) {
      next.columns = bullets.map((bullet, index) => {
        const text = typeof bullet === 'string' ? bullet.trim() : String(bullet?.text ?? bullet?.label ?? '').trim();
        const split = text.split(/[:\-â€”â€“]\s*/);
        const inlineTitle = split.length > 1 ? split[0].trim() : '';
        const body = split.length > 1 ? split.slice(1).join(' ').trim() : text;
        return {
          title: inlineTitle || titleWordsFromBody(body, `Point ${index + 1}`),
          body,
        };
      });
      colsKey = 'columns';
    } else if (indexedSlotCount >= 2) {
      const summary = String(content.summary || content.body || content.subtitle || '').trim();
      const parts = summary.split(/[.;]\s+/).map((part) => part.trim()).filter(Boolean);
      if (parts.length >= 2) {
        next.columns = Array.from({ length: indexedSlotCount }, (_, index) => {
          const body = parts[index] || parts[index % parts.length] || summary.slice(0, 120);
          return {
            title: titleWordsFromBody(body, `Point ${index + 1}`),
            body,
          };
        });
        colsKey = 'columns';
      }
    }
  }

  if (!colsKey) return content;

  next[colsKey] = [...next[colsKey]];
  const slideTitle = String(next.title || '').trim().toLowerCase();
  const seen = new Set();

  next[colsKey] = next[colsKey].map((col, index) => {
    if (!col || typeof col !== 'object') return col;
    const copy = { ...col };
    let title = String(copy.title ?? copy.heading ?? copy.label ?? '').trim();
    const body = String(copy.body ?? copy.text ?? '').trim();
    const titleLower = title.toLowerCase();

    // Hard rule: never reuse the slide title (or duplicates) as every column heading.
    if (!title || titleLower === slideTitle || seen.has(titleLower)) {
      const fromBody = titleWordsFromBody(body, '');
      const fromBodyLower = String(fromBody || '').trim().toLowerCase();
      if (fromBody && fromBodyLower !== slideTitle && !seen.has(fromBodyLower)) {
        title = fromBody;
      } else {
        title = `Aspect ${index + 1}`;
      }
      copy.title = title;
      if (copy.heading != null) copy.heading = title;
      if (copy.label != null) copy.label = title;
    }
    seen.add(String(copy.title ?? copy.heading ?? '').trim().toLowerCase());
    return copy;
  });

  const imageSlots = slots.filter((s) => isMediaImageSlot(s.id, s.role, s));
  if (imageSlots.length > 1) {
    const imagePrompts = {
      ...(next.imagePrompts && typeof next.imagePrompts === 'object' ? next.imagePrompts : {}),
    };
    const usedPrompts = new Set();
    imageSlots.forEach((slot, index) => {
      const slotId = String(slot.id);
      let prompt =
        imagePrompts[slotId] ||
        imagePrompts[slotId.toUpperCase()] ||
        buildSlotImagePrompt(slotId, next, layoutSchema) ||
        '';
      prompt = String(prompt).trim();
      const col = next[colsKey][index];
      const colTitle = col ? String(col.title ?? col.heading ?? '').trim() : '';
      if (!prompt || usedPrompts.has(prompt.toLowerCase())) {
        prompt = buildSlotImagePrompt(slotId, next, layoutSchema);
        if (!prompt && colTitle) {
          prompt = appendImageNegatives(
            `Single photograph, ONE subject only: ${shortVisualPhrase(colTitle, 8)} (variation ${index + 1})`,
            { hasChart: layoutHasChartSlot(layoutSchema) }
          );
        }
      }
      if (prompt && imagePromptEchoesCopy(prompt, next)) {
        prompt = buildSlotImagePrompt(slotId, next, layoutSchema);
      }
      prompt = appendImageNegatives(prompt, {
        isDevice: isDeviceScreenSlotId(slotId),
        hasChart: layoutHasChartSlot(layoutSchema),
      });
      prompt = withDeviceUiDirective(prompt, slotId, String(layoutSchema?.layout_id || ''));
      usedPrompts.add(prompt.toLowerCase());
      imagePrompts[slotId] = prompt;
    });
    next.imagePrompts = imagePrompts;
  }

  return next;
}

function listGalleryImageSlots(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots
    .filter((s) => {
      const id = String(s.id || '').toUpperCase();
      const role = String(s.role || '').toLowerCase();
      if (role !== 'image' && role !== 'background') return false;
      if (/^IMAGE_\d+$/.test(id)) return true;
      if (/^COL_\d+_IMAGE$/.test(id)) return true;
      if (/^METRIC_IMAGE_\d+$/.test(id)) return true;
      return false;
    })
    .sort(
      (a, b) =>
        Number(String(a.id).match(/\d+/)?.[0] || 0) - Number(String(b.id).match(/\d+/)?.[0] || 0)
    );
}

function layoutUsesPerSlotGalleryImages(layoutSchema) {
  const gallerySlots = listGalleryImageSlots(layoutSchema);
  if (gallerySlots.length < 2) return false;
  const slots = layoutSchema?.slots || [];
  const hasSingleHero = slots.some((s) => {
    const id = String(s.id || '').toUpperCase();
    return id === 'HERO_IMAGE' || id === 'BACKGROUND_IMAGE';
  });
  return !hasSingleHero;
}

function beatToColumn(entry, index, slideTitle) {
  if (typeof entry === 'string') {
    const text = entry.trim();
    const split = text.split(/[:\-–—]\s*/);
    return {
      title: split[0]?.trim() || titleWordsFromBody(text, `Highlight ${index + 1}`),
      body: split.slice(1).join(' ').trim() || text,
    };
  }
  if (entry && typeof entry === 'object') {
    return {
      title: String(entry.title ?? entry.label ?? entry.heading ?? entry.topic ?? '').trim() ||
        titleWordsFromBody(String(entry.body ?? entry.text ?? ''), `Highlight ${index + 1}`),
      body: String(entry.body ?? entry.text ?? entry.detail ?? entry.description ?? '').trim(),
    };
  }
  const title = String(slideTitle || 'Topic').trim();
  return {
    title: titleWordsFromBody(`${title} highlight ${index + 1}`, `Highlight ${index + 1}`),
    body: `On-topic visual for ${title}`,
  };
}

function normalizeGalleryImageContent(content, layoutSchema, options = {}) {
  const gallerySlots = listGalleryImageSlots(layoutSchema);
  if (gallerySlots.length < 2 || !content || typeof content !== 'object') return content;

  const outlineSlide =
    options.outlineSlide && typeof options.outlineSlide === 'object' ? options.outlineSlide : {};
  const deckContext =
    options.deckContext && typeof options.deckContext === 'object' ? options.deckContext : {};

  const needed = gallerySlots.length;
  const next = { ...content };
  if (!next.subtitle && outlineSlide.summary) {
    next.subtitle = String(outlineSlide.summary).trim();
  }
  if (!next.badge && (next.title || outlineSlide.title)) {
    next.badge = 'HIGHLIGHTS';
  }

  let columns = Array.isArray(content.columns) ? [...content.columns] : [];
  const outlineBeats = Array.isArray(outlineSlide.beats) ? outlineSlide.beats : [];
  const contentBeats = Array.isArray(content.beats) ? content.beats : [];
  const beats = outlineBeats.length >= needed ? outlineBeats : contentBeats;

  if (columns.length < needed) {
    const items = Array.isArray(content.items) ? content.items : [];
    const bullets = Array.isArray(content.bullets) ? content.bullets : [];
    const summary = String(
      content.summary ||
        content.body ||
        content.subtitle ||
        outlineSlide.summary ||
        ''
    ).trim();
    const parts = summary.split(/[.;]\s+/).map((part) => part.trim()).filter(Boolean);
    const slideTitle = String(content.title || outlineSlide.title || 'Topic').trim();

    if (beats.length >= needed) {
      columns = beats.slice(0, needed).map((beat, index) => beatToColumn(beat, index, slideTitle));
    } else if (items.length >= needed) {
      columns = items.slice(0, needed).map((item, index) => {
        if (typeof item === 'string') {
          const text = item.trim();
          const split = text.split(/[:\-â€”â€“]\s*/);
          return {
            title: split[0]?.trim() || titleWordsFromBody(text, `Item ${index + 1}`),
            body: split.slice(1).join(' ').trim() || text,
          };
        }
        return {
          title: String(item.title ?? item.label ?? item.heading ?? `Item ${index + 1}`).trim(),
          body: String(item.body ?? item.text ?? '').trim(),
        };
      });
    } else if (bullets.length >= 2) {
      columns = bullets.slice(0, needed).map((bullet, index) => {
        const text = typeof bullet === 'string' ? bullet.trim() : String(bullet?.text ?? bullet?.label ?? '').trim();
        const split = text.split(/[:\-â€”â€“]\s*/);
        return {
          title: split[0]?.trim() || titleWordsFromBody(text, `Item ${index + 1}`),
          body: split.slice(1).join(' ').trim() || text,
        };
      });
    } else if (parts.length >= 2) {
      columns = Array.from({ length: needed }, (_, index) => {
        const body = parts[index] || parts[index % parts.length] || summary.slice(0, 100);
        return {
          title: titleWordsFromBody(body, `Gallery ${index + 1}`),
          body,
        };
      });
    } else {
      const deckSnippet = shortVisualPhrase(
        deckContext.sourceText || deckContext.deckNarrative || summary || slideTitle,
        6
      );
      columns = Array.from({ length: needed }, (_, index) => ({
        title: titleWordsFromBody(
          deckSnippet ? `${deckSnippet} moment ${index + 1}` : `${slideTitle} moment ${index + 1}`,
          `Highlight ${index + 1}`
        ),
        body: deckSnippet
          ? `${deckSnippet} — visual ${index + 1}`
          : `Visual ${index + 1} illustrating ${slideTitle}`,
      }));
    }
  }

  const slideTitleLower = String(next.title || '').trim().toLowerCase();
  const seenTitles = new Set();
  next.columns = columns.slice(0, needed).map((col, index) => {
    const copy = col && typeof col === 'object' ? { ...col } : { title: '', body: '' };
    let title = String(copy.title ?? copy.heading ?? copy.label ?? '').trim();
    const body = String(copy.body ?? copy.text ?? '').trim();
    const titleLower = title.toLowerCase();
    if (!title || titleLower === slideTitleLower || seenTitles.has(titleLower)) {
      const fromBody = titleWordsFromBody(body, '');
      const fromBodyLower = String(fromBody || '').trim().toLowerCase();
      if (fromBody && fromBodyLower !== slideTitleLower && !seenTitles.has(fromBodyLower)) {
        title = fromBody;
      } else {
        title = `Gallery ${index + 1}`;
      }
      copy.title = title;
      if (copy.heading != null) copy.heading = title;
      if (copy.label != null) copy.label = title;
    }
    seenTitles.add(String(copy.title ?? title).trim().toLowerCase());
    if (body) copy.body = body;
    return copy;
  });

  const imagePrompts = {
    ...(next.imagePrompts && typeof next.imagePrompts === 'object' ? next.imagePrompts : {}),
  };
  const usedPrompts = new Set();
  const deckTheme = overallThemeSubject(next, deckContext) || '';
  gallerySlots.forEach((slot, index) => {
    const slotId = String(slot.id);
    const col = next.columns[index];
    const colTitle = col ? String(col.title ?? col.heading ?? col.label ?? '').trim() : '';
    const colBody = col ? String(col.body ?? col.text ?? col.description ?? '').trim() : '';
    let prompt = String(
      resolveImagePromptAlias(slotId, imagePrompts) || ''
    ).trim();
    if (!prompt || usedPrompts.has(prompt.toLowerCase())) {
      prompt = buildSlotImagePrompt(slotId, next, layoutSchema, deckContext);
    }
    if ((!prompt || imagePromptEchoesCopy(prompt, next)) && (colTitle || colBody)) {
      const subject = shortVisualPhrase(colTitle || colBody, 8);
      prompt = appendImageNegatives(
        [
          deckTheme ? `Same deck theme: ${deckTheme}` : null,
          `${slotId}: single photograph of ONE subject for this cardâ€™s topic`,
          `One isolated subject â€” ${subject}`,
          `(variation ${index + 1})`,
        ]
          .filter(Boolean)
          .join('. '),
        { hasChart: layoutHasChartSlot(layoutSchema) }
      );
    } else if (prompt && deckTheme && !prompt.toLowerCase().includes(deckTheme.toLowerCase().slice(0, 12))) {
      const slotSubject = shortVisualPhrase(colTitle || colBody, 6);
      prompt = `${deckTheme}. This slot: ${colTitle || slotSubject}. ${prompt}`;
    }
    if (prompt) {
      prompt = appendImageNegatives(prompt, {
        isDevice: isDeviceScreenSlotId(slotId),
        hasChart: layoutHasChartSlot(layoutSchema),
      });
      prompt = withDeviceUiDirective(prompt, slotId, String(layoutSchema?.layout_id || ''));
      usedPrompts.add(prompt.toLowerCase());
      imagePrompts[slotId] = prompt;
    }
  });
  next.imagePrompts = imagePrompts;

  return next;
}

function normalizeTimelineContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;

  const slots = layoutSchema.slots;
  const layoutId = String(layoutSchema.layout_id || '');
  const isTimeline =
    /timeline/i.test(layoutId) || slots.some((s) => /^milestone_/i.test(String(s.id || '')));
  if (!isTimeline) return content;

  const key = Array.isArray(content.timeline)
    ? 'timeline'
    : Array.isArray(content.milestones)
      ? 'milestones'
      : Array.isArray(content.events)
        ? 'events'
        : 'timeline';

  let items = Array.isArray(content[key]) ? [...content[key]] : [];
  if (items.length < 2 && Array.isArray(content.bullets) && content.bullets.length) {
    items = content.bullets.map((bullet) => {
      const text = typeof bullet === 'string' ? bullet : String(bullet?.text ?? bullet?.label ?? '');
      return text.trim();
    }).filter(Boolean);
  }

  const milestoneSlots = slots.filter(
    (s) => /^milestone_\d+$/i.test(String(s.id || '')) || /^milestone_\d+_label$/i.test(String(s.id || ''))
  );
  const needed = Math.max(2, milestoneSlots.length || 4);
  const summary = String(content.summary || content.body || content.subtitle || '').trim();
  const summaryParts = summary
    ? summary.split(/[.;]\s+/).map((part) => part.trim()).filter(Boolean)
    : [];

  const normalized = items.map((item, index) => {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      const yearOnly = /^\d{4}$/.test(trimmed);
      const split = trimmed.split(/[:\-â€”â€“]\s*/);
      const label = yearOnly ? trimmed : (split[0] || trimmed).trim();
      const inlineDetail = yearOnly ? '' : split.slice(1).join(' ').trim();
      const detail =
        inlineDetail ||
        summaryParts[index % Math.max(summaryParts.length, 1)] ||
        (summary ? summary.slice(0, 120) : `Key milestone ${index + 1}`);
      return { label, detail };
    }

    const copy = { ...item };
    let label = String(
      copy.label ?? copy.date ?? copy.year ?? copy.period ?? copy.title ?? copy.name ?? ''
    ).trim();
    let detail = String(copy.detail ?? copy.body ?? copy.text ?? copy.description ?? copy.summary ?? '').trim();
    if (!label) {
      label = String(copy.value ?? copy.head ?? `Phase ${index + 1}`).trim();
    }
    if (!detail) {
      detail =
        summaryParts[index % Math.max(summaryParts.length, 1)] ||
        (summary ? summary.slice(0, 120) : `Key development for ${label || `milestone ${index + 1}`}`);
    }
    return { ...copy, label, detail };
  });

  while (normalized.length < needed) {
    const n = normalized.length + 1;
    normalized.push({
      label: String(2010 + n * 3),
      detail: summaryParts[n % Math.max(summaryParts.length, 1)] || summary.slice(0, 100) || `Milestone ${n}`,
    });
  }

  const imageSlots = slots.filter((s) => {
    const id = String(s.id || '').toUpperCase();
    return String(s.role || '').toLowerCase() === 'image' || /^IMAGE_\d+$/.test(id);
  });

  const next = {
    ...content,
    [key]: normalized,
    timeline: key === 'timeline' ? normalized : content.timeline || normalized,
  };

  if (
    imageSlots.length > 1 &&
    (!Array.isArray(content.columns) || content.columns.length < imageSlots.length)
  ) {
    next.columns = normalized.slice(0, imageSlots.length).map((item) => ({
      title: String(item.label ?? item.title ?? item.period ?? '').trim(),
      body: String(item.detail ?? item.body ?? item.text ?? '').trim(),
    }));
  }

  return next;
}

function layoutNeedsDiagramCellsFromSchema(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((slot) => {
    const id = String(slot.id || '').toLowerCase();
    return /^q\d+_body$/i.test(id) || /^funnel_\d+_body$/i.test(id) || /^step_\d+_body$/i.test(id);
  });
}

function countDiagramCellSlotsFromSchema(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const quadrantBodies = slots.filter((s) => /^q\d+_body$/i.test(String(s.id || ''))).length;
  const funnelBodies = slots.filter((s) => /^funnel_\d+_body$/i.test(String(s.id || ''))).length;
  const stepBodies = slots.filter((s) => /^step_\d+_body$/i.test(String(s.id || ''))).length;
  return Math.max(quadrantBodies, funnelBodies, stepBodies, 0);
}

function schemaTitleForDiagramSlot(slots, index, kind) {
  if (kind === 'quadrant') {
    const slot = slots.find((s) => String(s.id).toUpperCase() === `Q${index + 1}_TITLE`);
    return slot?.placeholder_text ? String(slot.placeholder_text).trim() : '';
  }
  if (kind === 'funnel') {
    const slot = slots.find((s) => String(s.id).toLowerCase() === `funnel_${index + 1}_title`);
    return slot?.placeholder_text ? String(slot.placeholder_text).trim() : '';
  }
  const slot = slots.find((s) => String(s.id).toLowerCase() === `step_${index + 1}_title`);
  return slot?.placeholder_text ? String(slot.placeholder_text).trim() : '';
}

function diagramCellsSourceForKind(content, kind) {
  if (!content || typeof content !== 'object') return null;
  if (kind === 'quadrant') {
    return content.quadrants || content.diagram?.cells || content.cells || content.steps || content.funnel;
  }
  if (kind === 'funnel') {
    return content.funnel || content.diagram?.cells || content.cells || content.quadrants || content.steps;
  }
  return content.steps || content.diagram?.cells || content.cells || content.quadrants || content.funnel;
}

function countDeviceFeatureSlotsFromSchema(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const featureHeads = slots.filter((s) => /^FEATURE_[LR]\d+_HEADING$/i.test(String(s.id || ''))).length;
  const sideHeads = slots.filter((s) => /^HEADING_[LR]$/i.test(String(s.id || ''))).length;
  return Math.max(featureHeads, sideHeads, 0);
}

/**
 * Ensure device layouts get columns[] / multi-line title aligned to FEATURE_* / HEADING_L slots.
 */
function normalizeDeviceContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const layoutId = String(layoutSchema.layout_id || '').toLowerCase();
  if (!/device_|grid_device/.test(layoutId) && String(layoutSchema.content_type || '').toLowerCase() !== 'device_frames') {
    return content;
  }

  let next = { ...content };
  const needed = countDeviceFeatureSlotsFromSchema(layoutSchema);
  const existingCols = Array.isArray(next.columns)
    ? next.columns
    : Array.isArray(next.features)
      ? next.features
      : Array.isArray(next.cards)
        ? next.cards
        : [];

  if (needed > 0) {
    const bullets = Array.isArray(next.bullets) ? next.bullets : [];
    const items = Array.isArray(next.items) ? next.items : [];
    const cols = [];
    for (let i = 0; i < needed; i += 1) {
      const col = existingCols[i];
      if (col && typeof col === 'object') {
        cols.push({
          title: String(col.title ?? col.heading ?? col.label ?? '').trim(),
          body: String(col.body ?? col.text ?? '').trim(),
        });
        continue;
      }
      if (typeof col === 'string' && col.trim()) {
        cols.push({ title: col.trim().split(/\s+/).slice(0, 4).join(' '), body: col.trim() });
        continue;
      }
      const bullet = bullets[i];
      if (bullet) {
        const text = typeof bullet === 'string' ? bullet.trim() : String(bullet?.text ?? bullet?.label ?? '').trim();
        cols.push({
          title: text.split(/\s+/).slice(0, 4).join(' ') || `Aspect ${i + 1}`,
          body: text,
        });
        continue;
      }
      const item = items[i];
      if (item) {
        if (typeof item === 'string') {
          cols.push({ title: item.split(/\s+/).slice(0, 4).join(' '), body: item.trim() });
        } else {
          cols.push({
            title: String(item.title ?? item.heading ?? item.label ?? `Aspect ${i + 1}`).trim(),
            body: String(item.body ?? item.text ?? item.detail ?? '').trim(),
          });
        }
        continue;
      }
      cols.push({ title: '', body: '' });
    }
    if (cols.some((c) => c.title || c.body)) {
      next = { ...next, columns: cols };
    }
  }

  // Multi-cluster: merge two-line title so finalize can strip HEADING_2 safely.
  if (/device_multi_cluster/i.test(layoutId)) {
    const title = String(next.title || '').trim();
    const parts = title.split(/\n+/).map((s) => s.trim()).filter(Boolean);
    if (parts.length < 2) {
      const runs = Array.isArray(next.titleRuns)
        ? next.titleRuns.map((r) => String(r?.text || '').trim()).filter(Boolean)
        : [];
      if (runs.length >= 2) {
        next = { ...next, title: `${runs[0]}\n${runs.slice(1).join(' ')}` };
      }
    }
  }

  return next;
}

function normalizeDiagramContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const slots = layoutSchema.slots;
  if (!layoutNeedsDiagramCellsFromSchema(layoutSchema)) return content;

  const kind = slots.some((s) => /^q\d+_body$/i.test(String(s.id || '')))
    ? 'quadrant'
    : slots.some((s) => /^funnel_\d+_body$/i.test(String(s.id || '')))
      ? 'funnel'
      : 'step';

  const existing = diagramCellsSourceForKind(content, kind);
  const explicitType = String(content.diagram?.type || '').trim();
  const hasValidCells =
    Array.isArray(existing) &&
    existing.some((cell) => {
      const body = String(cell?.body ?? cell?.text ?? cell?.detail ?? '').trim();
      return body && !isCatalogPlaceholderText(body);
    });
  if (hasValidCells) {
    const cells = [...existing];
    return {
      ...content,
      diagram: {
        ...(content.diagram || {}),
        type: explicitType || content.diagram?.type || kind,
        cells,
      },
      cells,
    };
  }

  const needed = Math.max(2, countDiagramCellSlotsFromSchema(layoutSchema) || 4);

  const sourceCols = content.columns || content.cards || content.features || [];
  const sourceBullets = Array.isArray(content.bullets) ? content.bullets : [];
  const sourceItems = Array.isArray(content.items) ? content.items : [];
  const sourceBeats = Array.isArray(content.beats) ? content.beats : [];
  const summaryParts = String(content.summary || content.body || content.subtitle || '')
    .split(/[.;]\s+/)
    .map((part) => part.trim())
    .filter(Boolean);

  const sourceCount = Math.max(
    Array.isArray(sourceCols) ? sourceCols.filter(Boolean).length : 0,
    sourceBullets.filter(Boolean).length,
    sourceItems.filter(Boolean).length,
    sourceBeats.filter(Boolean).length,
    0
  );
  // Prefer matching layout slot count to real beats â€” do not invent filler steps from summary.
  const cellTarget =
    sourceCount > 0 && sourceCount < needed ? sourceCount : needed;

  const cells = [];
  for (let i = 0; i < cellTarget; i += 1) {
    const schemaTitle = schemaTitleForDiagramSlot(slots, i, kind);
    let title = schemaTitle;
    let body = '';

    const beat = sourceBeats[i];
    if (beat != null) {
      if (typeof beat === 'string') {
        body = beat.trim();
        title = titleWordsFromBody(body, schemaTitle || `Step ${i + 1}`);
      } else if (typeof beat === 'object') {
        title =
          String(beat.label || beat.title || beat.heading || schemaTitle).trim() || schemaTitle;
        body = String(beat.text || beat.body || beat.detail || '').trim();
      }
    }

    const col = sourceCols[i];
    if ((!body || !title || title === schemaTitle) && col && typeof col === 'object') {
      title = String(col.title ?? col.heading ?? col.label ?? schemaTitle).trim() || schemaTitle;
      body = String(col.body ?? col.text ?? '').trim() || body;
    } else if (!body && sourceItems[i]) {
      const item = sourceItems[i];
      if (typeof item === 'string') {
        body = item.trim();
        title = titleWordsFromBody(body, schemaTitle || `Point ${i + 1}`);
      } else {
        title = String(item.title ?? item.heading ?? item.label ?? schemaTitle).trim();
        body = String(item.body ?? item.text ?? item.detail ?? '').trim();
      }
    } else if (!body && sourceBullets[i]) {
      const bullet = sourceBullets[i];
      body = typeof bullet === 'string' ? bullet.trim() : String(bullet?.text ?? bullet?.label ?? '').trim();
      title = titleWordsFromBody(body, schemaTitle || `Point ${i + 1}`);
    }

    if (!body && sourceCount === 0) {
      body = summaryParts[i % Math.max(summaryParts.length, 1)] || '';
    }
    if (!title) title = schemaTitle || `Section ${i + 1}`;

    cells.push({ title, body });
  }

  const slideTitleLower = String(content.title || '').trim().toLowerCase();
  const seen = new Set();
  for (let i = 0; i < cells.length; i += 1) {
    let title = String(cells[i].title || '').trim();
    const body = String(cells[i].body || '').trim();
    const titleLower = title.toLowerCase();
    if (!title || titleLower === slideTitleLower || seen.has(titleLower)) {
      const fromBody = titleWordsFromBody(body, '');
      const fromBodyLower = String(fromBody || '').toLowerCase();
      title =
        fromBody && fromBodyLower !== slideTitleLower && !seen.has(fromBodyLower)
          ? fromBody
          : `Section ${i + 1}`;
      cells[i] = { ...cells[i], title };
    }
    seen.add(String(cells[i].title || '').trim().toLowerCase());
  }

  return {
    ...content,
    diagram: { ...(content.diagram || {}), type: explicitType || kind, cells },
    cells,
  };
}
function chartInsightBody(content = {}, chart = {}) {
  const labels = Array.isArray(chart.labels) ? chart.labels : [];
  const values = chart.series?.[0]?.values || chart.data || chart.values || [];
  const lead = labels[0] ? String(labels[0]) : 'The leading category';
  const topValue = values[0] != null ? String(values[0]) : '';
  const topic = String(content.title || 'this topic').trim();
  if (lead && topValue) {
    return `${lead} leads ${topic.toLowerCase()} at ${topValue}, with the remaining categories spread across the chart. Use this split to highlight concentration and opportunity.`;
  }
  return `This chart summarizes the key quantitative story behind ${topic}. Keep the insight scannable in three to four lines.`;
}

function normalizeChartContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const slots = layoutSchema.slots;
  const chartSlots = slots.filter((slot) => String(slot.role || '').toLowerCase() === 'chart');
  if (!chartSlots.length || !content.chart || typeof content.chart !== 'object') return content;

  const next = { ...content };
  const chart = { ...next.chart };
  chart.type = inferChartTypeFromStory(chart, next, layoutSchema);
  next.chart = chart;

  const hasBodySlot = slots.some((slot) => String(slot.role || '').toLowerCase() === 'body');
  const analysis = analyzeChartStory(next);
  if (hasBodySlot && chartSlots.length === 1 && analysis.needsBody && !String(next.body || '').trim()) {
    next.body = chartInsightBody(next, chart);
  }

  return next;
}

module.exports = {
  runContentPreShape,
  normalizeAgendaContent,
  normalizeMultiColumnContent,
  normalizeGalleryImageContent,
  normalizeChartContent,
  normalizeTimelineContent,
  normalizeDiagramContent,
  normalizeDeviceContent,
  normalizeComparisonProsConsContent,
  layoutUsesPerSlotGalleryImages,
  isComparisonProsConsLayoutId,
  layoutNeedsDiagramCellsFromSchema,
  countDiagramCellSlotsFromSchema,
};
