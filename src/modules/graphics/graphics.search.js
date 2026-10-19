function tokenize(value) {
  return String(value || '')
    .toLowerCase()
    .split(/[^a-z0-9]+/i)
    .map((t) => t.trim())
    .filter((t) => t.length > 1);
}

function arrayScore(haystack, needles) {
  if (!needles.length) return 0;
  const set = new Set((haystack || []).map((v) => String(v).toLowerCase()));
  let hits = 0;
  for (const n of needles) {
    if (set.has(n)) hits += 1;
  }
  return hits;
}

function textScore(text, keywords) {
  const hay = tokenize(text);
  if (!hay.length || !keywords.length) return 0;
  const set = new Set(hay);
  let hits = 0;
  for (const k of keywords) {
    if (set.has(k)) hits += 2;
    else if (hay.some((h) => h.includes(k) || k.includes(h))) hits += 1;
  }
  return hits;
}

/**
 * Rank published GraphicAsset rows from visual intent.
 * AI produces intent; this function picks assets.
 */
function searchGraphics(published = [], intent = {}, theme = null) {
  const keywords = (intent.keywords || []).map((k) => String(k).toLowerCase().trim()).filter(Boolean);
  const style = intent.style ? String(intent.style).toLowerCase() : '';
  const mood = intent.mood ? String(intent.mood).toLowerCase() : '';
  const preferredType = intent.preferredType ? String(intent.preferredType) : '';
  const usage = intent.usage ? String(intent.usage).toLowerCase() : '';
  const maxCount = Math.max(1, Math.min(8, Number(intent.maxCount) || 4));
  const preferRecolor = Boolean(theme?.palette);

  const scored = published.map((g) => {
    let score = 0;
    score += textScore(`${g.name} ${g.description || ''}`, keywords);
    score += arrayScore(g.tags, keywords) * 3;
    if (style && String(g.style || '').toLowerCase() === style) score += 4;
    if (mood && (g.moods || []).map((m) => String(m).toLowerCase()).includes(mood)) score += 4;
    if (usage && (g.usage || []).map((u) => String(u).toLowerCase()).includes(usage)) score += 5;
    if (preferredType && g.type === preferredType) score += 5;
    if (preferRecolor && g.colorMode === 'recolorable') score += 2;
    if ((g.usage || []).includes('editor')) score += 1;
    return { graphic: g, score };
  });

  scored.sort((a, b) => b.score - a.score || String(a.graphic.name).localeCompare(b.graphic.name));
  const minScore = keywords.length || style || mood || usage || preferredType ? 1 : 0;
  return scored
    .filter((row) => row.score >= minScore)
    .slice(0, maxCount)
    .map((row) => row.graphic);
}

module.exports = { searchGraphics };
