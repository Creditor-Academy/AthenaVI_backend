/**
 * Hyperlinks in text boxes, for exports. Mirrors the editor's src/utils/textLinks.js:
 * a run's stored `href`, plus web addresses ("https://…", "www.…") found in plain text.
 * Only http(s), mailto and tel links are ever written out: hrefs come from user content.
 */

const SAFE_SCHEME = /^(https?:|mailto:|tel:)/i;
const URL_IN_TEXT = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;

function safeLinkHref(value) {
  const raw = String(value ?? '').trim();
  if (!raw || !SAFE_SCHEME.test(raw)) return null;
  try {
    const url = new URL(raw);
    return SAFE_SCHEME.test(url.protocol) ? raw : null;
  } catch {
    return null;
  }
}

function trimUrlEnd(url) {
  let out = url;
  const pairs = { ')': '(', ']': '[', '}': '{' };
  for (;;) {
    const last = out[out.length - 1];
    if (/[.,;:!?'"]/.test(last)) {
      out = out.slice(0, -1);
      continue;
    }
    if (pairs[last] && out.split(last).length > out.split(pairs[last]).length) {
      out = out.slice(0, -1);
      continue;
    }
    return out;
  }
}

/** Plain text → pieces, the web addresses in it carrying an `href`. */
function splitTextLinks(text) {
  const value = String(text ?? '');
  if (!value) return [];
  const pieces = [];
  let cursor = 0;
  for (const match of value.matchAll(URL_IN_TEXT)) {
    const url = trimUrlEnd(match[0]);
    const href = safeLinkHref(/^www\./i.test(url) ? `https://${url}` : url);
    if (!href || url.length < 5) continue;
    if (match.index > cursor) pieces.push({ text: value.slice(cursor, match.index) });
    pieces.push({ text: url, href });
    cursor = match.index + url.length;
  }
  if (cursor < value.length) pieces.push({ text: value.slice(cursor) });
  return pieces;
}

/** Runs with their links resolved: stored (safe) hrefs kept, web addresses in the text split out. */
function linkedRuns(runs) {
  const out = [];
  for (const run of runs || []) {
    const text = run?.text == null ? '' : String(run.text);
    if (!text) continue;
    const stored = run?.href ? safeLinkHref(run.href) : null;
    if (stored) {
      out.push({ ...run, text, href: stored });
      continue;
    }
    const rest = { ...run };
    delete rest.href;
    for (const piece of splitTextLinks(text)) {
      out.push(piece.href ? { ...rest, text: piece.text, href: piece.href } : { ...rest, text: piece.text });
    }
  }
  return out;
}

module.exports = { safeLinkHref, splitTextLinks, linkedRuns };
