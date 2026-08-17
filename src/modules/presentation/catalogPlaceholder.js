/** Catalog / seed layout placeholder strings that must not survive AI generation. */

const CATALOG_PLACEHOLDER_PATTERNS = [
  /^two to three lines explaining this section\.?$/i,
  /supporting paragraph with three to four lines/i,
  /scannable copy that explains the key idea/i,
  /^we help teams turn complex ideas into clear narratives/i,
  /^our approach combines research, design, and storytelling/i,
  /^from first draft to final delivery/i,
  /^the result is a deck that feels polished/i,
  /^key strengths$/i,
  /^areas to improve$/i,
  /^market opportunities$/i,
  /^external risks$/i,
  /^high impact · easy$/i,
  /^high impact · hard$/i,
  /^low impact · easy$/i,
  /^low impact · hard$/i,
  /^feature [abc]$/i,
  /^product (one|two)$/i,
  /^stage \d+$/i,
  /^\d+\. step \d+$/i,
  /^0\d · /i,
  /^double-?click to edit$/i,
];

function isCatalogPlaceholderText(text) {
  const t = String(text || '').trim();
  if (!t) return false;
  const lower = t.toLowerCase();
  return CATALOG_PLACEHOLDER_PATTERNS.some((re) => re.test(lower));
}

module.exports = {
  isCatalogPlaceholderText,
  CATALOG_PLACEHOLDER_PATTERNS,
};
