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
  /^add (your )?text here\.?$/i,
  /^click to (add|edit)( text)?\.?$/i,
  /^type here\.?$/i,
  /^option [ab]$/i,
  /^metric [ab]$/i,
  /^this is a sample description for metric/i,
  /^lorem ipsum$/i,
  /^lorem ipsum is simply dummy/i,
  /^step \d+$/i,
  /^phase \d+$/i,
  /^describe this feature\.?$/i,
  /^market share$/i,
  /^metric [a-d]$/i,
  /^represents the largest share of the market/i,
  /^maintains a steady presence with consistent growth/i,
  /^shows gradual progress and increasing contribution/i,
  /^remains a significant part of the market with stable performance/i,
  // grid_insights_chart_* sample copy
  /^insight \d+$/i,
  /^revenue growth$/i,
  /^monthly performance$/i,
  /^key takeaway$/i,
  // timeline_* diagram sample copy
  /insert your desired text here/i,
  /this is a sample text/i,
  /^lorem ipsum dolor sit amet/i,
  /^bring your presentation to life/i,
  /^option 0?\d+$/i,
  /^milestone 0?\d+$/i,
  /^phase 0\d$/i,
  /^stage \d+: (master plan|permits|design|schedule|build)$/i,
];

const LAYOUT_ENGINE_DEFAULT_EXACT = new Set(
  [
    'MARKET SHARE',
    'Metric A',
    'Metric B',
    'Metric C',
    'Metric D',
    'Describe this feature',
    'Market share',
    'TOTAL',
    '100%',
  ].map((s) => s.toLowerCase())
);

function isLayoutEngineDefaultText(text) {
  const t = String(text || '').trim();
  if (!t) return false;
  if (LAYOUT_ENGINE_DEFAULT_EXACT.has(t.toLowerCase())) return true;
  return isCatalogPlaceholderText(t);
}

function isCatalogPlaceholderText(text) {
  const t = String(text || '').trim();
  if (!t) return false;
  const lower = t.toLowerCase();
  return CATALOG_PLACEHOLDER_PATTERNS.some((re) => re.test(lower));
}

module.exports = {
  isCatalogPlaceholderText,
  isLayoutEngineDefaultText,
  CATALOG_PLACEHOLDER_PATTERNS,
};
