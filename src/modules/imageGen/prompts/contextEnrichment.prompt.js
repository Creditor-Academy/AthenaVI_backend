/**
 * Build a prompt enrichment block from parsed context materials.
 */
function buildEnrichmentBlock({
  inlineText = '',
  documents = [],
  images = [],
} = {}) {
  const parts = [];

  if (inlineText && String(inlineText).trim()) {
    parts.push(String(inlineText).trim());
  }

  for (const doc of documents) {
    const name = doc.name || 'document';
    const text = doc.text || doc.excerpt || '';
    if (!text) continue;
    parts.push(`[Document: ${name}]\n${String(text).trim()}`);
  }

  images.forEach((img, index) => {
    const summary = img.summary || '';
    if (!summary) return;
    const label = img.name ? ` (${img.name})` : '';
    parts.push(`Reference image ${index + 1}${label}: ${String(summary).trim()}`);
  });

  if (!parts.length) return '';

  return [
    '--- User reference context ---',
    ...parts,
    '--- End reference context ---',
  ].join('\n\n');
}

function appendContextBlock(basePrompt, enrichmentBlock) {
  const base = String(basePrompt || '').trim();
  const block = String(enrichmentBlock || '').trim();
  if (!block) return base;
  if (!base) return block;
  return `${block}\n\n${base}`;
}

/**
 * When using images.edit with refs, remind the model which index is which.
 */
function withReferenceImageIndexHints(prompt, imageCount) {
  const n = Number(imageCount) || 0;
  if (n <= 0) return String(prompt || '');
  const lines = [];
  for (let i = 1; i <= n; i += 1) {
    lines.push(`Image ${i}: reference image ${i} (use as visual context; do not copy unless asked).`);
  }
  return `${lines.join('\n')}\n\n${String(prompt || '').trim()}`;
}

module.exports = {
  buildEnrichmentBlock,
  appendContextBlock,
  withReferenceImageIndexHints,
};
