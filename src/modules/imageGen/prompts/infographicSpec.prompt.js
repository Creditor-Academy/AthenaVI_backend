const SCHEMA_HINT = {
  title: 'string (required)',
  titleAccent: 'optional substring of title to accent visually',
  subtitle: 'optional string',
  sections:
    'array of { id, number?, label, body?, metric?, color?, iconHint?, chips?, emphasize? } — XOR with flows',
  flows:
    'array of { id, label, sections: [...] } for parallel lanes (e.g. comparison) — XOR with sections',
  sidebar: 'optional { title?, body?, items? }',
  notes: 'optional array of { title?, body }',
  footerFlow: 'optional { items: [{ label, iconHint? }] }',
  archetype: 'process | timeline | comparison | stats | hierarchy | list | cycle',
  orientation: 'square | landscape | portrait (may be set by server)',
  visualStyle: 'optional free-text appearance guidance; leave empty if none asked',
  palette: 'optional hex color array',
  constraints: { doNotInventNumbers: true, language: 'en', tone: 'optional' },
};

function buildSystem() {
  return [
    'You produce InfographicSpec JSON for a typesetting image model.',
    'You are topic-agnostic and design-agnostic: structure content to match what the user asked,',
    'do not impose a house visual style, and leave visualStyle empty unless the user gave style language.',
    '',
    'Data rules (strict):',
    '1. Numbers and facts written in the user prompt must appear VERBATIM in the spec.',
    '2. Numbers and facts from attached context must appear VERBATIM; never contradict or “improve” them.',
    '3. If a needed PUBLIC / general-knowledge fact is missing (e.g. country population, well-known dates),',
    '   you MAY fill it from model knowledge.',
    '4. NEVER invent private or company-specific metrics that were not supplied.',
    '   For those, omit the metric or use "—".',
    '',
    'Structure rules:',
    '- Pick the archetype that matches the content shape (process, timeline, comparison, stats,',
    '  hierarchy, list, cycle). If archetypeHint is provided, treat it as a hard instruction.',
    '- Use sections for a single sequence/grid. Use flows for parallel lanes (e.g. A vs B process).',
    '- Provide either sections OR flows, never both, never neither.',
    '- Keep labels short and readable. Respect maxSections.',
    '- Return ONLY valid JSON matching the schema hint.',
  ].join('\n');
}

function buildUser({
  userPrompt,
  contextText = '',
  archetypeHint = null,
  styleHint = null,
  orientation = 'landscape',
  maxSections = 10,
} = {}) {
  const parts = [
    `Orientation: ${orientation}`,
    `Max content items (sections total, or sum across all flows): ${maxSections}`,
  ];

  if (archetypeHint) {
    parts.push(
      `ArchetypeHint (HARD instruction — you MUST use this archetype): ${archetypeHint}`
    );
  } else {
    parts.push('ArchetypeHint: none — pick the best-fitting archetype from the content.');
  }

  if (styleHint && String(styleHint).trim()) {
    parts.push(
      `StyleHint (seed visualStyle; do not invent a house style beyond this): ${String(styleHint).trim()}`
    );
  } else {
    parts.push('StyleHint: none — leave visualStyle empty or minimal.');
  }

  parts.push('', 'User request:', String(userPrompt || '').trim());

  if (contextText && String(contextText).trim()) {
    parts.push('', 'Attached context (factual source of truth):', String(contextText).trim());
  }

  parts.push(
    '',
    'Return a single InfographicSpec JSON object.',
    'Every label, body, and metric that will appear in the image must be exact and final.'
  );

  return parts.join('\n');
}

function buildCorrectiveUser(previousErrors) {
  const errText = Array.isArray(previousErrors)
    ? previousErrors.map((e) => (typeof e === 'string' ? e : e.message || String(e))).join('; ')
    : String(previousErrors || 'schema validation failed');
  return [
    'Your previous InfographicSpec failed validation.',
    `Errors: ${errText}`,
    'Return a corrected InfographicSpec JSON that satisfies the schema.',
    'Keep the same factual content; fix structure only.',
  ].join('\n');
}

module.exports = {
  SCHEMA_HINT,
  buildSystem,
  buildUser,
  buildCorrectiveUser,
};
