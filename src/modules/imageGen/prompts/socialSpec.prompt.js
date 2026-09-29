const SCHEMA_HINT = {
  headline: 'string (required) — the main on-image text',
  supportingText: 'optional short supporting line; empty string when the destination allows none',
  cta: 'optional short call to action; empty string when not needed or not allowed',
  visualSubject: 'string (required) — what the image shows (subject, scene, props)',
  composition: 'optional — where the subject and text sit on the canvas',
  visualStyle: 'optional free-text appearance guidance; leave empty if none asked',
  palette: 'optional hex color array',
  constraints: { doNotInventNumbers: true, language: 'en', tone: 'optional' },
};

function buildSystem() {
  return [
    'You produce SocialPostSpec JSON for an image model that renders a single social media graphic.',
    'The user describes what they want in free text. Turn it into short, final on-image copy',
    'and a clear visual direction for the chosen platform destination.',
    '',
    'Copy rules (strict):',
    '1. Keep any wording, names, prices, dates, and numbers the user wrote VERBATIM.',
    '2. Facts from attached context must appear VERBATIM; never contradict or “improve” them.',
    '3. NEVER invent prices, discounts, dates, statistics, or company metrics that were not supplied.',
    '4. Write punchy, legible copy. Respect the character limits given for this destination.',
    '   When a limit is 0, return an empty string for that field.',
    '5. Use the language the user wrote in unless they ask for another one.',
    '',
    'Visual rules:',
    '- visualSubject describes one clear focal subject that suits the message.',
    '- composition must respect the destination safe zone given below.',
    '- Leave visualStyle empty unless the user or StyleHint gave style language.',
    '- Return ONLY valid JSON matching the schema hint.',
  ].join('\n');
}

function describeLimits(limits = {}) {
  return [
    `headline ≤ ${limits.headline ?? 60} chars`,
    `supportingText ≤ ${limits.supportingText ?? 100} chars`,
    `cta ≤ ${limits.cta ?? 24} chars`,
  ].join(', ');
}

function buildUser({
  userPrompt,
  contextText = '',
  styleHint = null,
  brandPalette = null,
  format,
} = {}) {
  const parts = [
    `Destination: ${format.name} (${format.platform}), ${format.width}x${format.height} px`,
    `Safe zone: ${format.safeZone}`,
    `Copy limits: ${describeLimits(format.textLimits)}`,
  ];

  if (styleHint && String(styleHint).trim()) {
    parts.push(
      `StyleHint (seed visualStyle; do not invent a house style beyond this): ${String(styleHint).trim()}`
    );
  } else {
    parts.push('StyleHint: none — leave visualStyle empty or minimal.');
  }

  if (Array.isArray(brandPalette) && brandPalette.length) {
    parts.push(`Brand palette (use as palette): ${brandPalette.join(', ')}`);
  }

  parts.push('', 'User request:', String(userPrompt || '').trim());

  if (contextText && String(contextText).trim()) {
    parts.push('', 'Attached context (factual source of truth):', String(contextText).trim());
  }

  parts.push(
    '',
    'Return a single SocialPostSpec JSON object.',
    'Every piece of text that will appear in the image must be exact and final.'
  );

  return parts.join('\n');
}

function buildCorrectiveUser(previousErrors) {
  const errText = Array.isArray(previousErrors)
    ? previousErrors.map((e) => (typeof e === 'string' ? e : e.message || String(e))).join('; ')
    : String(previousErrors || 'schema validation failed');
  return [
    'Your previous SocialPostSpec failed validation.',
    `Errors: ${errText}`,
    'Return a corrected SocialPostSpec JSON that satisfies the schema.',
    'Keep the same message and facts; fix structure only.',
  ].join('\n');
}

module.exports = {
  SCHEMA_HINT,
  buildSystem,
  buildUser,
  buildCorrectiveUser,
  describeLimits,
};
