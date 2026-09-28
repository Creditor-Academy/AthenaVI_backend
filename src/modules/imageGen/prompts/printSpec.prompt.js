const SCHEMA_HINT = {
  headline:
    'string (required) — poster/invitation title, or the person’s name on a business card',
  subheadline:
    'optional — tagline / host line, or job title and company on a business card',
  details:
    'array of short verbatim lines (date, time, venue, RSVP, phone, email, website, address); empty array when none',
  cta: 'optional short call to action; empty string when not needed or not allowed',
  visualSubject: 'string (required) — the artwork: subject, motif, or background imagery',
  composition: 'optional — where the headline, details, and artwork sit on the page',
  visualStyle: 'optional free-text appearance guidance; leave empty if none asked',
  palette: 'optional hex color array',
  constraints: {
    doNotInventNumbers: true,
    doNotInventContactDetails: true,
    language: 'en',
    tone: 'optional',
  },
};

const KIND_GUIDANCE = Object.freeze({
  poster: 'A printed poster: one strong headline, optional subheadline, a few detail lines, optional call to action.',
  business_card:
    'The FRONT of a business card: headline = the person’s full name (or brand name if no person); subheadline = job title and company; details = contact lines (phone, email, website, address) exactly as given. No call to action.',
  invitation:
    'A printed invitation card: headline = event title; subheadline = host or invitation line; details = date, time, venue, dress code, RSVP exactly as given.',
});

function buildSystem() {
  return [
    'You produce PrintSpec JSON for an image model that renders one flat, print-ready design.',
    'The user describes what they want in free text. Turn it into final printed copy',
    'and a clear visual direction for the chosen print size.',
    '',
    'Copy rules (strict):',
    '1. Keep any wording, names, prices, dates, times, addresses, and numbers the user wrote VERBATIM.',
    '2. Facts from attached context must appear VERBATIM; never contradict or “improve” them.',
    '3. NEVER invent phone numbers, emails, websites, addresses, dates, prices, or statistics.',
    '   If a detail was not supplied, leave it out rather than using a placeholder.',
    '4. Respect the character and line limits given for this size. When a limit is 0, return an empty string.',
    '5. Use the language the user wrote in unless they ask for another one.',
    '',
    'Visual rules:',
    '- visualSubject describes artwork that suits the message and can be printed flat (no mockups).',
    '- composition must keep all text inside the safe margin given below.',
    '- Leave visualStyle empty unless the user or StyleHint gave style language.',
    '- Return ONLY valid JSON matching the schema hint.',
  ].join('\n');
}

function describeLimits(limits = {}) {
  return [
    `headline ≤ ${limits.headline ?? 60} chars`,
    `subheadline ≤ ${limits.subheadline ?? 100} chars`,
    `details ≤ ${limits.details ?? 4} lines of ≤ ${limits.detailLine ?? 80} chars`,
    `cta ≤ ${limits.cta ?? 40} chars`,
  ].join(', ');
}

function describeSize(format) {
  const size = format.widthIn
    ? `${format.widthIn} x ${format.heightIn} in`
    : `${Math.round(format.widthMm)} x ${Math.round(format.heightMm)} mm`;
  return `${format.name}, ${size} ${format.orientation}`;
}

function buildUser({
  userPrompt,
  contextText = '',
  styleHint = null,
  brandPalette = null,
  format,
} = {}) {
  const parts = [
    `Print size: ${describeSize(format)}`,
    `Item: ${KIND_GUIDANCE[format.kind] || KIND_GUIDANCE.poster}`,
    `Safe margin: ${format.safeZone}`,
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
    'Return a single PrintSpec JSON object.',
    'Every piece of text that will be printed must be exact and final.'
  );

  return parts.join('\n');
}

function buildCorrectiveUser(previousErrors) {
  const errText = Array.isArray(previousErrors)
    ? previousErrors.map((e) => (typeof e === 'string' ? e : e.message || String(e))).join('; ')
    : String(previousErrors || 'schema validation failed');
  return [
    'Your previous PrintSpec failed validation.',
    `Errors: ${errText}`,
    'Return a corrected PrintSpec JSON that satisfies the schema.',
    'Keep the same message and facts; fix structure only.',
  ].join('\n');
}

module.exports = {
  SCHEMA_HINT,
  buildSystem,
  buildUser,
  buildCorrectiveUser,
  describeLimits,
  describeSize,
};
