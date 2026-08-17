const LAYOUTS = [
  'process',
  'comparison',
  'timeline',
  'stats',
  'hierarchy',
  'funnel',
  'custom',
];

const PLAN_SCHEMA = {
  title: 'string',
  subtitle: 'string',
  layout: LAYOUTS.join('|'),
  regions: [
    {
      type: 'header|flowRow|sidebar|footer|note',
      title: 'string',
      steps: [
        {
          number: '01',
          heading: 'string',
          body: 'one short sentence',
          icon: 'concrete icon description',
        },
      ],
    },
  ],
  exactText: ['every string that must appear on the canvas'],
  expectedStepCount: 0,
  metrics: ['numeric values for funnel/stats, in display order'],
  palette: ['hex or color names'],
  characterNotes: 'reuse the same actor/icon characters across rows',
};

function buildSystem() {
  return [
    'You plan a professional flat-vector infographic for a text-rendering image model.',
    'You decide layout regions and on-canvas copy. The image model only typesets your spec.',
    'Return JSON only matching the schema. Do not invent a new topic.',
    'VERBATIM: if the user provided infographic.sections, keep each section title and bullet text exactly — do not paraphrase.',
    'If the user only gave a freeform brief, invent clear structured copy (short body: one sentence per step).',
    'Number flow steps 01, 02, 03… with no gaps or duplicates.',
    'Include every requested step. Do not drop the last step.',
    'Years must be four digits (1950 not 150).',
    'Funnel metrics must strictly decrease. Timelines must be chronological.',
    'Process / dense custom: header (title+subtitle), one or more left-to-right flowRow regions, optional sidebar (KEY POINTS) only when there are 6+ steps, optional footer note.',
    'Do not add a sidebar for simple 3-step layouts.',
    'exactText must list every on-canvas phrase including titles, step headings, bodies, years, and metrics.',
    'Icons: simple flat metaphors; reuse the same characters across rows when the same actor appears.',
  ].join(' ');
}

function buildUser({
  prompt = '',
  infographic = {},
  brandPalette,
  contextExcerpt = '',
} = {}) {
  const layout = infographic.layout || 'custom';
  const title = infographic.title || '';
  const sections = Array.isArray(infographic.sections) ? infographic.sections : [];
  const palette = Array.isArray(brandPalette) && brandPalette.length
    ? brandPalette.join(', ')
    : '';

  const sectionLines = sections.map((section, i) => {
    const heading = section.title || `Section ${i + 1}`;
    const bullets = Array.isArray(section.bullets)
      ? section.bullets.join(' | ')
      : section.content || '';
    return `${i + 1}. "${heading}"${bullets ? ` — ${bullets}` : ''}`;
  });

  const lines = [
    `Layout type: ${layout}`,
    title ? `Title (verbatim if provided): "${title}"` : 'Title: derive from the brief.',
    palette ? `Brand palette: ${palette}` : 'Brand palette: navy/purple accents, green for success, white/light ground.',
    '',
    'User brief:',
    String(prompt || '').trim() || '(none — use sections only)',
  ];

  if (sectionLines.length) {
    lines.push('', `Sections (VERBATIM, ${sectionLines.length} required):`, ...sectionLines);
  }

  if (contextExcerpt && String(contextExcerpt).trim()) {
    lines.push('', 'Reference context (excerpt):', String(contextExcerpt).trim().slice(0, 4000));
  }

  lines.push(
    '',
    'Return JSON with title, subtitle, layout, regions, exactText, expectedStepCount, metrics, palette, characterNotes.'
  );

  return lines.join('\n');
}

module.exports = {
  LAYOUTS,
  PLAN_SCHEMA,
  buildSystem,
  buildUser,
};
