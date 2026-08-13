/**
 * Upgrade seed-deck-packs.json with meta, narrative, intent, designTokens, generationHints.
 * Run: node scripts/upgrade-seed-packs-v2.js
 */
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../src/modules/presentation/templates/seed-deck-packs.json');
const packs = JSON.parse(fs.readFileSync(file, 'utf8'));

const PACK_META = {
  corp_pitch_midnight: {
    meta: {
      name: 'Corporate Pitch — Midnight',
      description: '5-slide investor-ready pitch. Best for fundraising overviews.',
      useCase: 'investor_pitch',
      audience: 'investors',
      tone: 'professional, confident, data-driven',
      industry: ['technology', 'saas', 'enterprise'],
    },
    narrative: {
      arc: 'problem_solution_proof_ask',
      summary:
        'Opens with company vision, sets agenda, proves traction with metrics, shows the product, closes with a partner ask.',
    },
    intents: [
      'Bold vision statement — hook investors in five seconds',
      'Signal structure and depth with a crisp agenda',
      'Shock with traction metrics that feel credible',
      'Introduce the product clearly and visually',
      'Close with a specific, memorable ask',
    ],
    design: [
      { backgroundStyle: 'gradient', accentPosition: 'bottom-bar', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'left-bar', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'top-bar', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'left-half', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'bottom-bar', imagePosition: 'none', textContrast: 'high' },
    ],
    hints: [
      { maxTitleWords: 10, titleLength: '8-12 words, bold', subtitleLength: 'one sentence' },
      { itemCountMin: 5, itemCountMax: 7, itemLength: '4-8 words' },
      { maxTitleWords: 8, statFormat: 'percentage, dollar, or multiplier' },
      { maxBodyWords: 40, maxTitleWords: 8 },
      { maxTitleWords: 10, ctaFormat: 'email or URL' },
    ],
    tags: ['pitch', 'fundraising', 'dark theme'],
    color: '#0B1220',
    accentColor: '#3B82F6',
  },
  marketing_clean_light: {
    meta: {
      name: 'Marketing Story — Clean Light',
      description: '5-slide campaign narrative with before/after and proof.',
      useCase: 'marketing',
      audience: 'brand and growth teams',
      tone: 'clear, optimistic, outcome-focused',
      industry: ['marketing', 'saas'],
    },
    narrative: {
      arc: 'story_contrast_proof_voice_cta',
      summary: 'Campaign story, before vs after, impact metric, customer voice, then next steps.',
    },
    intents: [
      'Open with the campaign story',
      'Make the before/after contrast impossible to miss',
      'Lead with one unforgettable impact number',
      'Let a customer voice land the emotional proof',
      'Close with clear next steps and contact',
    ],
    design: [
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'left-bar', imagePosition: 'none', textContrast: 'normal' },
    ],
    hints: [
      { maxTitleWords: 8 },
      { pointCount: '3-5 per side', parallelStructure: 'yes' },
      { maxTitleWords: 6, statFormat: 'percentage or multiplier' },
      { maxBodyWords: 30 },
      { maxBodyWords: 40 },
    ],
    tags: ['marketing', 'campaign', 'light theme'],
    color: '#FFFFFF',
    accentColor: '#2563EB',
  },
  portfolio_forest: {
    meta: {
      name: 'Portfolio Showcase — Forest',
      description: '5-slide studio portfolio with journey, team, and case study.',
      useCase: 'portfolio',
      audience: 'prospective clients',
      tone: 'crafted, confident, human',
      industry: ['design', 'agency'],
    },
    narrative: {
      arc: 'intro_journey_team_case_close',
      summary: 'Selected work intro, journey timeline, team, case study, thank you.',
    },
    intents: [
      'Introduce the portfolio with craft and confidence',
      'Show the journey as milestones, not fluff',
      'Establish credibility through the team',
      'Tell one case study tightly',
      'Close with a collaboration invitation',
    ],
    design: [
      { backgroundStyle: 'gradient', accentPosition: 'left-bar', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'top-bar', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'full-bleed', textContrast: 'high' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'full-bleed', textContrast: 'high' },
    ],
    hints: [
      { maxTitleWords: 6 },
      { itemCountMin: 4, itemCountMax: 4 },
      { nameFormat: 'First Last', bioLength: 'max 8 words' },
      { maxBodyWords: 35 },
      { maxTitleWords: 4 },
    ],
    tags: ['portfolio', 'studio', 'dark theme'],
    color: '#0F1A14',
    accentColor: '#34D399',
  },
  consulting_report_paper: {
    meta: {
      name: 'Consulting Report — Paper Ink',
      description: '8-slide text-first consulting report for executive committees.',
      useCase: 'consulting_report',
      audience: 'executive committee',
      tone: 'precise, neutral, evidence-led',
      industry: ['consulting', 'enterprise'],
    },
    narrative: {
      arc: 'mandate_baseline_options_recommendation',
      summary:
        'Title and contents, baseline divider, executive summary, chart evidence, option table, prize, recommended next steps.',
    },
    intents: [
      'Frame the review for the Executive Committee',
      'Set a clear table of contents',
      'Mark the baseline diagnostic section',
      'Deliver three sharp findings',
      'Prove cost-to-serve with a chart and callouts',
      'Compare options in a clean table',
      'Quantify the prize with context',
      'Leave clear owners and next steps',
    ],
    design: [
      { backgroundStyle: 'solid', accentPosition: 'left-bar', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'left-bar', imagePosition: 'none', textContrast: 'normal' },
    ],
    hints: [
      { maxTitleWords: 8 },
      { itemCountMin: 5, itemCountMax: 7 },
      { maxTitleWords: 6 },
      { maxBodyWords: 70, itemCountMax: 5 },
      { calloutLength: 'one sentence' },
      { maxTitleWords: 6 },
      { maxBodyWords: 50, statFormat: 'dollar amount' },
      { maxBodyWords: 40 },
    ],
    tags: ['consulting', 'report', 'monochrome'],
    color: '#FAFAF9',
    accentColor: '#18181B',
    preferVisuals: false,
  },
  investor_deck_violet: {
    meta: {
      name: 'Investor Deck — Violet Noir',
      description: '8-slide Series A fundraising deck.',
      useCase: 'investor_pitch',
      audience: 'investors',
      tone: 'confident, specific, ambitious',
      industry: ['saas', 'ai'],
    },
    narrative: {
      arc: 'problem_solution_traction_competition_team_ask',
      summary:
        'Series A title, problem cards, solution, traction, growth chart, competitive contrast, team, the ask.',
    },
    intents: [
      'Open the Series A story with clarity',
      'Make the problem feel urgent and concrete',
      'Introduce the solution without fluff',
      'Prove traction with three sharp metrics',
      'Show growth as progressive and real',
      'Make the competitive advantage undeniable',
      'Investors back people — show the team',
      'Close with a specific ask',
    ],
    design: [
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'top-bar', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'top-bar', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'bottom-bar', imagePosition: 'none', textContrast: 'high' },
    ],
    hints: [
      { maxTitleWords: 6 },
      { itemCountMax: 3, maxBodyWords: 30 },
      { maxBodyWords: 50 },
      { statFormat: 'ARR, NRR, or logo count' },
      { calloutLength: 'one sentence highlighting YoY' },
      { parallelStructure: 'yes', pointCount: '3-5' },
      { nameFormat: 'First Last', bioLength: 'max 8 words' },
      { maxTitleWords: 6, ctaFormat: 'email' },
    ],
    tags: ['pitch', 'series-a', 'dark theme'],
    color: '#0C0A14',
    accentColor: '#A78BFA',
  },
  product_launch_ocean: {
    meta: {
      name: 'Product Launch — Ocean Mist',
      description: '8-slide product launch announcement.',
      useCase: 'product_launch',
      audience: 'customers and press',
      tone: 'energetic, clear, customer-first',
      industry: ['product', 'saas'],
    },
    narrative: {
      arc: 'announce_why_features_rollout_proof_close',
      summary: 'Announce release, why now, hero story, features, rollout, early results, quote, ship CTA.',
    },
    intents: [
      'Announce the release with energy',
      'Explain why now in one beat',
      'Show the product around one job-to-be-done',
      'List three crisp new capabilities',
      'Make the rollout plan tangible',
      'Lead with one early-result number',
      'Use a beta customer quote',
      'Close with a ship CTA',
    ],
    design: [
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'full-bleed', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'left-half', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'full-bleed', textContrast: 'high' },
    ],
    hints: [
      { maxTitleWords: 8 },
      { maxTitleWords: 4 },
      { maxBodyWords: 30 },
      { itemCountMax: 3 },
      { itemCountMin: 4, itemCountMax: 4 },
      { statFormat: 'multiplier' },
      { maxBodyWords: 35 },
      { maxTitleWords: 4 },
    ],
    tags: ['launch', 'product', 'light theme'],
    color: '#F0F9FF',
    accentColor: '#0369A1',
  },
  executive_review_charcoal: {
    meta: {
      name: 'Executive Review — Charcoal Gold',
      description: '8-slide QBR for leadership teams.',
      useCase: 'qbr',
      audience: 'leadership team',
      tone: 'direct, accountable, forward-looking',
      industry: ['enterprise'],
    },
    narrative: {
      arc: 'glance_performance_lessons_roadmap_decisions',
      summary: 'Quarter glance, plan vs actual, pros/cons, roadmap, decisions required, owners.',
    },
    intents: [
      'Open the quarterly review crisply',
      'Set the agenda for decisions',
      'Show the quarter at a glance',
      'Explain performance against plan',
      'Be honest about what worked and what did not',
      'Lay out next-quarter milestones',
      'Call out decisions required',
      'Assign owners and follow-ups',
    ],
    design: [
      { backgroundStyle: 'gradient', accentPosition: 'bottom-bar', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'left-bar', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'top-bar', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'left-bar', imagePosition: 'none', textContrast: 'normal' },
    ],
    hints: [
      { maxTitleWords: 6 },
      { itemCountMin: 5, itemCountMax: 5 },
      { statFormat: 'percentage or count' },
      { maxBodyWords: 45 },
      { pointCount: '3-5 per side' },
      { itemCountMax: 3 },
      { maxTitleWords: 4 },
      { maxBodyWords: 40 },
    ],
    tags: ['qbr', 'executive', 'dark theme'],
    color: '#111111',
    accentColor: '#D4AF37',
    preferVisuals: false,
  },
  brand_story_sand: {
    meta: {
      name: 'Brand Story — Warm Sand',
      description: '8-slide editorial brand story.',
      useCase: 'brand_story',
      audience: 'partners and customers',
      tone: 'warm, crafted, human',
      industry: ['brand', 'consumer'],
    },
    narrative: {
      arc: 'promise_origin_milestones_impact_people_future',
      summary: 'Story open, brand promise, origin, milestones, impact, people, what next, thank you.',
    },
    intents: [
      'Open the brand story',
      'State the founding promise',
      'Tell where it started',
      'Show milestones with craft',
      'Quantify impact with context',
      'Feature the people behind it',
      'Point to what is next',
      'Close with gratitude and contact',
    ],
    design: [
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'normal' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'none', textContrast: 'high' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'left-half', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'top-bar', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'full-bleed', textContrast: 'high' },
      { backgroundStyle: 'gradient', accentPosition: 'none', imagePosition: 'full-bleed', textContrast: 'high' },
    ],
    hints: [
      { maxTitleWords: 4 },
      { maxBodyWords: 25 },
      { maxBodyWords: 35 },
      { itemCountMin: 4, itemCountMax: 4 },
      { maxBodyWords: 40, statFormat: 'count' },
      { nameFormat: 'First Last' },
      { maxBodyWords: 25 },
      { maxTitleWords: 3 },
    ],
    tags: ['brand', 'story', 'editorial'],
    color: '#FFFBF5',
    accentColor: '#C2410C',
  },
  website_launch_paper_v1: {
    meta: {
      name: 'Website Launch — Paper Ink',
      description: '7-slide launch deck for announcing a redesigned company website.',
      useCase: 'website_launch',
      audience: 'customers, partners, and internal stakeholders',
      tone: 'muted, professional, confident, clear',
      industry: ['saas', 'technology'],
    },
    narrative: {
      arc: 'announce_discover_experience_prove_content',
      summary:
        'Announce the launch, map the site with a hero agenda, justify the rebuild, show desktop and mobile mockups, highlight pages with metrics, end on rich site content.',
    },
    intents: [
      'Announce the new Atlas website with confidence and clarity',
      'Map the site into Discover, Evaluate, and Act paths beneath a wide hero image',
      'Explain why the rebuild mattered — problem, then solution',
      'Show the desktop experience where complex evaluations happen',
      'Prove mobile-first design for the majority of traffic',
      'Combine flagship page cards with two launch benchmark stats',
      'Close with rich content on what visitors will find across the site',
    ],
    design: [
      { backgroundStyle: 'solid', accentPosition: 'left-bar', imagePosition: 'right-half', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'full-bleed', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'left-half', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'none', textContrast: 'normal' },
      { backgroundStyle: 'solid', accentPosition: 'none', imagePosition: 'right-half', textContrast: 'normal' },
    ],
    hints: [
      { maxTitleWords: 6, subtitleLength: 'one sentence', imagePromptStyle: 'editorial photography, muted tones' },
      { itemCountMin: 3, itemCountMax: 4, parallelStructure: 'yes', imagePromptStyle: 'wide launch hero banner, muted tones' },
      { maxTitleWords: 6, maxBodyWords: 55, imagePromptStyle: 'before-and-after redesign, muted workspace' },
      { maxTitleWords: 6, maxBodyWords: 40, imagePromptStyle: 'SaaS homepage inside laptop frame mockup' },
      { maxTitleWords: 5, maxBodyWords: 40, imagePromptStyle: 'mobile website inside phone frame mockup' },
      { maxTitleWords: 6, statFormat: 'time or score', itemCountMax: 3, imagePromptStyle: 'bento grid of SaaS page screenshots' },
      { maxTitleWords: 6, itemCountMax: 4, imagePromptStyle: 'team browsing documentation site' },
    ],
    tags: ['website', 'launch', 'product', 'muted theme'],
    color: '#FAFAF9',
    accentColor: '#3F3F46',
    preferVisuals: true,
  },
};

const upgraded = packs.map((pack) => {
  const schema = { ...pack.schema, schemaVersion: 2 };
  const packId = schema.pack_id;
  const cfg = PACK_META[packId];
  if (!cfg) return pack;

  schema.meta = cfg.meta;
  schema.narrative = cfg.narrative;
  schema.slides = (schema.slides || []).map((slide, i) => ({
    ...slide,
    intent: cfg.intents[i] || slide.intent || null,
    designTokens: cfg.design[i] || slide.designTokens || null,
    generationHints: cfg.hints[i] || slide.generationHints || null,
  }));

  const layoutWhitelist = schema.slides.map((s) => s.layout_id);
  const preferVisuals =
    cfg.preferVisuals != null ? cfg.preferVisuals : schema.generationDefaults?.preferVisuals;

  schema.generationDefaults = {
    ...(schema.generationDefaults || {}),
    preferVisuals,
    layoutWhitelist,
    slideOrder: 'fixed',
    titleSlide: {
      layout_id: schema.slides[0]?.layout_id,
      alwaysFirst: true,
    },
    closingSlide: {
      layout_id: schema.slides[schema.slides.length - 1]?.layout_id,
      alwaysLast: true,
    },
    contentDistribution: {
      maxConsecutiveBulletSlides: preferVisuals === false ? 2 : 1,
      requireStatSlide: true,
      requireImageSlide: preferVisuals !== false,
      requireChartSlide: Boolean(
        schema.slides.some((s) => String(s.contentType).includes('chart'))
      ),
      requireComparisonSlide: Boolean(
        schema.slides.some((s) => String(s.contentType).includes('comparison'))
      ),
    },
  };

  schema.preview = {
    ...(schema.preview || {}),
    label: cfg.meta.name,
    color: cfg.color,
    accentColor: cfg.accentColor,
    description: cfg.meta.description,
    useCase: cfg.meta.useCase,
    slideCount: schema.slides.length,
    tags: cfg.tags,
  };

  return { ...pack, schema };
});

fs.writeFileSync(file, JSON.stringify(upgraded, null, 2) + '\n');
console.log(`Upgraded ${upgraded.length} packs`);
