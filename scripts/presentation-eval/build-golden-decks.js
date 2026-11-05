/**
 * Phase 0.2 — build the golden export decks (JSON fixtures) used by export-fidelity.js.
 *
 *   node scripts/presentation-eval/build-golden-decks.js [--frontend ../AthenaVI]
 *
 * Writes src/modules/presentation/test/fixtures/export/:
 *   ai-light.json, ai-dark.json, ai-editorial.json  10 real seed layouts each (compiled here, as
 *                                                    generation does), three different themes
 *   kitchen-sink.json  every element type and style the editor has (all library shapes,
 *                      masks, filters, effects, text styles, charts, table, group, embed,
 *                      image / gradient backgrounds)
 *   four-three.json    a 4:3 deck
 *   forty-slides.json  40 slides (the size limit)
 *   assets/            the pictures the decks use
 *
 * Pictures are referenced like production: an S3 URL + s3Key under `golden/` (the harness
 * serves them in place of S3). `{{EXTERNAL}}/…` is an image on another site (stock photo).
 * The fixtures are committed: re-run this only to change the decks.
 */

const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const sharp = require('sharp');

const root = path.join(__dirname, '../..');
const OUT = path.join(root, 'src/modules/presentation/test/fixtures/export');
const ASSETS = path.join(OUT, 'assets');
const BUCKET_HOST = 'https://athena-golden.s3.us-east-1.amazonaws.com';

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}
const FRONTEND = path.resolve(root, arg('frontend', '../AthenaVI'));

const s3 = (file) => ({ url: `${BUCKET_HOST}/golden/${file}`, s3Key: `golden/${file}` });
const PHOTOS = ['photo-1.jpg', 'photo-2.jpg', 'photo-3.jpg', 'photo-4.jpg'];
const PEOPLE = ['person-1.jpg', 'person-2.jpg', 'person-3.jpg'];

async function buildAssets() {
  fs.mkdirSync(ASSETS, { recursive: true });
  const pub = path.join(FRONTEND, 'public');
  const jobs = [
    ['promo_banner_1.jpg', 'photo-1.jpg', 1280],
    ['promo_banner_2.jpg', 'photo-2.jpg', 1280],
    ['promo_banner_1b.jpg', 'photo-3.jpg', 1280],
    ['promo_banner_2b.jpg', 'photo-4.jpg', 1280],
    ['avatar1.png', 'person-1.jpg', 480],
    ['avatar2.png', 'person-2.jpg', 480],
    ['avatar3.png', 'person-3.jpg', 480],
  ];
  for (const [from, to, width] of jobs) {
    const src = path.join(pub, from);
    if (!fs.existsSync(src)) throw new Error(`Missing ${src} (pass --frontend <path to the AthenaVI repo>)`);
    await sharp(src).resize({ width, withoutEnlargement: true }).jpeg({ quality: 78 }).toFile(path.join(ASSETS, to));
  }
  await sharp(path.join(pub, 'favicon.png')).resize({ width: 256 }).png().toFile(path.join(ASSETS, 'logo.png'));
}

// ── Themes ────────────────────────────────────────────────────────────────────

const THEMES = {
  light: {
    appearance: 'light',
    palette: { bg: '#FFFFFF', surface: '#F8FAFC', text: '#0F172A', muted: '#64748B', primary: '#2563EB', secondary: '#F97316', accent: '#14B8A6', cardBg: '#F1F5F9', divider: '#E2E8F0' },
    fonts: { heading: 'Playfair Display', body: 'Inter' },
  },
  dark: {
    appearance: 'dark',
    palette: { bg: '#0B1220', surface: '#111A2E', text: '#F1F5F9', muted: '#94A3B8', primary: '#38BDF8', secondary: '#F472B6', accent: '#FBBF24', cardBg: '#16213A', divider: '#1E293B' },
    fonts: { heading: 'Montserrat', body: 'Open Sans' },
  },
  editorial: {
    appearance: 'light',
    palette: { bg: '#FBF7F0', surface: '#F3ECE0', text: '#2B2118', muted: '#7C6A58', primary: '#B45309', secondary: '#0F766E', accent: '#9F1239', cardBg: '#F3ECE0', divider: '#E7DCCB' },
    fonts: { heading: 'Playfair Display', body: 'Lato' },
  },
};

// ── Content: one rich object a layout takes what it needs from ─────────────────

const TOPICS = [
  ['Scaling a neighbourhood bakery into a regional brand without losing its soul', 'Strategy review for the leadership offsite'],
  ['What we will cover today', 'Agenda for a ninety minute working session'],
  ['Three bets for the next eighteen months', 'Where we will put money, people and attention'],
  ['From one shop to twelve: the road so far', 'Milestones since the first oven was lit'],
  ['Franchise versus staying independent', 'What each path costs and what it gives back'],
  ['Revenue grew in every region this year', 'Quarterly revenue by region, in thousands'],
  ['The numbers that matter', 'Measured across all locations'],
  ['What customers told us in two hundred interviews', 'Freshness, fair prices and somewhere to sit'],
  ['The people behind the counter', 'A small team doing a lot of things well'],
  ['Thank you', 'Questions, ideas and pastries welcome'],
];

function richContent(i) {
  const [title, subtitle] = TOPICS[i % TOPICS.length];
  return {
    title,
    subtitle,
    eyebrow: 'Strategy 2027',
    body: 'We grew by staying close to the neighbourhood: bread baked before dawn, prices people trust and a room where regulars meet. The plan keeps that and adds the systems a bigger bakery needs.',
    summary: 'Growth that keeps what customers love about us.',
    bullets: [
      'Freshness matters more than price, as long as prices are fair and stable',
      'People come for bread and stay for coffee when there is somewhere to sit',
      'Loyalty rewards are ignored unless they are simple and automatic',
      'Wholesale cafés want a rotating menu, not the full catalogue',
      'Staff turnover drops when schedules are published two weeks ahead',
    ],
    cards: [
      { title: 'Wholesale partnerships with cafés', body: 'Supply twelve independent cafés with a rotating pastry menu and shared branding.' },
      { title: 'A second production kitchen', body: 'Move laminated doughs to a dedicated kitchen so the flagship can focus on bread.' },
      { title: 'Subscription boxes', body: 'Weekly boxes for offices and households, priced to smooth demand across the week.' },
      { title: 'A training programme', body: 'Six weeks from new hire to confident baker, taught by our head bakers.' },
    ],
    stats: [
      { value: '42%', label: 'Revenue growth year on year' },
      { value: '12', label: 'Cafés supplied every morning' },
      { value: '4.8', label: 'Average customer rating' },
      { value: '£1.2m', label: 'Annual revenue' },
    ],
    members: [
      { name: 'Ana Ruiz', role: 'Head baker', bio: 'Fifteen years of sourdough and a love of rye.' },
      { name: 'Raj Patel', role: 'Operations', bio: 'Keeps three kitchens running on time.' },
      { name: 'Mia Chen', role: 'Customer experience', bio: 'Turns regulars into friends.' },
      { name: 'Tom Okafor', role: 'Finance', bio: 'Makes the numbers add up.' },
    ],
    timeline: [
      { year: '2018', title: 'First shop opens', body: 'One oven, two bakers, forty loaves a day.' },
      { year: '2020', title: 'Wholesale begins', body: 'Three cafés take our croissants.' },
      { year: '2022', title: 'Second shop', body: 'A seated café in the old market.' },
      { year: '2024', title: 'Central kitchen', body: 'Production moves out of the shops.' },
      { year: '2026', title: 'Twelve partners', body: 'Wholesale is a third of revenue.' },
    ],
    steps: [
      { title: 'Listen', body: 'Interview customers and staff.' },
      { title: 'Decide', body: 'Pick three bets and fund them.' },
      { title: 'Build', body: 'Kitchen, training and logistics.' },
      { title: 'Measure', body: 'Monthly reviews against targets.' },
    ],
    quotes: [
      { text: 'The only bakery where the staff remember my order and my dog’s name.', author: 'Priya S.', role: 'Customer since 2019' },
      { text: 'Their croissants doubled our morning sales.', author: 'Luca M.', role: 'Café owner' },
    ],
    quote: 'The only bakery where the staff remember my order and my dog’s name.',
    author: 'Priya S.',
    left: { title: 'Franchise', bullets: ['Buying power on flour and butter', 'A proven store layout', 'National campaigns'] },
    right: { title: 'Independent', bullets: ['Menu freedom for local tastes', 'Direct supplier relationships', 'Neighbourhood brand'] },
    prosTitle: 'Franchise',
    consTitle: 'Independent',
    pros: ['Buying power: lower flour and butter cost', 'Playbook: proven store layout', 'Marketing: national campaigns'],
    cons: ['Fees: royalties on every sale', 'Menu: little room for local recipes', 'Exit: harder to sell later'],
    chart: {
      type: i % 2 ? 'line' : 'bar',
      labels: ['North', 'South', 'East', 'West'],
      series: [
        { name: '2025', values: [120, 190, 70, 150] },
        { name: '2026', values: [160, 240, 95, 180] },
      ],
    },
    table: {
      headers: ['Location', 'Revenue', 'Growth', 'Rating'],
      rows: [
        ['Market Street', '£420k', '+38%', '4.9'],
        ['Old Town', '£310k', '+44%', '4.8'],
        ['Riverside', '£270k', '+51%', '4.7'],
        ['Wholesale', '£200k', '+62%', '—'],
      ],
    },
    plans: [
      { name: 'Weekly', price: '£12', features: ['One loaf', 'Four pastries', 'Free delivery'] },
      { name: 'Office', price: '£45', features: ['Pastries for 15', 'Coffee beans', 'Monday delivery'], highlight: true },
      { name: 'Family', price: '£24', features: ['Two loaves', 'Eight pastries', 'Weekend delivery'] },
    ],
    cta: 'Visit us at the old market',
    contact: { email: 'hello@example-bakery.com', phone: '+44 20 7946 0000', website: 'www.example-bakery.com' },
  };
}

function imageSlotUrls(layoutSchema, offset) {
  const out = {};
  let n = offset;
  for (const slot of layoutSchema.slots || []) {
    const role = String(slot.role || '').toLowerCase();
    const id = String(slot.id || '');
    if (role !== 'image' && role !== 'background') continue;
    const person = /AVATAR|PORTRAIT|MEMBER|PERSON|SPEAKER|HEADSHOT|PROFILE|TEAM/i.test(id);
    const logo = /LOGO/i.test(id);
    const file = logo ? 'logo.png' : person ? PEOPLE[n % PEOPLE.length] : PHOTOS[n % PHOTOS.length];
    out[id] = s3(file).url;
    n += 1;
  }
  return out;
}

async function compileDeck({ id, theme, layoutIds, aspectRatio = '16:9' }) {
  const { compileSlide } = require('../../src/modules/presentation/slideCompiler.service');
  const seeds = require('../../src/modules/presentation/templates/seed-layouts.json');
  const canvas = aspectRatio === '4:3' ? { width: 1600, height: 1200 } : { width: 1920, height: 1080 };
  const themeTokens = THEMES[theme];
  const slides = [];
  for (const [i, layoutId] of layoutIds.entries()) {
    const layoutSchema = seeds.find((r) => r.schema?.layout_id === layoutId)?.schema;
    if (!layoutSchema) throw new Error(`Unknown layout ${layoutId}`);
    const slotImageUrls = imageSlotUrls(layoutSchema, i);
    const content = { ...richContent(i), slotImageUrls, imageUrls: Object.values(slotImageUrls) };
    const { elementsDoc } = await compileSlide({
      layoutSchema,
      content,
      themeTokens,
      skipContentRepair: true,
      canvasSize: canvas,
    });
    // Image elements carry their S3 key like generated decks do.
    for (const el of elementsDoc.elements || []) {
      if (el.type === 'image' && el.content?.url?.startsWith(BUCKET_HOST)) {
        el.content.s3Key = el.content.url.slice(BUCKET_HOST.length + 1);
      }
    }
    elementsDoc.canvas = canvas;
    slides.push({ id: `${id}-${i + 1}`, order: i + 1, layoutId, content: { title: content.title }, elements: elementsDoc });
  }
  return { id, aspectRatio, themeTokens, slides };
}

// ── Kitchen sink ─────────────────────────────────────────────────────────────

const P = (x, y, width, height, extra = {}) => ({ x, y, width, height, rotation: 0, opacity: 1, ...extra });
const text = (id, placement, content, extra = {}) => ({ id, type: 'text', layer: 5, placement, content, ...extra });
const slide = (id, order, elements, extra = {}) => ({
  id,
  order,
  content: { title: id },
  elements: { canvas: { width: 1920, height: 1080 }, backgroundColor: '#FFFFFF', elements, ...extra },
});

async function kitchenSink() {
  const shapes = (await import(pathToFileURL(path.join(FRONTEND, 'src/constants/shapeLibrary.js')).href)).SHAPE_LIBRARY;
  const slides = [];

  // 1. Text styles
  slides.push(
    slide('ks-text', 1, [
      text('t-fit', P(80, 50, 1100, 120), { text: 'A generated heading far too long for its box, so the editor shrinks it to fit on two lines', fontSize: 44, bold: true }, { slotId: 'HEADING', role: 'title' }),
      text('t-bullets', P(80, 220, 560, 260), { text: 'Bullet one\nBullet two\nBullet three', fontSize: 20, listType: 'bullet', lineHeight: 1.4 }),
      text('t-numbered', P(700, 220, 560, 260), { text: 'First step\nSecond step\nThird step', fontSize: 20, listType: 'numbered' }),
      text('t-check', P(1320, 220, 520, 260), { text: 'Done\nChecked\nShipped', fontSize: 20, listType: 'check', color: '#15803D', userColor: true }),
      text('t-caps', P(80, 520, 560, 80), { text: 'uppercase with spacing', fontSize: 22, textTransform: 'uppercase', letterSpacing: 4, bold: true }),
      text('t-deco', P(700, 520, 560, 80), { text: 'underlined italic struck', fontSize: 22, underline: true, italic: true, strikethrough: true }),
      text('t-runs', P(1320, 520, 520, 120), { text: 'Mixed runs and www.example.com', fontSize: 22, runs: [{ text: 'Mixed ', bold: true }, { text: 'runs ', color: '#DC2626' }, { text: 'and www.example.com' }] }),
      text('t-pad', P(80, 680, 560, 160), { text: 'Padded, centred both ways', fontSize: 20, padding: 18, paddingX: 24, align: 'center', verticalAlign: 'center', fill: undefined }),
      text('t-right', P(700, 680, 560, 160), { text: 'Right aligned at the bottom of its box', fontSize: 20, align: 'right', verticalAlign: 'bottom' }),
      text('t-justify', P(1320, 680, 520, 200), { text: 'Justified paragraph text that runs over several lines so the justification is visible from edge to edge of the box.', fontSize: 18, align: 'justify' }),
      text('t-nowrap', P(80, 900, 900, 70), { text: 'A single line that never wraps', fontSize: 26, wrap: 'nowrap' }),
      text('t-rotated', P(1100, 920, 600, 80, { rotation: -8 }), { text: 'Rotated text', fontSize: 30, bold: true, color: '#7C3AED', userColor: true }),
    ])
  );

  // 2–3. Every library shape (filled, then outlined), in a grid
  const shapeSlides = [shapes.slice(0, 35), shapes.slice(35)];
  shapeSlides.forEach((group, s) => {
    const els = group.map((shape, i) => {
      const col = i % 7;
      const row = Math.floor(i / 7);
      const outlined = s === 1 && i % 2 === 1;
      const style = shape.style || {};
      return {
        id: `shape-${shape.id}`,
        type: 'shape',
        layer: 2,
        placement: P(60 + col * 265, 40 + row * 205, 200, 160),
        content: {
          shape: shape.id,
          fill: outlined ? 'transparent' : ['#2563EB', '#F97316', '#14B8A6', '#7C3AED', '#E11D48'][i % 5],
          ...(style.clipPath ? { clipPath: style.clipPath } : {}),
          ...(style.borderRadius != null ? { borderRadius: Number.parseFloat(style.borderRadius) || style.borderRadius } : {}),
          ...(outlined ? { stroke: '#475569', strokeWidth: 3, variant: 'outlined' } : { variant: 'filled' }),
        },
      };
    });
    slides.push(slide(`ks-shapes-${s + 1}`, slides.length + 1, els));
  });

  // 4. Images
  const img = (id, x, y, content, extra = {}) => ({ id, type: 'image', layer: 3, placement: P(x, y, 360, 240, extra.placement), content: { fit: 'cover', ...content }, ...extra.el });
  slides.push(
    slide('ks-images', slides.length + 1, [
      img('i-plain', 60, 60, s3('photo-1.jpg')),
      img('i-crop', 480, 60, { ...s3('photo-2.jpg'), crop: { x: 0.2, y: 0.1, width: 0.5, height: 0.6 } }),
      img('i-radius', 900, 60, { ...s3('photo-3.jpg'), borderRadius: 24 }),
      img('i-circle', 1320, 60, { ...s3('person-1.jpg'), imageMask: { type: 'circle' } }),
      img('i-oval', 60, 380, { ...s3('photo-4.jpg'), imageMask: { type: 'oval' } }),
      img('i-hex', 480, 380, { ...s3('photo-1.jpg'), imageMask: { type: 'hexagon' } }),
      img('i-blob', 900, 380, { ...s3('photo-2.jpg'), imageMask: { type: 'blob' } }),
      img('i-fade', 1320, 380, { ...s3('photo-3.jpg'), edgeFade: true }),
      img('i-filter', 60, 700, { ...s3('photo-4.jpg'), cssFilter: 'grayscale(1) contrast(1.2)' }),
      img('i-flip-rot', 480, 700, { ...s3('photo-1.jpg'), flipHorizontal: true }, { placement: { rotation: 10 } }),
      img('i-external', 900, 700, { url: '{{EXTERNAL}}/photo-2.jpg' }),
      img('i-empty', 1320, 700, {}),
      img('i-faded', 1600, 60, s3('person-2.jpg'), { placement: { opacity: 0.5 } }),
    ])
  );

  // 5. Charts and a table
  const chart = (id, x, y, w, h, chartType) => ({
    id,
    type: 'chart',
    layer: 2,
    placement: P(x, y, w, h),
    content: { chartType, labels: ['North', 'South', 'East', 'West'], series: [{ name: 'Revenue', values: [12, 19, 7, 15] }, { name: 'Cost', values: [8, 11, 6, 9] }] },
  });
  slides.push(
    slide('ks-charts', slides.length + 1, [
      chart('c-bar', 60, 60, 580, 420, 'bar'),
      chart('c-line', 680, 60, 580, 420, 'line'),
      chart('c-area', 1300, 60, 560, 420, 'area'),
      chart('c-pie', 60, 560, 420, 420, 'pie'),
      chart('c-donut', 520, 560, 420, 420, 'donut'),
      { id: 'tbl', type: 'table', layer: 2, placement: P(1000, 560, 860, 420), content: { hasHeader: true, rows: [['Location', 'Revenue', 'Growth'], ['Market Street', '£420k', '+38%'], ['Old Town', '£310k', '+44%'], ['Riverside', '£270k', '+51%']] } },
    ])
  );

  // 6. Effects: every element effect on a shape, every text effect on a heading
  const elementEffects = ['shadow', 'lift', 'glow', 'outline', 'echo', 'neon', 'glitch', 'blur'];
  const textEffects = ['drop', 'glow', 'echo', 'outline', 'background', 'splice', 'hollow', 'neon', 'glitch'];
  slides.push(
    slide('ks-effects', slides.length + 1, [
      ...elementEffects.map((type, i) => ({
        id: `fx-${type}`,
        type: 'shape',
        layer: 2,
        placement: P(80 + (i % 4) * 460, 60 + Math.floor(i / 4) * 220, 340, 160),
        content: { shape: 'rounded-rect', borderRadius: 16, fill: '#2563EB', effect: { type } },
      })),
      ...textEffects.map((effect, i) =>
        text(`tfx-${effect}`, P(80 + (i % 3) * 620, 540 + Math.floor(i / 3) * 170, 560, 140), { text: `Text ${effect}`, fontSize: 40, bold: true, textEffect: effect })
      ),
    ])
  );

  // 7. Background photo, a group, an embed, gradient shapes
  slides.push(
    slide(
      'ks-background',
      slides.length + 1,
      [
        text('bg-title', P(120, 760, 1300, 160), { text: 'Text over a background photo', fontSize: 44, bold: true, color: '#FFFFFF', userColor: true }),
        { id: 'grp', type: 'group', layer: 4, childIds: ['grp-a', 'grp-b'], placement: P(1200, 80, 600, 260), content: {} },
        { id: 'grp-a', type: 'shape', layer: 4, groupId: 'grp', placement: P(1200, 80, 280, 260), content: { shape: 'rounded-rect', borderRadius: 20, fill: '#FACC15' } },
        { id: 'grp-b', type: 'shape', layer: 4, groupId: 'grp', placement: P(1520, 80, 280, 260), content: { shape: 'circle', fill: '#F472B6' } },
        { id: 'embed', type: 'embed', layer: 4, placement: P(120, 80, 640, 360), content: { url: 'https://www.youtube.com/watch?v=aqz-KE-bpKQ', provider: 'youtube', title: 'Our bakery story' } },
      ],
      { backgroundImage: s3('photo-3.jpg').url, backgroundImageFit: 'cover' }
    )
  );
  slides.push(
    slide(
      'ks-gradient',
      slides.length + 1,
      [
        text('g-title', P(120, 100, 1500, 140), { text: 'Gradients everywhere', fontSize: 48, bold: true, color: '#FFFFFF', userColor: true }),
        { id: 'g-card', type: 'shape', layer: 2, placement: P(120, 320, 700, 420), content: { shape: 'rounded-rect', borderRadius: 28, fill: { type: 'gradient', angle: 135, stops: [{ color: '#F97316', at: 0 }, { color: '#E11D48', at: 1 }] } } },
        { id: 'g-pill', type: 'shape', layer: 2, placement: P(900, 360, 760, 140), content: { shape: 'pill', fill: { type: 'gradient', kind: 'radial', stops: [{ color: '#FDE68A', at: 0 }, { color: '#F59E0B', at: 1 }] } } },
        { id: 'g-dashed', type: 'shape', layer: 2, placement: P(900, 560, 760, 200), content: { shape: 'rect', fill: 'transparent', stroke: '#FFFFFF', strokeWidth: 3, borderStyle: 'dashed' } },
        text('g-text', P(120, 800, 1500, 120), { text: 'Gradient text', fontSize: 56, bold: true, fill: { type: 'gradient', angle: 90, stops: [{ color: '#22D3EE', at: 0 }, { color: '#A78BFA', at: 1 }] } }),
      ],
      { backgroundFill: { type: 'gradient', angle: 160, stops: [{ color: '#1E1B4B', at: 0 }, { color: '#0F766E', at: 1 }] } }
    )
  );

  return { id: 'kitchen-sink', aspectRatio: '16:9', themeTokens: THEMES.light, slides };
}

// ── Decks ────────────────────────────────────────────────────────────────────

const AI_LIGHT = ['title_hero_left_blob_v1', 'agenda_numbered_v1', 'three_cards_image_text_v1', 'timeline_horizontal_v1', 'comparison_pros_cons_v1', 'chart_single_v1', 'metric_three_v1', 'quote_testimonial_card_v1', 'team_three_horizontal_v1', 'closing_thank_you_v1'];
const AI_DARK = ['section_divider_centered_v1', 'grid_bento_four_v1', 'process_linear_business_v1', 'table_single_v1', 'chart_two_v1', 'diagram_swot_v1', 'pricing_three_plans_v1', 'device_phone_horizontal_v1', 'full_bg_image_overlay_v1', 'contact_card_cta_v1'];
const AI_EDITORIAL = ['title_fullbleed_overlay_v1', 'statement_large_v1', 'para_split_50_50_v1', 'bullet_list_numbered_v1', 'four_images_text_v1', 'logo_wall_v1', 'timeline_vertical_v1', 'diagram_funnel_v1', 'speaker_bio_image_right_v1', 'minimal_text_cta_v1'];

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  await buildAssets();
  const decks = {
    'ai-light': await compileDeck({ id: 'ai-light', theme: 'light', layoutIds: AI_LIGHT }),
    'ai-dark': await compileDeck({ id: 'ai-dark', theme: 'dark', layoutIds: AI_DARK }),
    'ai-editorial': await compileDeck({ id: 'ai-editorial', theme: 'editorial', layoutIds: AI_EDITORIAL }),
    'kitchen-sink': await kitchenSink(),
    'four-three': await compileDeck({ id: 'four-three', theme: 'light', aspectRatio: '4:3', layoutIds: ['title_centered_v1', 'two_cards_image_text_v1', 'chart_with_description_v1', 'timeline_milestones_v1', 'closing_contact_cta_v1'] }),
  };
  const all = [...AI_LIGHT, ...AI_DARK, ...AI_EDITORIAL, ...AI_LIGHT];
  decks['forty-slides'] = await compileDeck({ id: 'forty', theme: 'dark', layoutIds: all.slice(0, 40) });

  for (const [name, deck] of Object.entries(decks)) {
    fs.writeFileSync(path.join(OUT, `${name}.json`), `${JSON.stringify(deck)}\n`);
    const elements = deck.slides.reduce((n, s) => n + (s.elements.elements || []).length, 0);
    console.log(`${name.padEnd(14)} ${String(deck.slides.length).padStart(2)} slides, ${elements} elements`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
