/* global window, document */
/**
 * Present harness (Phase 0.2 of PRESENT_MODE_PRODUCTION_PLAN.md in the frontend docs):
 * measures the slide editor's Present mode the way an audience sees it.
 *
 *   node scripts/presentation-eval/present-eval.js [options]      (npm run eval:present)
 *
 *   --decks a,b          decks to run (default: every deck in test/fixtures/export and
 *                        test/fixtures/present)
 *   --label name         report folder name (default: current)
 *   --out dir            output root (default: .eval/present)
 *   --present-url url    the frontend's Present measurement page (default: PRESENT_EVAL_URL, else
 *                        http://localhost:5173/present-eval.html — run the frontend dev server;
 *                        the page is dev-only, it is not in the production build)
 *   --render-url url     the export render page, which draws the reference pictures (default:
 *                        EXPORT_RENDER_URL, else export-render.html next to the Present page)
 *   --asset-latency ms   delay before every picture is served (default 150), as S3 over the
 *                        internet; 0 measures a warm cache
 *   --compare file       an earlier scores.json: the report shows the change against it
 *   --skip-screens       skip the screen-size pass
 *   --headful            show the browser
 *   --verbose            log each step to stderr
 *
 * For every deck, at 1920 × 1080: open Present on slide 1, step forward through every slide, then
 * back to the first, with the arrow keys. For every slide change it records:
 *   settle time    key press → the new slide drawn with all its pictures loaded, fonts ready and
 *                  no transition running (ms; Present today has no transitions on these decks)
 *   blank frames   animation frames with no slide drawn during the change (target 0)
 *   pop-in frames  frames where the new slide is up but its pictures are still loading
 *   embeds created video / web embeds created by the change (a slide revisited should not reload)
 * and, for every slide, SSIM of the presented slide against the editor's own rendering (the export
 * render page), the same score export-fidelity.js uses.
 *
 * Screen pass: one 16:9 and one 4:3 deck on a laptop (1366 × 768), 1920 × 1080, 2560 × 1440,
 * 1024 × 768 and a phone (390 × 844, both ways round): how much of the screen the slide uses.
 *   fill   slide area ÷ the largest box of the slide's shape that fits the screen (100% = edge
 *          to edge, letterboxed)
 *   area   slide area ÷ screen area
 *
 * Pictures: the decks reference S3 keys under golden/; they are served from
 * test/fixtures/export/assets, as in export-fidelity.js. YouTube embeds are answered with a small
 * local page, so the run needs no video site (fonts still come from Google Fonts).
 * Writes report.html and scores.json in <out>/<label>/.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '../..');
const PRESENTATION = path.join(ROOT, 'src/modules/presentation');
const FIXTURE_DIRS = [
  path.join(PRESENTATION, 'test/fixtures/export'),
  path.join(PRESENTATION, 'test/fixtures/present'),
];
const ASSETS = path.join(PRESENTATION, 'test/fixtures/export/assets');
const VIEW = { width: 1920, height: 1080 };
const SCREENS = [
  { id: 'laptop', label: 'Laptop 1366 × 768', width: 1366, height: 768 },
  { id: 'fhd', label: '1920 × 1080', width: 1920, height: 1080 },
  { id: 'qhd', label: '2560 × 1440', width: 2560, height: 1440 },
  { id: 'xga', label: '1024 × 768', width: 1024, height: 768 },
  { id: 'phone', label: 'Phone 390 × 844', width: 390, height: 844, mobile: true },
  { id: 'phone-land', label: 'Phone 844 × 390', width: 844, height: 390, mobile: true },
];
const SETTLE_TIMEOUT_MS = 20_000;
const THUMB_WIDTH = 360;

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}
const flag = (name) => process.argv.includes(`--${name}`);
const log = (...a) => (flag('verbose') ? console.error('[present-eval]', ...a) : undefined);

// ── Environment (before any backend module loads) ───────────────────────────────
process.env.AWS_S3_BUCKET = 'athena-golden';
process.env.AWS_REGION = process.env.AWS_REGION || 'us-east-1';
process.env.PPT_EXPORT_BROWSER_CHECK = '0';
const PRESENT_URL = arg('present-url') || process.env.PRESENT_EVAL_URL || 'http://localhost:5173/present-eval.html';
const RENDER_URL =
  arg('render-url') || process.env.EXPORT_RENDER_URL || new URL('/export-render.html', PRESENT_URL).href;
process.env.EXPORT_RENDER_URL = RENDER_URL;
const ASSET_LATENCY_MS = Number(arg('asset-latency', 150)) || 0;

const sharp = require('sharp');
const puppeteer = require('puppeteer');
const { score } = require('./imageScore');

// ── Media: S3 → local fixture files ────────────────────────────────────────────

function startAssetServer() {
  const server = http.createServer((req, res) => {
    const pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    const file = path.join(ASSETS, path.basename(pathname));
    if (!/^\/(golden|external)\//.test(pathname) || !fs.existsSync(file)) {
      res.writeHead(404);
      res.end();
      return;
    }
    setTimeout(() => {
      res.writeHead(200, {
        'content-type': file.endsWith('.png') ? 'image/png' : 'image/jpeg',
        'access-control-allow-origin': '*',
        'cache-control': 'max-age=3600',
      });
      fs.createReadStream(file).pipe(res);
    }, ASSET_LATENCY_MS);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

function stubS3(assetBase) {
  const s3 = require(path.join(ROOT, 'src/modules/s3/s3.service'));
  s3.getObjectBuffer = async (key) => {
    if (!String(key).startsWith('golden/')) {
      throw Object.assign(new Error(`NoSuchKey: ${key}`), { name: 'NoSuchKey' });
    }
    return fs.promises.readFile(path.join(ASSETS, path.basename(key)));
  };
  s3.getPresignedGetUrl = async (key) =>
    String(key).startsWith('golden/')
      ? `${assetBase}/golden/${path.basename(key)}?X-Amz-Signature=golden`
      : `https://athena-golden.s3.us-east-1.amazonaws.com/${key}?X-Amz-Signature=missing`;
}

function deckFile(name) {
  for (const dir of FIXTURE_DIRS) {
    const file = path.join(dir, `${name}.json`);
    if (fs.existsSync(file)) return file;
  }
  throw new Error(`No deck named ${name} in ${FIXTURE_DIRS.join(', ')}`);
}

function loadDeck(name, assetBase) {
  const raw = fs.readFileSync(deckFile(name), 'utf8');
  return JSON.parse(raw.replaceAll('{{EXTERNAL}}', `${assetBase}/external`));
}

function allDeckNames() {
  return FIXTURE_DIRS.flatMap((dir) =>
    fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => f.replace(/\.json$/, '')) : []
  );
}

// ── Present page ───────────────────────────────────────────────────────────────

const EMBED_HOSTS = /(^|\.)(youtube\.com|youtube-nocookie\.com|youtu\.be|ytimg\.com|vimeo\.com|player\.vimeo\.com|loom\.com)$/;
const EMBED_STUB =
  '<!doctype html><html><body style="margin:0;height:100vh;display:grid;place-items:center;background:#111;color:#eee;font:24px system-ui">▶ video</body></html>';

async function openPresentPage(browser, viewport) {
  const page = await browser.newPage();
  await page.setViewport({ deviceScaleFactor: 1, ...viewport });
  await page.setRequestInterception(true);
  page.on('request', (request) => {
    let host = '';
    try {
      host = new URL(request.url()).hostname;
    } catch {
      /* data: / blob: */
    }
    if (EMBED_HOSTS.test(host)) {
      request.respond({ status: 200, contentType: 'text/html', body: EMBED_STUB });
      return;
    }
    request.continue();
  });
  const errors = [];
  page.on('pageerror', (err) => errors.push(String(err.message || err).slice(0, 200)));
  const response = await page.goto(PRESENT_URL, { waitUntil: 'load', timeout: 120_000 });
  // 304 = served from the browser cache (every page after the first).
  if (response && response.status() >= 400) throw new Error(`Present page: HTTP ${response.status()}`);
  await page.waitForFunction(() => window.__athenaPresent && window.__athenaPresent.loaded, { timeout: 60_000 });
  page.__errors = errors;
  return page;
}

async function presentPayload(deck) {
  const { attachPresignedMediaToSlides } = require(path.join(PRESENTATION, 'presignSlideMedia'));
  const { fontCssUrlFromThemeTokens } = require(path.join(ROOT, 'src/shared/fonts/googleFontsCss'));
  const slides = [...(deck.slides || [])].sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  return {
    id: deck.id,
    aspectRatio: deck.aspectRatio || '16:9',
    themeTokens: deck.themeTokens || null,
    fontCssUrl: fontCssUrlFromThemeTokens(deck.themeTokens) || null,
    slides: await attachPresignedMediaToSlides(slides),
  };
}

async function openDeck(page, payload, slideIndex = 0) {
  await page.evaluate((p) => window.__athenaPresent.open(p), { deck: payload, slideIndex });
  await page.evaluate(() => document.fonts && document.fonts.ready);
  await page.waitForFunction(() => window.__athenaPresent.probe.settled(), { timeout: 60_000, polling: 'raf' });
}

const waitSettled = (page) =>
  page
    .waitForFunction(() => window.__athenaPresent.probe.settled(), { timeout: SETTLE_TIMEOUT_MS, polling: 'raf' })
    .then(() => true)
    .catch(() => false);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function shootSlide(page, file) {
  const rect = await page.evaluate(() => window.__athenaPresent.probe.snapshot().slideRect);
  if (!rect) return false;
  await page.screenshot({
    path: file,
    clip: { x: Math.round(rect.x), y: Math.round(rect.y), width: Math.round(rect.width), height: Math.round(rect.height) },
  });
  return true;
}

async function thumb(file, out, width = THUMB_WIDTH) {
  await sharp(file).flatten({ background: '#ffffff' }).resize({ width }).jpeg({ quality: 74 }).toFile(out);
}

// ── One deck at 1920 × 1080 ────────────────────────────────────────────────────

const pct = (part, whole) => Math.round((part / whole) * 1000) / 10;

function fillOf(rect, viewport, aspect) {
  if (!rect) return { fill: 0, area: 0, heightShare: 0 };
  const bestWidth = Math.min(viewport.width, viewport.height * aspect);
  const bestArea = bestWidth * (bestWidth / aspect);
  const area = rect.width * rect.height;
  return {
    fill: pct(area, bestArea),
    area: pct(area, viewport.width * viewport.height),
    heightShare: pct(rect.height, viewport.height),
    slideWidth: Math.round(rect.width),
    slideHeight: Math.round(rect.height),
  };
}

function stats(values) {
  const v = values.filter((x) => typeof x === 'number').sort((a, b) => a - b);
  if (!v.length) return { median: null, p95: null, max: null };
  const at = (q) => v[Math.min(v.length - 1, Math.floor(q * (v.length - 1)))];
  return { median: at(0.5), p95: at(0.95), max: v[v.length - 1] };
}

async function runDeck({ name, browser, renderer, enrich, assetBase, outDir }) {
  const started = Date.now();
  const dir = path.join(outDir, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const deck = enrich(loadDeck(name, assetBase));
  const fourThree = deck.aspectRatio === '4:3';
  const aspect = fourThree ? 4 / 3 : 16 / 9;
  const errors = [];

  // Reference: the editor's own rendering (export render page).
  log(name, 'reference');
  const refShots = await renderer.renderDeckImages(deck, { format: 'png', scale: 960 / (fourThree ? 1600 : 1920) });
  refShots.forEach((shot, i) => fs.writeFileSync(path.join(dir, `ref-${String(i + 1).padStart(3, '0')}.png`), shot.data));

  log(name, 'payload');
  const payload = await presentPayload(deck);
  log(name, 'open page');
  const count = payload.slides.length;
  const page = await openPresentPage(browser, VIEW);
  const changes = [];
  let timeouts = 0;
  let screen = null;
  try {
    const openStarted = Date.now();
    await openDeck(page, payload, 0);
    log(name, 'opened');
    const openMs = Date.now() - openStarted;
    screen = fillOf(await page.evaluate(() => window.__athenaPresent.probe.snapshot().slideRect), VIEW, aspect);
    await page.screenshot({ path: path.join(dir, 'screen.png') });
    await shootSlide(page, path.join(dir, 'present-001.png'));
    await page.bringToFront();
    await page.evaluate(() => window.__athenaPresent.probe.start());
    // Forward through every slide (screenshot each), then back to the first.
    for (let i = 1; i < count; i += 1) {
      await page.keyboard.press('ArrowRight');
      if (!(await waitSettled(page))) timeouts += 1;
      await sleep(200);
      await shootSlide(page, path.join(dir, `present-${String(i + 1).padStart(3, '0')}.png`));
    }
    for (let i = count - 1; i > 0; i -= 1) {
      await page.keyboard.press('ArrowLeft');
      if (!(await waitSettled(page))) timeouts += 1;
      await sleep(120);
    }
    log(name, 'stepped');
    const recorded = await page.evaluate(() => window.__athenaPresent.probe.stop());
    changes.push(...recorded.changes);
    errors.push(...page.__errors);

    const slides = [];
    for (let i = 0; i < count; i += 1) {
      const n = String(i + 1).padStart(3, '0');
      const ref = path.join(dir, `ref-${n}.png`);
      const shot = path.join(dir, `present-${n}.png`);
      const value = fs.existsSync(ref) ? await score(ref, shot, aspect) : null;
      if (fs.existsSync(ref)) await thumb(ref, path.join(dir, `t-ref-${n}.jpg`));
      if (fs.existsSync(shot)) await thumb(shot, path.join(dir, `t-present-${n}.jpg`));
      // Present plays embeds; the reference draws them as cards, so those slides differ on purpose.
      const hasEmbed = (payload.slides[i]?.elements?.elements || []).some((el) => el.type === 'embed');
      slides.push({ n: i + 1, id: payload.slides[i]?.id, ssim: value, hasEmbed });
    }
    await thumb(path.join(dir, 'screen.png'), path.join(dir, 't-screen.jpg'), 640);

    const settle = stats(changes.map((c) => c.settleMs));
    const mean = (list) => (list.length ? Math.round((list.reduce((a, b) => a + b, 0) / list.length) * 1000) / 1000 : null);
    const ssims = slides.map((s) => s.ssim).filter((x) => typeof x === 'number');
    const plain = slides.filter((s) => !s.hasEmbed).map((s) => s.ssim).filter((x) => typeof x === 'number');
    return {
      name,
      aspectRatio: deck.aspectRatio || '16:9',
      slides,
      ssim: {
        mean: mean(ssims),
        min: ssims.length ? Math.min(...ssims) : null,
        meanWithoutEmbeds: mean(plain),
        minWithoutEmbeds: plain.length ? Math.min(...plain) : null,
      },
      openMs,
      screen,
      changes: {
        count: changes.length,
        settleMs: settle,
        blankFrames: changes.reduce((a, c) => a + c.blankFrames, 0),
        changesWithBlank: changes.filter((c) => c.blankFrames > 0).length,
        popInFrames: changes.reduce((a, c) => a + c.popInFrames, 0),
        changesWithPopIn: changes.filter((c) => c.popInFrames > 0).length,
        embedsCreated: changes.reduce((a, c) => a + c.iframesCreated, 0),
        timeouts,
        detail: changes,
      },
      seconds: Math.round((Date.now() - started) / 1000),
      errors,
    };
  } finally {
    await page.close();
  }
}

// ── Screen pass ────────────────────────────────────────────────────────────────

async function runScreens({ browser, names, enrich, assetBase, outDir }) {
  const sixteen = names.find((n) => n === 'ai-light') || names.find((n) => !/four-three/.test(n));
  const four = names.find((n) => n === 'four-three');
  const picks = [sixteen, four].filter(Boolean);
  const dir = path.join(outDir, 'screens');
  fs.mkdirSync(dir, { recursive: true });
  const rows = [];
  for (const name of picks) {
    const deck = enrich(loadDeck(name, assetBase));
    const aspect = deck.aspectRatio === '4:3' ? 4 / 3 : 16 / 9;
    const payload = await presentPayload(deck);
    for (const s of SCREENS) {
      const viewport = {
        width: s.width,
        height: s.height,
        ...(s.mobile ? { deviceScaleFactor: 2, isMobile: true, hasTouch: true } : {}),
      };
      const page = await openPresentPage(browser, viewport);
      try {
        await openDeck(page, payload, Math.min(1, payload.slides.length - 1));
        const rect = await page.evaluate(() => window.__athenaPresent.probe.snapshot().slideRect);
        const file = path.join(dir, `${name}-${s.id}.png`);
        await page.screenshot({ path: file });
        await thumb(file, path.join(dir, `t-${name}-${s.id}.jpg`), 320);
        rows.push({ deck: name, screen: s.id, label: s.label, aspectRatio: deck.aspectRatio || '16:9', ...fillOf(rect, s, aspect) });
        process.stdout.write('.');
      } finally {
        await page.close();
      }
    }
  }
  process.stdout.write('\n');
  return rows;
}

// ── Report ─────────────────────────────────────────────────────────────────────

const esc = (v) =>
  String(v ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const num = (v, d = 0) => (v == null ? '—' : Number(v).toFixed(d));

function cell(value, { good, before, digits = 0, lowerIsBetter = false, suffix = '' }) {
  if (value == null) return '<td class="na">—</td>';
  const ok = good == null ? null : lowerIsBetter ? value <= good : value >= good;
  const cls = ok == null ? '' : ok ? 'ok' : 'low';
  const was = before == null ? '' : ` <small>(was ${num(before, digits)}${suffix})</small>`;
  return `<td class="${cls}">${num(value, digits)}${suffix}${was}</td>`;
}

function writeReport(outDir, result, compare) {
  const prev = (deck) => compare?.decks?.[deck] || null;
  const prevScreen = (deck, screen) => compare?.screens?.find((r) => r.deck === deck && r.screen === screen) || null;
  const summary = Object.values(result.decks)
    .map((d) => {
      const p = prev(d.name);
      return (
        `<tr><th><a href="#${esc(d.name)}">${esc(d.name)}</a></th><td>${d.slides.length}</td>` +
        cell(d.ssim.meanWithoutEmbeds, { good: 0.98, before: p?.ssim?.meanWithoutEmbeds, digits: 3 }) +
        cell(d.ssim.minWithoutEmbeds, { good: 0.95, before: p?.ssim?.minWithoutEmbeds, digits: 3 }) +
        cell(d.screen?.fill, { good: 99, before: p?.screen?.fill, digits: 1, suffix: '%' }) +
        `<td>${d.changes.count}</td>` +
        cell(d.changes.settleMs.median, { good: 100, before: p?.changes?.settleMs?.median, lowerIsBetter: true, suffix: ' ms' }) +
        cell(d.changes.settleMs.p95, { good: 1000, before: p?.changes?.settleMs?.p95, lowerIsBetter: true, suffix: ' ms' }) +
        cell(d.changes.blankFrames, { good: 0, before: p?.changes?.blankFrames, lowerIsBetter: true }) +
        `<td>${d.changes.changesWithBlank} / ${d.changes.count}</td>` +
        cell(d.changes.popInFrames, { good: 0, before: p?.changes?.popInFrames, lowerIsBetter: true }) +
        cell(d.changes.embedsCreated, { before: p?.changes?.embedsCreated }) +
        `<td>${d.changes.timeouts}</td><td>${d.seconds}s</td><td class="err">${esc(d.errors.join('; '))}</td></tr>`
      );
    })
    .join('');
  const screens = (result.screens || [])
    .map((r) => {
      const p = prevScreen(r.deck, r.screen);
      return (
        `<tr><td>${esc(r.label)}</td><td>${esc(r.deck)} (${esc(r.aspectRatio)})</td>` +
        cell(r.fill, { good: 99, before: p?.fill, digits: 1, suffix: '%' }) +
        cell(r.area, { before: p?.area, digits: 1, suffix: '%' }) +
        `<td>${r.slideWidth} × ${r.slideHeight}</td><td><img src="screens/t-${esc(r.deck)}-${esc(r.screen)}.jpg"></td></tr>`
      );
    })
    .join('');
  const decks = Object.values(result.decks)
    .map(
      (d) =>
        `<h2 id="${esc(d.name)}">${esc(d.name)}</h2><p>Whole screen at 1920 × 1080, slide 1:</p><img class="screen" src="${esc(d.name)}/t-screen.jpg">` +
        `<table class="slides"><tr><th>#</th><th>Editor (reference)</th><th>Present</th><th>SSIM</th></tr>` +
        d.slides
          .map((s) => {
            const n = String(s.n).padStart(3, '0');
            const was = prev(d.name)?.slides?.find((x) => x.n === s.n)?.ssim;
            return `<tr><td>${s.n}<br><small>${esc(s.id)}${s.hasEmbed ? '<br>embed: plays in Present, a card in the editor' : ''}</small></td><td><img src="${esc(d.name)}/t-ref-${n}.jpg"></td><td><img src="${esc(d.name)}/t-present-${n}.jpg"></td>${cell(s.ssim, { good: 0.98, before: was, digits: 3 })}</tr>`;
          })
          .join('') +
        '</table>'
    )
    .join('');
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Present — ${esc(result.label)}</title><style>
body{font:14px system-ui,sans-serif;margin:24px;color:#0f172a;background:#fff}
table{border-collapse:collapse;margin:12px 0}td,th{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}
.ok{background:#dcfce7}.low{background:#fee2e2}.na{color:#94a3b8}.err{color:#b91c1c;max-width:360px}
.slides img{width:${THUMB_WIDTH}px;display:block}img.screen{width:640px;border:1px solid #e2e8f0}small{color:#64748b}
</style></head><body><h1>Present — ${esc(result.label)}</h1>
<p>${esc(result.date)} · frontend page ${esc(result.presentUrl)} · picture latency ${result.assetLatencyMs} ms${compare ? ` · compared with <b>${esc(compare.label)}</b>` : ''}</p>
<p>Targets (PRESENT_MODE_PRODUCTION_PLAN.md): fill 100% of the largest slide-shaped box on screen; 0 blank frames; settle under 100 ms (p95 under 1 s); SSIM ≥ 0.98 against the editor. Slide changes are arrow-key presses forward through the deck and back. SSIM leaves out slides with an embed (Present plays it; the editor shows a card).</p>
<h2>Decks at 1920 × 1080</h2>
${(result.failed || []).map((f) => `<p class="err">${esc(f.name)} failed: ${esc(f.error)}</p>`).join('')}
<table><tr><th>Deck</th><th>Slides</th><th>SSIM mean</th><th>SSIM min</th><th>Fill</th><th>Changes</th><th>Settle median</th><th>Settle p95</th><th>Blank frames</th><th>Changes with a blank</th><th>Pop-in frames</th><th>Embeds created</th><th>Timeouts</th><th>Time</th><th>Errors</th></tr>${summary}</table>
<h2>Screens</h2><p>Fill: slide area ÷ the largest box of the slide's shape that fits the screen. Area: slide area ÷ screen area.</p>
<table><tr><th>Screen</th><th>Deck</th><th>Fill</th><th>Area</th><th>Slide size (px)</th><th>Screenshot</th></tr>${screens}</table>
${decks}</body></html>`;
  fs.writeFileSync(path.join(outDir, 'report.html'), html);
}

// ── Main ───────────────────────────────────────────────────────────────────────

function gitDescribe(dir) {
  try {
    const sha = execFileSync('git', ['-C', dir, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['-C', dir, 'status', '--porcelain', '--', 'src'], { encoding: 'utf8' }).trim();
    return dirty ? `${sha}+local changes` : sha;
  } catch {
    return 'unknown';
  }
}

async function main() {
  const label = arg('label', 'current');
  const outDir = path.resolve(ROOT, arg('out', '.eval/present'), label);
  const names = (arg('decks') || allDeckNames().join(','))
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const compare = arg('compare') ? JSON.parse(fs.readFileSync(path.resolve(arg('compare')), 'utf8')) : null;
  for (const url of [PRESENT_URL, RENDER_URL]) {
    const probe = await fetch(url).catch((err) => ({ ok: false, statusText: err.message }));
    if (!probe.ok) {
      throw new Error(`Not reachable: ${url} (${probe.status || probe.statusText}). Start the frontend (npm run dev) or pass --present-url / --render-url.`);
    }
  }

  const server = await startAssetServer();
  const assetBase = `http://127.0.0.1:${server.address().port}`;
  stubS3(assetBase);
  const enrich = require(path.join(PRESENTATION, 'presignSlideMedia.js')).enrichDeckMediaKeysForExport;
  const renderer = require(path.join(PRESENTATION, 'exportRenderer.service.js'));
  const browser = await puppeteer.launch({ headless: !flag('headful'), args: ['--no-sandbox'] });

  fs.mkdirSync(outDir, { recursive: true });
  const result = {
    label,
    date: new Date().toISOString(),
    presentUrl: PRESENT_URL,
    frontend: arg('frontend-sha') || null,
    backend: gitDescribe(ROOT),
    assetLatencyMs: ASSET_LATENCY_MS,
    decks: {},
    screens: [],
  };
  try {
    for (const name of names) {
      process.stdout.write(`${name.padEnd(16)} `);
      let d;
      try {
        d = await runDeck({ name, browser, renderer, enrich, assetBase, outDir });
      } catch (err) {
        console.log(`ERROR ${String(err.stack || err).slice(0, 600)}`);
        result.failed = [...(result.failed || []), { name, error: String(err.message || err).slice(0, 300) }];
        continue;
      }
      result.decks[name] = d;
      const c = d.changes;
      console.log(
        `SSIM ${num(d.ssim.meanWithoutEmbeds, 3)} (min ${num(d.ssim.minWithoutEmbeds, 3)})  fill ${num(d.screen?.fill, 1)}%  settle ${num(c.settleMs.median)}/${num(c.settleMs.p95)} ms  ` +
          `blank ${c.blankFrames} (${c.changesWithBlank}/${c.count})  pop-in ${c.popInFrames}  embeds ${c.embedsCreated}` +
          `${c.timeouts ? `  timeouts ${c.timeouts}` : ''}  ${d.seconds}s${d.errors.length ? `  ! ${d.errors.join('; ')}` : ''}`
      );
    }
    if (!flag('skip-screens')) {
      process.stdout.write('screens ');
      result.screens = await runScreens({ browser, names: allDeckNames(), enrich, assetBase, outDir });
    }
  } finally {
    log('closing');
    await browser.close();
    log('browser closed');
    server.close();
    // The shared export browser (reference pictures); don't wait on it for long.
    await Promise.race([
      Promise.resolve(require(path.join(ROOT, 'src/shared/utils/exportBrowser')).closeSharedBrowser?.()).catch(() => {}),
      sleep(5000),
    ]);
  }
  log('writing report');
  fs.writeFileSync(path.join(outDir, 'scores.json'), `${JSON.stringify(result, null, 2)}\n`);
  writeReport(outDir, result, compare);
  console.log(`\nReport: ${path.join(outDir, 'report.html')}`);
  process.exit(0);
}

process.on('beforeExit', (code) => log('beforeExit', code));

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
