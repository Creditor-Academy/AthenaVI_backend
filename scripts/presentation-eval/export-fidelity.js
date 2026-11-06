/**
 * Phase 0.3 — export fidelity harness: how close PDF and PPTX exports are to the editor.
 *
 *   node scripts/presentation-eval/export-fidelity.js [options]
 *
 *   --decks a,b          golden decks to run (default: all in test/fixtures/export)
 *   --label name         report folder name (default: current)
 *   --out dir            output root (default: .eval/export-fidelity)
 *   --backend dir        backend checkout whose export code is measured (default: this one).
 *                        Point it at an older checkout (git worktree) to measure a baseline.
 *   --render-url url     the editor renderer page (default: EXPORT_RENDER_URL, else
 *                        http://localhost:5173/export-render.html — run the frontend dev server)
 *   --compare file       an earlier scores.json: the report shows the change against it
 *   --skip-pptx          PDF only (no LibreOffice needed)
 *   --no-fonts           don't embed the deck's fonts in the PPTX (they are by default, as in a
 *                        PowerPoint export)
 *   --legacy             measure the fallback renderer (PPT_EXPORT_RENDERER=legacy) instead of
 *                        the render page; the reference is still the render page
 *   --legacy-pdf-timeout ms  page timeout for an old checkout's PDF (default 60000)
 *
 * For every slide of every deck:
 *   reference = the editor's own rendering (export-render page, the same component as the editor)
 *   PDF       = export → rasterized
 *   PPTX      = export → LibreOffice → PDF → rasterized (LibreOffice stands in for PowerPoint)
 * and SSIM (0–1, 1 = identical) of each against the reference. Writes report.html and
 * scores.json. Thresholds (Phase 3 / 4 targets): PDF ≥ 0.98, PPTX ≥ 0.95. Images are compared at
 * 480px wide, grayscale, blurred σ 1 (anti-aliasing isn't a difference).
 *
 * Needs: the frontend render page, LibreOffice (`soffice`, or SOFFICE_PATH), and a PDF
 * rasterizer — `pdftoppm` (poppler-utils) or Python with `pypdfium2`.
 *
 * Pictures: the decks reference S3 keys under golden/. S3 is replaced here by the files in
 * test/fixtures/export/assets (read for PPTX, served over HTTP for presigned URLs), so media
 * behaves as in production. Any other key is missing, as it would be in production.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '../..');
const FIXTURES = path.join(ROOT, 'src/modules/presentation/test/fixtures/export');
const ASSETS = path.join(FIXTURES, 'assets');
const PDF_TARGET = 0.98;
const PPTX_TARGET = 0.95;
const COMPARE_WIDTH = 480;
const THUMB_WIDTH = 480;
const LEGACY_PDF_TIMEOUT_MS = Number(arg('legacy-pdf-timeout')) || 60_000;

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}
const flag = (name) => process.argv.includes(`--${name}`);

// ── Environment (before any export module loads) ────────────────────────────────
process.env.AWS_S3_BUCKET = 'athena-golden';
process.env.AWS_REGION = process.env.AWS_REGION || 'us-east-1';
process.env.PPT_EXPORT_BROWSER_CHECK = '0';
const RENDER_URL = arg('render-url') || process.env.EXPORT_RENDER_URL || 'http://localhost:5173/export-render.html';
process.env.EXPORT_RENDER_URL = RENDER_URL;
delete process.env.PPT_EXPORT_RENDERER;

const sharp = require('sharp');

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
    res.writeHead(200, {
      'content-type': file.endsWith('.png') ? 'image/png' : 'image/jpeg',
      'access-control-allow-origin': '*',
    });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

function stubS3(tree, assetBase) {
  const s3 = require(path.join(tree, 'src/modules/s3/s3.service'));
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

function loadDeck(name, assetBase) {
  const raw = fs.readFileSync(path.join(FIXTURES, `${name}.json`), 'utf8');
  return JSON.parse(raw.replaceAll('{{EXTERNAL}}', `${assetBase}/external`));
}

// ── Tools ──────────────────────────────────────────────────────────────────────

function findSoffice() {
  const candidates = [
    process.env.SOFFICE_PATH,
    'C:\\Program Files\\LibreOffice\\program\\soffice.com',
    'C:\\Program Files\\LibreOffice\\program\\soffice.exe',
    '/Applications/LibreOffice.app/Contents/MacOS/soffice',
    '/usr/bin/soffice',
    '/usr/bin/libreoffice',
  ].filter(Boolean);
  const found = candidates.find((c) => fs.existsSync(c));
  if (found) return found;
  const which = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['soffice'], { encoding: 'utf8' });
  return which.status === 0 ? which.stdout.split(/\r?\n/)[0].trim() : null;
}

function findRasterizer() {
  if (spawnSync('pdftoppm', ['-v'], { encoding: 'utf8' }).status === 0) return { kind: 'pdftoppm' };
  for (const python of ['python3', 'python']) {
    const probe = spawnSync(python, ['-I', '-c', 'import pypdfium2'], { encoding: 'utf8' });
    if (probe.status === 0) return { kind: 'pypdfium2', python };
  }
  return null;
}

/** PDF → page-001.png … at `width` px. Returns the PNG paths in page order. */
function rasterizePdf(rasterizer, pdfPath, outDir, width) {
  fs.mkdirSync(outDir, { recursive: true });
  if (rasterizer.kind === 'pdftoppm') {
    execFileSync('pdftoppm', ['-png', '-scale-to-x', String(width), '-scale-to-y', '-1', pdfPath, path.join(outDir, 'page')]);
  } else {
    execFileSync(rasterizer.python, ['-I', path.join(__dirname, 'rasterize_pdf.py'), pdfPath, outDir, String(width)]);
  }
  return fs
    .readdirSync(outDir)
    .filter((f) => /^page-\d+\.png$/.test(f))
    .sort((a, b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0]))
    .map((f) => path.join(outDir, f));
}

function pptxToPdf(soffice, pptxPath, outDir) {
  // A private profile: works even while the user has LibreOffice open.
  const profile = path.join(os.tmpdir(), 'athena-fidelity-lo-profile').replace(/\\/g, '/');
  execFileSync(
    soffice,
    [`-env:UserInstallation=file:///${profile.replace(/^\//, '')}`, '--headless', '--convert-to', 'pdf', '--outdir', outDir, pptxPath],
    { stdio: 'ignore', timeout: 10 * 60 * 1000 }
  );
  const out = path.join(outDir, `${path.basename(pptxPath, '.pptx')}.pdf`);
  if (!fs.existsSync(out)) throw new Error('LibreOffice did not convert the PPTX');
  return out;
}

// ── Similarity ─────────────────────────────────────────────────────────────────

/**
 * Grayscale at the comparison size, lightly blurred (σ 1) so anti-aliasing differences between
 * renderers (Chrome vs a PDF rasterizer) don't read as layout differences.
 */
async function grayscale(file, width, height) {
  const { data } = await sharp(file)
    .flatten({ background: '#ffffff' })
    .resize(width, height, { fit: 'fill' })
    .blur(1)
    .grayscale()
    .raw()
    .toBuffer({ resolveWithObject: true });
  return data;
}

/** Mean SSIM over 8×8 windows (stride 4) of two same-size grayscale images. */
function ssim(a, b, width, height) {
  const win = 8;
  const step = 4;
  const C1 = (0.01 * 255) ** 2;
  const C2 = (0.03 * 255) ** 2;
  const n = win * win;
  let total = 0;
  let count = 0;
  for (let y = 0; y + win <= height; y += step) {
    for (let x = 0; x + win <= width; x += step) {
      let sa = 0;
      let sb = 0;
      let saa = 0;
      let sbb = 0;
      let sab = 0;
      for (let j = 0; j < win; j += 1) {
        let i = (y + j) * width + x;
        for (let k = 0; k < win; k += 1, i += 1) {
          const va = a[i];
          const vb = b[i];
          sa += va;
          sb += vb;
          saa += va * va;
          sbb += vb * vb;
          sab += va * vb;
        }
      }
      const ma = sa / n;
      const mb = sb / n;
      const varA = saa / n - ma * ma;
      const varB = sbb / n - mb * mb;
      const cov = sab / n - ma * mb;
      total += ((2 * ma * mb + C1) * (2 * cov + C2)) / ((ma * ma + mb * mb + C1) * (varA + varB + C2));
      count += 1;
    }
  }
  return count ? total / count : 0;
}

async function score(referenceFile, candidateFile, aspect) {
  if (!candidateFile || !fs.existsSync(candidateFile)) return null;
  const height = Math.round(COMPARE_WIDTH / aspect);
  const [a, b] = await Promise.all([
    grayscale(referenceFile, COMPARE_WIDTH, height),
    grayscale(candidateFile, COMPARE_WIDTH, height),
  ]);
  return Math.round(ssim(a, b, COMPARE_WIDTH, height) * 1000) / 1000;
}

async function thumb(file, out) {
  await sharp(file).flatten({ background: '#ffffff' }).resize({ width: THUMB_WIDTH }).jpeg({ quality: 72 }).toFile(out);
}

// ── One deck ──────────────────────────────────────────────────────────────────

async function runDeck({ name, current, measured, assetBase, outDir, soffice, rasterizer, skipPptx, legacy }) {
  const started = Date.now();
  const dir = path.join(outDir, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const deckRaw = loadDeck(name, assetBase);
  const fourThree = deckRaw.aspectRatio === '4:3';
  const aspect = fourThree ? 4 / 3 : 16 / 9;
  const width = COMPARE_WIDTH * 2;
  const errors = [];

  // Reference: the editor's own rendering.
  const refShots = await current.renderer.renderDeckImages(current.enrich(deckRaw), {
    format: 'png',
    scale: width / (fourThree ? 1600 : 1920),
  });
  const refFiles = refShots.map((shot, i) => {
    const file = path.join(dir, `ref-${String(i + 1).padStart(3, '0')}.png`);
    fs.writeFileSync(file, shot.data);
    return file;
  });

  // PDF, by the export code being measured.
  const deck = measured.enrich(deckRaw);
  if (legacy) process.env.PPT_EXPORT_RENDERER = 'legacy';
  let pdfPages = [];
  try {
    const pdf = await measured.buildPdf(deck, {});
    fs.writeFileSync(path.join(dir, 'export.pdf'), pdf);
    pdfPages = rasterizePdf(rasterizer, path.join(dir, 'export.pdf'), path.join(dir, 'pdf'), width);
  } catch (err) {
    errors.push(`PDF: ${String(err.message || err).slice(0, 200)}`);
  }

  // PPTX → LibreOffice → PDF.
  let pptxPages = [];
  if (!skipPptx) {
    try {
      const assets = measured.renderer?.capturePptxAssets ? await measured.renderer.capturePptxAssets(deck) : null;
      // Fonts embedded like a PowerPoint export (LibreOffice reads them), unless --no-fonts.
      const pptx = await measured.exportService.buildPptxBuffer(deck, { ...(assets ? { assets } : {}), embedFonts: !flag('no-fonts') });
      const pptxPath = path.join(dir, 'export.pptx');
      fs.writeFileSync(pptxPath, pptx);
      pptxPages = rasterizePdf(rasterizer, pptxToPdf(soffice, pptxPath, path.join(dir, 'lo')), path.join(dir, 'pptx'), width);
    } catch (err) {
      errors.push(`PPTX: ${String(err.message || err).slice(0, 200)}`);
    }
  }

  delete process.env.PPT_EXPORT_RENDERER;

  const slides = [];
  for (const [i, ref] of refFiles.entries()) {
    const n = String(i + 1).padStart(3, '0');
    const pdf = await score(ref, pdfPages[i], aspect);
    const pptx = skipPptx ? null : await score(ref, pptxPages[i], aspect);
    await thumb(ref, path.join(dir, `t-ref-${n}.jpg`));
    if (pdfPages[i]) await thumb(pdfPages[i], path.join(dir, `t-pdf-${n}.jpg`));
    if (pptxPages[i]) await thumb(pptxPages[i], path.join(dir, `t-pptx-${n}.jpg`));
    slides.push({ n: i + 1, id: deckRaw.slides[i]?.id, layoutId: deckRaw.slides[i]?.layoutId || null, pdf, pptx });
  }
  if (pdfPages.length && pdfPages.length !== refFiles.length) errors.push(`PDF has ${pdfPages.length} pages for ${refFiles.length} slides`);
  if (pptxPages.length && pptxPages.length !== refFiles.length) errors.push(`PPTX has ${pptxPages.length} slides for ${refFiles.length}`);
  refFiles.forEach((f) => fs.rmSync(f));

  const stats = (key) => {
    const values = slides.map((s) => s[key] ?? 0);
    if (!values.length) return { mean: null, min: null };
    return {
      mean: Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 1000) / 1000,
      min: Math.min(...values),
    };
  };
  return {
    name,
    slides,
    pdf: stats('pdf'),
    pptx: skipPptx ? null : stats('pptx'),
    errors,
    seconds: Math.round((Date.now() - started) / 1000),
  };
}

// ── Report ────────────────────────────────────────────────────────────────────

const esc = (v) =>
  String(v ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const fmt = (v) => (v == null ? '—' : v.toFixed(3));

function scoreCell(value, target, before) {
  if (value == null) return '<td class="na">—</td>';
  const delta = before != null ? value - before : null;
  const deltaText =
    delta == null ? '' : ` <small class="${delta >= 0 ? 'up' : 'down'}">${delta >= 0 ? '+' : ''}${delta.toFixed(3)}</small>`;
  return `<td class="${value >= target ? 'ok' : 'low'}">${value.toFixed(3)}${deltaText}</td>`;
}

function writeReport(outDir, result, compare) {
  const was = (deck, key) => compare?.decks?.[deck]?.[key]?.mean ?? null;
  const wasSlide = (deck, n, key) => compare?.decks?.[deck]?.slides?.find((s) => s.n === n)?.[key] ?? null;
  const summary = Object.values(result.decks)
    .map(
      (d) =>
        `<tr><th><a href="#${esc(d.name)}">${esc(d.name)}</a></th><td>${d.slides.length}</td>` +
        `${scoreCell(d.pdf.mean, PDF_TARGET, was(d.name, 'pdf'))}<td>${fmt(d.pdf.min)}</td>` +
        `${d.pptx ? scoreCell(d.pptx.mean, PPTX_TARGET, was(d.name, 'pptx')) : '<td>—</td>'}<td>${fmt(d.pptx?.min)}</td>` +
        `<td>${d.seconds}s</td><td class="err">${esc(d.errors.join('; '))}</td></tr>`
    )
    .join('');
  const detail = (d, s, key) => {
    const n = String(s.n).padStart(3, '0');
    const before = wasSlide(d.name, s.n, key);
    return `<td><img src="${esc(d.name)}/t-${key}-${n}.jpg" alt="missing"><br>${fmt(s[key])}${before != null ? ` <small>(was ${fmt(before)})</small>` : ''}</td>`;
  };
  const decks = Object.values(result.decks)
    .map(
      (d) =>
        `<h2 id="${esc(d.name)}">${esc(d.name)}</h2><table class="slides"><tr><th>#</th><th>Editor (reference)</th><th>PDF</th><th>PPTX (LibreOffice)</th></tr>` +
        d.slides
          .map((s) => {
            const n = String(s.n).padStart(3, '0');
            return `<tr><td>${s.n}<br><small>${esc(s.layoutId || s.id)}</small></td><td><img src="${esc(d.name)}/t-ref-${n}.jpg"></td>${detail(d, s, 'pdf')}${detail(d, s, 'pptx')}</tr>`;
          })
          .join('') +
        '</table>'
    )
    .join('');
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Export fidelity — ${esc(result.label)}</title><style>
body{font:14px system-ui,sans-serif;margin:24px;color:#0f172a;background:#fff}
table{border-collapse:collapse;margin:12px 0}td,th{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;vertical-align:top}
.ok{background:#dcfce7}.low{background:#fee2e2}.na{color:#94a3b8}.err{color:#b91c1c;max-width:420px}
small.up{color:#15803d}small.down{color:#b91c1c}.slides img{width:${THUMB_WIDTH}px;display:block}
</style></head><body><h1>Export fidelity — ${esc(result.label)}</h1>
<p>${esc(result.date)} · backend ${esc(result.backend)} · renderer ${esc(result.renderUrl)}${compare ? ` · compared with <b>${esc(compare.label)}</b> (backend ${esc(compare.backend)})` : ''}</p>
<p>SSIM against the editor's own rendering (1 = identical). Targets: PDF ≥ ${PDF_TARGET}, PPTX ≥ ${PPTX_TARGET}. PPTX is drawn by LibreOffice as a stand-in for PowerPoint, with the fonts installed on this machine.</p>
<table><tr><th>Deck</th><th>Slides</th><th>PDF mean</th><th>PDF min</th><th>PPTX mean</th><th>PPTX min</th><th>Time</th><th>Errors</th></tr>${summary}</table>${decks}</body></html>`;
  fs.writeFileSync(path.join(outDir, 'report.html'), html);
}

// ── Main ──────────────────────────────────────────────────────────────────────

/**
 * Older checkouts don't export buildPdfBuffer: build the PDF the way their processExport did —
 * that checkout's slideHtml, networkidle0, page.pdf scaled to the slide size.
 */
function legacyPdfBuilder(presentation) {
  const { buildDeckHtml } = require(path.join(presentation, 'slideHtml.js'));
  const { resolveAspectCanvas } = require(path.join(presentation, 'presentation.constants.js'));
  const { withExportPage } = require(path.join(ROOT, 'src/shared/utils/exportBrowser'));
  return (deck, opts = {}) =>
    withExportPage(async (page) => {
      const aspect = resolveAspectCanvas(deck.aspectRatio);
      await page.setViewport({ width: aspect.width, height: aspect.height });
      const open = new Map();
      page.on('request', (r) => open.set(r, Date.now()));
      page.on('requestfinished', (r) => open.delete(r));
      page.on('requestfailed', (r) => open.delete(r));
      try {
        await page.setContent(await buildDeckHtml(deck, opts), { waitUntil: 'networkidle0', timeout: LEGACY_PDF_TIMEOUT_MS });
      } catch (err) {
        const pending = [...open.keys()].map((r) => `${r.resourceType()} ${r.url().slice(0, 80)}`);
        throw new Error(`${err.message}; still loading: ${pending.slice(0, 3).join(', ') || 'nothing'}`);
      }
      const pdf = await page.pdf({
        width: `${aspect.pptxWidthIn}in`,
        height: `${aspect.pptxHeightIn}in`,
        scale: (aspect.pptxWidthIn * 96) / aspect.width,
        printBackground: true,
        margin: { top: 0, right: 0, bottom: 0, left: 0 },
      });
      return Buffer.from(pdf);
    });
}

function loadTree(tree) {
  const presentation = path.join(tree, 'src/modules/presentation');
  const rendererPath = path.join(presentation, 'exportRenderer.service.js');
  const exportService = require(path.join(presentation, 'export.service.js'));
  return {
    exportService,
    buildPdf: exportService.buildPdfBuffer || legacyPdfBuilder(presentation),
    enrich: require(path.join(presentation, 'presignSlideMedia.js')).enrichDeckMediaKeysForExport,
    renderer: fs.existsSync(rendererPath) ? require(rendererPath) : null,
  };
}

function gitDescribe(tree) {
  try {
    const sha = execFileSync('git', ['-C', tree, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['-C', tree, 'status', '--porcelain', '--', 'src'], { encoding: 'utf8' }).trim();
    return dirty ? `${sha}+local changes` : sha;
  } catch {
    return 'unknown';
  }
}

async function main() {
  const label = arg('label', 'current');
  const outDir = path.resolve(ROOT, arg('out', '.eval/export-fidelity'), label);
  const tree = path.resolve(arg('backend', ROOT));
  const skipPptx = flag('skip-pptx');
  const names = (
    arg('decks') ||
    fs
      .readdirSync(FIXTURES)
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.replace(/\.json$/, ''))
      .join(',')
  )
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const compare = arg('compare') ? JSON.parse(fs.readFileSync(path.resolve(arg('compare')), 'utf8')) : null;

  const soffice = skipPptx ? null : findSoffice();
  if (!skipPptx && !soffice) throw new Error('LibreOffice not found: install it, set SOFFICE_PATH, or pass --skip-pptx');
  const rasterizer = findRasterizer();
  if (!rasterizer) throw new Error('No PDF rasterizer: install poppler-utils (pdftoppm) or `pip install pypdfium2`');
  const probe = await fetch(RENDER_URL).catch((err) => ({ ok: false, statusText: err.message }));
  if (!probe.ok) {
    throw new Error(`Render page not reachable at ${RENDER_URL} (${probe.status || probe.statusText}). Start the frontend (npm run dev) or pass --render-url.`);
  }

  const server = await startAssetServer();
  const assetBase = `http://127.0.0.1:${server.address().port}`;
  const current = loadTree(ROOT);
  if (!current.renderer) throw new Error('This checkout has no exportRenderer.service.js: the reference needs it');
  const measured = tree === ROOT ? current : loadTree(tree);
  stubS3(ROOT, assetBase);
  if (tree !== ROOT) stubS3(tree, assetBase);

  fs.mkdirSync(outDir, { recursive: true });
  const result = {
    label,
    legacyRenderer: flag('legacy'),
    date: new Date().toISOString(),
    backend: gitDescribe(tree),
    renderUrl: RENDER_URL,
    rasterizer: rasterizer.kind,
    decks: {},
  };
  try {
    for (const name of names) {
      process.stdout.write(`${name.padEnd(14)} `);
      const deck = await runDeck({ name, current, measured, assetBase, outDir, soffice, rasterizer, skipPptx, legacy: flag('legacy') });
      result.decks[name] = deck;
      console.log(
        `PDF ${fmt(deck.pdf.mean)} (min ${fmt(deck.pdf.min)})` +
          (deck.pptx ? `  PPTX ${fmt(deck.pptx.mean)} (min ${fmt(deck.pptx.min)})` : '') +
          `  ${deck.seconds}s${deck.errors.length ? `  ! ${deck.errors.join('; ')}` : ''}`
      );
    }
  } finally {
    server.close();
  }
  fs.writeFileSync(path.join(outDir, 'scores.json'), `${JSON.stringify(result, null, 2)}\n`);
  writeReport(outDir, result, compare);
  console.log(`\nReport: ${path.join(outDir, 'report.html')}`);
  process.exit(0);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
