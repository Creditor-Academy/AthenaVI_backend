/**
 * Helpers for presentation export jobs: heartbeats, the browser concurrency limit, file
 * names and user-facing error messages. Kept free of DB / S3 so they can be unit tested.
 */

/** Formats rendered by the headless browser (PPTX is built in Node). */
const BROWSER_EXPORT_FORMATS = new Set(['PDF', 'PNG', 'JPEG']);

function isBrowserExportFormat(format) {
  return BROWSER_EXPORT_FORMATS.has(String(format || '').toUpperCase());
}

/**
 * A counting semaphore. `acquire()` resolves to a `release` function (safe to call twice)
 * once a slot is free; waiters are served first come, first served.
 */
function createSemaphore(limit) {
  const max = Math.max(1, Math.floor(Number(limit)) || 1);
  let active = 0;
  const waiters = [];

  const makeRelease = () => {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const next = waiters.shift();
      if (next) next(makeRelease());
      else active -= 1;
    };
  };

  return {
    acquire() {
      if (active < max) {
        active += 1;
        return Promise.resolve(makeRelease());
      }
      return new Promise((resolve) => waiters.push(resolve));
    },
    get active() {
      return active;
    },
    get waiting() {
      return waiters.length;
    },
    get limit() {
      return max;
    },
  };
}

/**
 * Call `beat()` every `intervalMs` while `fn()` runs, so a long render is not mistaken
 * for a dead job. Heartbeat failures are ignored.
 */
async function withHeartbeat(beat, fn, intervalMs = 20_000) {
  const timer = setInterval(() => {
    Promise.resolve()
      .then(beat)
      .catch(() => {});
  }, Math.max(10, Number(intervalMs) || 20_000));
  if (typeof timer.unref === 'function') timer.unref();
  try {
    return await fn();
  } finally {
    clearInterval(timer);
  }
}

/** Puppeteer's page timeout for a whole-deck PDF: the base limit, more for big decks. */
function pdfRenderTimeoutMs(slideCount, baseMs = 180_000) {
  const perSlideMs = 8_000;
  const capMs = 15 * 60 * 1000;
  return Math.min(capMs, Math.max(baseMs, (Number(slideCount) || 0) * perSlideMs));
}

function safeFileBase(name) {
  return (
    String(name || 'presentation')
      .replace(/[^\w\s.-]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 80) || 'presentation'
  );
}

function safeExportFilename(name, ext) {
  return `${safeFileBase(name)}.${ext}`;
}

/**
 * Extension of the stored export file. A multi-slide PNG / JPEG export is a .zip, so the
 * stored key is the source of truth; the format is only a fallback.
 */
function exportFileExt(row = {}) {
  const fromKey = /\.([a-z0-9]{2,5})$/i.exec(String(row.s3Key || ''))?.[1];
  if (fromKey) return fromKey.toLowerCase();
  const format = String(row.format || 'pptx').toLowerCase();
  return format === 'jpeg' ? 'jpg' : format;
}

/**
 * A slide image inside a multi-page download, named the way Canva names pages: `3.png`, the
 * slide's page number in the deck. The zip itself carries the deck name (`<Deck>.zip`).
 */
function slideImageFilename(deckName, position, ext) {
  return `${Math.max(1, Math.round(Number(position)) || 1)}.${ext}`;
}

const MESSAGES = {
  browser:
    'PDF and image export is temporarily unavailable. Please try again later, or export as PowerPoint (PPTX).',
  crashed: 'The export stopped unexpectedly. Please try again.',
  memory: 'This presentation was too large to export in one go. Please try again, or export as PowerPoint (PPTX).',
  storage: "We couldn't save the exported file. Please try again.",
  generic: 'Export failed. Please try again.',
};

/**
 * The message stored on the export row and shown to the user. Technical details stay in
 * the server log.
 */
function normalizeExportError(err) {
  const msg = String(err?.message || err || '');
  const statusCode = Number(err?.statusCode || err?.status);

  if (err?.code === 'EXPORT_BROWSER_UNAVAILABLE') return MESSAGES.browser;
  if (
    /could not find (chrome|expected browser)|browser was not found|failed to launch the browser process|spawn \S+ ENOENT|executable doesn't exist|no headless browser/i.test(
      msg
    )
  ) {
    return MESSAGES.browser;
  }
  if (/timeout.*\d{4,7}.*exceeded|navigation timeout|waiting failed.*timeout|timed out/i.test(msg)) {
    const ms = msg.match(/(\d{4,7})\s*ms/)?.[1];
    const hint = ms ? ` (${Math.round(Number(ms) / 1000)}s limit)` : '';
    return `Export rendering timed out${hint}. For large decks use PowerPoint (PPTX), or try again with fewer slides.`;
  }
  if (/target closed|session closed|protocol error|browser has disconnected|page crashed|connection closed/i.test(msg)) {
    return MESSAGES.crashed;
  }
  if (/ENOMEM|out of memory|allocation failed|heap limit/i.test(msg)) return MESSAGES.memory;
  if (/NoSuchBucket|AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch|S3ServiceException/i.test(msg)) {
    return MESSAGES.storage;
  }
  // Our own 4xx errors are already written for the user ("No slides to export", …).
  if (err?.isOperational === true && statusCode >= 400 && statusCode < 500 && msg) {
    return msg.slice(0, 500);
  }
  return MESSAGES.generic;
}

/** Plain words for why something became a picture in a PPTX (pptxCapability reasons). */
const PICTURE_LABELS = [
  [/^curved text/, 'curved text'],
  [/^text effect/, 'text effects'],
  [/^gradient text/, 'gradient text'],
  [/^icon \/ graphic/, 'icons and graphics'],
  [/^image placeholder/, 'empty picture frames'],
  [/^(image mask|clipped image|rounded corners)/, 'photos with a shape mask'],
  [/^image filter/, 'photo filters'],
  [/^edge fade/, 'faded photo edges'],
  [/^image border/, 'photos with a border'],
  [/^device frame/, 'device frames'],
  [/^image in shape/, 'pictures inside shapes'],
  [/^gradient fill/, 'gradient fills'],
  [/^(shadow|effect)/, 'effects'],
  [/border$/, 'shapes with special borders'],
  [/^shape/, 'shapes'],
  [/^embed/, 'embedded media'],
  [/^chart/, 'charts'],
];

function pictureLabel(reason) {
  const r = String(reason || '').toLowerCase();
  return (PICTURE_LABELS.find(([re]) => re.test(r)) || [null, 'other items'])[1];
}

/**
 * What a PPTX contains, for the export dialog: how many objects stayed editable, what became a
 * picture and why (in plain words), the fonts inside the file, native groups, and text boxes
 * grown to show all their text. Built from buildPptxBuffer's report.
 */
function pptxReportSummary(report = {}) {
  const sum = (obj) => Object.values(obj || {}).reduce((n, v) => n + (Number(v) || 0), 0);
  const pictures = new Map();
  for (const [reason, n] of Object.entries(report.pictures || {})) {
    const label = pictureLabel(reason);
    pictures.set(label, (pictures.get(label) || 0) + (Number(n) || 0));
  }
  const family = (name) => String(name || '').replace(/\s*\([^)]*\)\s*$/, '').trim();
  const unique = (list) => [...new Set((list || []).map(family).filter(Boolean))];
  return {
    editable: sum(report.native),
    pictures: [...pictures].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count),
    missing: sum(report.missing),
    fonts: unique(report.fonts?.embedded),
    fontsMissing: unique(report.fonts?.unavailable),
    groups: Number(report.groups?.native) || 0,
    grownText: Number(report.text?.['grown to fit']) || 0,
  };
}

/** Where a PPTX export's report is kept, next to the file. */
function exportReportKey(s3Key) {
  return s3Key ? `${s3Key}.report.json` : null;
}

module.exports = {
  BROWSER_EXPORT_FORMATS,
  isBrowserExportFormat,
  createSemaphore,
  withHeartbeat,
  pdfRenderTimeoutMs,
  safeFileBase,
  safeExportFilename,
  exportFileExt,
  slideImageFilename,
  normalizeExportError,
  pptxReportSummary,
  exportReportKey,
  EXPORT_ERROR_MESSAGES: MESSAGES,
};
