/**
 * Helpers for presentation export jobs: heartbeats, the browser concurrency limit, file
 * names and user-facing error messages. Kept free of DB / S3 so they can be unit tested.
 */

/** Formats rendered by the headless browser (PPTX is built in Node). */
const BROWSER_EXPORT_FORMATS = new Set(['PDF', 'PNG', 'JPEG']);

function isBrowserExportFormat(format) {
  return BROWSER_EXPORT_FORMATS.has(String(format || '').toUpperCase());
}

/** Statuses of an export that is still in progress (it can be cancelled or picked up). */
const ACTIVE_EXPORT_STATUSES = ['QUEUED', 'RENDERING'];
/** The file is uploaded and the credits are being charged: too late to cancel. */
const SAVING_EXPORT_STATUS = 'SAVING';

/**
 * A counting semaphore. `acquire()` resolves to a `release` function (safe to call twice)
 * once a slot is free; waiters are served first come, first served. `acquire({ signal })`
 * stops waiting (and rejects) when the signal aborts.
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
      if (next) next.grant(makeRelease());
      else active -= 1;
    };
  };

  return {
    acquire({ signal = null } = {}) {
      if (signal?.aborted) return Promise.reject(signal.reason || new Error('aborted'));
      if (active < max) {
        active += 1;
        return Promise.resolve(makeRelease());
      }
      return new Promise((resolve, reject) => {
        const waiter = {
          grant(release) {
            signal?.removeEventListener('abort', onAbort);
            resolve(release);
          },
        };
        const onAbort = () => {
          const at = waiters.indexOf(waiter);
          if (at >= 0) waiters.splice(at, 1);
          reject(signal.reason || new Error('aborted'));
        };
        signal?.addEventListener('abort', onAbort, { once: true });
        waiters.push(waiter);
      });
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

const envNumber = (name, fallback) => (Number(process.env[name]) > 0 ? Number(process.env[name]) : fallback);

/** Time per slide an export may take, by format (images also scale with the pixel size). */
const JOB_MS_PER_SLIDE = { PPTX: 20_000, PDF: 10_000, PNG: 8_000, JPEG: 8_000 };

/**
 * How long one export may run once it has started (time waiting in the queue doesn't count):
 * a base allowance plus time per slide, capped. PNG / JPEG at 2× or 3× get more per slide.
 * PPT_EXPORT_JOB_TIMEOUT_BASE_MS (default 2 min) and PPT_EXPORT_JOB_TIMEOUT_MAX_MS (default
 * 30 min) override the limits.
 */
function exportJobTimeoutMs(format, slideCount, { scale = 1 } = {}) {
  const base = envNumber('PPT_EXPORT_JOB_TIMEOUT_BASE_MS', 2 * 60 * 1000);
  const cap = envNumber('PPT_EXPORT_JOB_TIMEOUT_MAX_MS', 30 * 60 * 1000);
  const key = String(format || '').toUpperCase();
  const imageScale = key === 'PNG' || key === 'JPEG' ? Math.max(1, Math.min(3, Number(scale) || 1)) : 1;
  const perSlide = (JOB_MS_PER_SLIDE[key] || 15_000) * imageScale;
  const slides = Math.max(1, Math.floor(Number(slideCount) || 0));
  return Math.min(cap, base + slides * perSlide);
}

/** An export that ran past its time limit (exportJobTimeoutMs). Never retried. */
class ExportTimeoutError extends Error {
  constructor(timeoutMs) {
    super(`Export took longer than its ${Math.round(Number(timeoutMs) / 1000)}s limit`);
    this.name = 'ExportTimeoutError';
    this.code = 'EXPORT_TIMEOUT';
    this.timeoutMs = Number(timeoutMs) || 0;
  }
}

/** BullMQ states of a job that is still waiting for a worker. */
const QUEUE_WAITING_STATES = ['waiting', 'delayed', 'prioritized', 'waiting-children'];

/**
 * What to do with an in-progress export row, given where its job is in the queue:
 *  - `{ ok: true }`: it is waiting or running, leave it;
 *  - `{ ok: false, error }`: give it up with that message;
 *  - `{ ok: null }`: the queue doesn't know this job (no Redis, or the job ran in-process on
 *    some server): only the heartbeat can tell (exportJobIsStale).
 * `queueState` is the BullMQ state ('waiting', 'active', 'failed', …) or null.
 */
function queueVerdict(row, queueState, { now = Date.now(), maxQueueWaitMs = envNumber('PPT_EXPORT_MAX_QUEUE_WAIT_MS', 15 * 60 * 1000) } = {}) {
  if (!queueState) return { ok: null };
  if (QUEUE_WAITING_STATES.includes(queueState)) {
    const createdAt = row?.createdAt ? new Date(row.createdAt).getTime() : now;
    return now - createdAt > maxQueueWaitMs ? { ok: false, error: MESSAGES.queueWait } : { ok: true };
  }
  // A running job holds a lock the worker renews; when its server dies BullMQ moves it back to
  // waiting (once) or to failed. So 'active' is trustworthy.
  if (queueState === 'active') return { ok: true };
  // 'completed' / 'failed' while the row is still in progress: the job ended without finishing it.
  return { ok: false, error: MESSAGES.crashed };
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
  tooLong:
    'This export took too long and was stopped. Try again, or export fewer pages at a time.',
  queueWait: 'The export did not start in time because our servers are busy. Please try again.',
  expired: 'This download has expired (files are kept for 7 days). Export the presentation again to get a new file.',
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
  if (err?.code === 'EXPORT_TIMEOUT') return MESSAGES.tooLong;
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

/**
 * Worth one more try: the browser crashed or disconnected mid-render (a fresh browser usually
 * works). Never a bad request, a missing deck, a timeout or a storage error.
 */
function isRetryableExportError(err) {
  if (!err || ['EXPORT_CANCELLED', 'EXPORT_BROWSER_UNAVAILABLE', 'EXPORT_TIMEOUT'].includes(err.code)) return false;
  const statusCode = Number(err.statusCode || err.status);
  if (err.isOperational === true && statusCode >= 400 && statusCode < 500) return false;
  return normalizeExportError(err) === MESSAGES.crashed;
}

/**
 * Where each step of an export sits on the dialog's 0–100 bar, per format. `drawing` and
 * `building` move with the slides done; the other steps are fixed points.
 *  - PNG / JPEG: drawing = one screenshot per slide.
 *  - PDF: drawing = the render page drawing the deck (no per-slide signal), building = printing.
 *  - PPTX: drawing = cutting pictures per slide, building = writing each slide.
 */
const PROGRESS_RANGES = {
  PNG: { drawing: [10, 90], building: [90, 93] },
  JPEG: { drawing: [10, 90], building: [90, 93] },
  PDF: { drawing: [10, 70], building: [70, 92] },
  PPTX: { drawing: [10, 50], building: [50, 92] },
};
const PROGRESS_POINTS = { queued: 0, preparing: 4, saving: 95, done: 100 };

/** `{ stage, percent, done, total }` for the export dialog. */
function exportProgress(format, stage, done = 0, total = 0) {
  const ranges = PROGRESS_RANGES[String(format || '').toUpperCase()] || PROGRESS_RANGES.PDF;
  let percent;
  if (ranges[stage]) {
    const [lo, hi] = ranges[stage];
    const share = total > 0 ? Math.min(1, Math.max(0, done / total)) : 0;
    percent = lo + (hi - lo) * share;
  } else {
    percent = PROGRESS_POINTS[stage] ?? 0;
  }
  return {
    stage,
    percent: Math.round(percent),
    done: Math.max(0, Math.round(Number(done) || 0)),
    total: Math.max(0, Math.round(Number(total) || 0)),
  };
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
  ACTIVE_EXPORT_STATUSES,
  SAVING_EXPORT_STATUS,
  isRetryableExportError,
  exportProgress,
  BROWSER_EXPORT_FORMATS,
  isBrowserExportFormat,
  createSemaphore,
  withHeartbeat,
  exportJobTimeoutMs,
  ExportTimeoutError,
  QUEUE_WAITING_STATES,
  queueVerdict,
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
