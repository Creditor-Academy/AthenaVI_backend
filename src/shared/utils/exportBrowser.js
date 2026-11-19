const fs = require('fs');
const path = require('path');
const os = require('os');
const { AsyncLocalStorage } = require('async_hooks');

/**
 * The headless browser used for PDF / image exports (presentations, brand kit guidelines).
 *
 * Order: an explicit PUPPETEER_EXECUTABLE_PATH / CHROME_PATH, then Puppeteer's own
 * chrome-headless-shell, then Puppeteer's Chrome for Testing, then a system Chrome.
 * The headless shell comes first: it needs the fewest system libraries (the Docker image)
 * and never opens a window (desktop Chrome on Windows does, even when headless).
 */

const BASE_ARGS = [
  '--no-sandbox',
  '--disable-setuid-sandbox',
  '--disable-dev-shm-usage',
  '--disable-gpu',
  '--font-render-hinting=none',
  '--window-position=-32000,-32000',
  '--mute-audio',
  '--no-first-run',
  '--no-default-browser-check',
];

const SYSTEM_CANDIDATES = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'Application', 'chrome.exe'),
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium-browser',
  '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
];

class BrowserUnavailableError extends Error {
  constructor(message = 'No headless browser is installed for exports') {
    super(message);
    this.name = 'BrowserUnavailableError';
    this.code = 'EXPORT_BROWSER_UNAVAILABLE';
  }
}

function fileExists(candidate) {
  try {
    return typeof candidate === 'string' && candidate !== '' && fs.existsSync(candidate);
  } catch {
    return false;
  }
}

function isHeadlessShell(executablePath) {
  return /headless[-_]shell/i.test(path.basename(String(executablePath || '')));
}

/** Puppeteer ≥ 22 returns a Promise here (older versions a string); both are handled. */
async function puppeteerExecutable(arg) {
  try {
    const puppeteer = require('puppeteer');
    if (typeof puppeteer.executablePath !== 'function') return null;
    const found = await (arg === undefined ? puppeteer.executablePath() : puppeteer.executablePath(arg));
    return fileExists(found) ? found : null;
  } catch {
    return null;
  }
}

/**
 * @returns {Promise<{ executablePath: string, headless: true | 'shell', source: string } | null>}
 */
async function resolveExportBrowser() {
  const fromEnv = String(process.env.PUPPETEER_EXECUTABLE_PATH || process.env.CHROME_PATH || '').trim();
  if (fileExists(fromEnv)) {
    return { executablePath: fromEnv, headless: isHeadlessShell(fromEnv) ? 'shell' : true, source: 'env' };
  }

  const shell = await puppeteerExecutable({ headless: 'shell' });
  if (shell) return { executablePath: shell, headless: 'shell', source: 'puppeteer-headless-shell' };

  const chrome = await puppeteerExecutable();
  if (chrome) {
    return { executablePath: chrome, headless: isHeadlessShell(chrome) ? 'shell' : true, source: 'puppeteer-chrome' };
  }

  const system = SYSTEM_CANDIDATES.find(fileExists);
  if (system) return { executablePath: system, headless: true, source: 'system' };

  return null;
}

async function launchExportBrowser({ args = [] } = {}) {
  const found = await resolveExportBrowser();
  if (!found) throw new BrowserUnavailableError();
  const puppeteer = require('puppeteer');
  return puppeteer.launch({
    headless: found.headless,
    executablePath: found.executablePath,
    windowsHide: true,
    pipe: true,
    args: [...BASE_ARGS, ...args],
  });
}

// ── Shared browser ───────────────────────────────────────────────────────────
// Starting Chrome takes about a second and a lot of memory, so exports share one browser. Each
// export gets its own incognito context (no cookies or cache shared between users' decks), closed
// when the export ends. The browser is replaced after PPT_EXPORT_BROWSER_MAX_JOBS exports (Chrome
// slowly leaks memory), when it crashes, and closed after PPT_EXPORT_BROWSER_IDLE_MS with no work.
// PPT_EXPORT_BROWSER_REUSE=0 goes back to one browser per export.

const envNumber = (name, fallback) => (Number(process.env[name]) > 0 ? Number(process.env[name]) : fallback);

function reuseEnabled() {
  return process.env.PPT_EXPORT_BROWSER_REUSE !== '0';
}

/** The browser in use (`current`) and how many browsers have been started (for tests / health). */
const pool = { current: null, launching: null, launches: 0 };

function closeQuietly(browser) {
  return Promise.resolve()
    .then(() => browser.close())
    .catch(() => {
      try {
        browser.process()?.kill('SIGKILL');
      } catch {
        // already gone
      }
    });
}

function retire(entry) {
  if (pool.current === entry) pool.current = null;
  entry.retired = true;
  if (entry.idleTimer) clearTimeout(entry.idleTimer);
  if (entry.active === 0) closeQuietly(entry.browser);
}

/**
 * An idle shared browser must not keep Node running: a script or test that exported something
 * would otherwise wait for the idle timeout before exiting (Puppeteer still closes Chrome when
 * Node exits). While an export uses it, it does keep Node running.
 */
function holdProcess(entry, hold) {
  const proc = entry.browser.process();
  if (!proc) return;
  try {
    if (hold) proc.ref();
    else proc.unref();
    for (const stream of proc.stdio || []) {
      if (stream && typeof stream.ref === 'function') {
        if (hold) stream.ref();
        else stream.unref();
      }
    }
  } catch {
    // best effort
  }
}

async function launchShared() {
  const browser = await launchExportBrowser();
  pool.launches += 1;
  const entry = { browser, served: 0, active: 0, retired: false, idleTimer: null };
  holdProcess(entry, false);
  browser.on('disconnected', () => {
    if (pool.current === entry) pool.current = null;
    entry.retired = true;
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
  });
  return entry;
}

/** A lease on the shared browser; `release()` must be called once the export is done with it. */
async function leaseSharedBrowser() {
  const maxJobs = envNumber('PPT_EXPORT_BROWSER_MAX_JOBS', 50);
  let entry = pool.current;
  if (entry && (!entry.browser.connected || entry.served >= maxJobs)) {
    retire(entry);
    entry = null;
  }
  if (!entry) {
    if (!pool.launching) {
      pool.launching = launchShared().finally(() => {
        pool.launching = null;
      });
    }
    entry = await pool.launching;
    if (!pool.current || pool.current.retired) pool.current = entry;
    entry = pool.current;
  }
  entry.served += 1;
  entry.active += 1;
  if (entry.active === 1) holdProcess(entry, true);
  if (entry.idleTimer) {
    clearTimeout(entry.idleTimer);
    entry.idleTimer = null;
  }
  let released = false;
  return {
    browser: entry.browser,
    release() {
      if (released) return;
      released = true;
      entry.active -= 1;
      if (entry.active > 0) return;
      holdProcess(entry, false);
      if (entry.retired || pool.current !== entry) {
        closeQuietly(entry.browser);
        return;
      }
      entry.idleTimer = setTimeout(() => retire(entry), envNumber('PPT_EXPORT_BROWSER_IDLE_MS', 5 * 60 * 1000));
      entry.idleTimer.unref?.();
    },
  };
}

/** Close the shared browser (server shutdown, tests). */
async function closeSharedBrowser() {
  const entry = pool.current;
  pool.current = null;
  if (entry) {
    if (entry.idleTimer) clearTimeout(entry.idleTimer);
    entry.retired = true;
    await closeQuietly(entry.browser);
  }
}

function exportBrowserStats() {
  const entry = pool.current;
  return {
    reuse: reuseEnabled(),
    launches: pool.launches,
    open: Boolean(entry && entry.browser.connected),
    servedByCurrent: entry ? entry.served : 0,
    active: entry ? entry.active : 0,
    pid: entry?.browser.process()?.pid || null,
  };
}

// ── Cancelling ───────────────────────────────────────────────────────────────
// An export job runs inside runWithExportSignal(signal, …). When the signal aborts (the user
// pressed Cancel), every page that job opened is closed at once, so a long render stops right
// away instead of finishing and being thrown away.

const signalStore = new AsyncLocalStorage();

/**
 * `info` (optional) collects facts about the job for its log line, such as the render page
 * version (noteExportRenderer).
 */
function runWithExportSignal(signal, fn, info = null) {
  return signalStore.run({ signal, info }, fn);
}

function currentExportSignal() {
  return signalStore.getStore()?.signal || null;
}

/** Record the render page version used by the current export job (for its log line). */
function noteExportRenderer(version) {
  const info = signalStore.getStore()?.info;
  if (info && version != null) info.rendererVersion = version;
}

class ExportCancelledError extends Error {
  constructor(message = 'Export cancelled') {
    super(message);
    this.name = 'ExportCancelledError';
    this.code = 'EXPORT_CANCELLED';
  }
}

/** Throw ExportCancelledError if the current export job has been cancelled. */
function throwIfExportCancelled(signal = currentExportSignal()) {
  if (signal?.aborted) throw new ExportCancelledError();
}

/**
 * Run `fn(page)` on a new page, closed afterwards. Uses the shared browser (an incognito context
 * per call). Extra launch `args`, or `shared: false`, use a fresh browser closed afterwards.
 */
async function withExportPage(fn, { args = [], shared = true } = {}) {
  const signal = currentExportSignal();
  throwIfExportCancelled(signal);
  const ownBrowser = !shared || !reuseEnabled() || args.length > 0;
  let browser = null;
  let lease = null;
  let context = null;
  let onAbort = null;
  try {
    if (ownBrowser) {
      browser = await launchExportBrowser({ args });
    } else {
      lease = await leaseSharedBrowser();
      context = await lease.browser.createBrowserContext();
    }
    throwIfExportCancelled(signal);
    const page = ownBrowser ? await browser.newPage() : await context.newPage();
    if (signal) {
      onAbort = () => {
        (context ? context.close() : browser.close()).catch(() => {});
      };
      signal.addEventListener('abort', onAbort, { once: true });
    }
    try {
      return await fn(page);
    } catch (err) {
      // Closing the pages makes Puppeteer fail with "Target closed": report it as the cancel it is.
      if (signal?.aborted) throw new ExportCancelledError();
      throw err;
    }
  } finally {
    if (onAbort) signal.removeEventListener('abort', onAbort);
    if (context) await context.close().catch(() => {});
    if (lease) lease.release();
    if (browser) await closeQuietly(browser);
  }
}

/**
 * Load HTML and wait until it is fully drawn: the `load` event (stylesheets, images in the
 * markup), then web fonts, then any image still decoding. Used instead of
 * waitUntil 'networkidle0', which can wait forever with nothing left loading — every PDF
 * export failed with "Navigation timeout" that way.
 */
async function setContentAndSettle(page, html, { timeoutMs = 60_000 } = {}) {
  await page.setContent(html, { waitUntil: 'load', timeout: timeoutMs });
  await page.evaluate(
    /* global document, requestAnimationFrame */
    async (limitMs) => {
      const deadline = new Promise((resolve) => setTimeout(resolve, limitMs));
      const images = [...document.images].map((img) =>
        img.complete
          ? null
          : new Promise((resolve) => {
              img.addEventListener('load', resolve, { once: true });
              img.addEventListener('error', resolve, { once: true });
            })
      );
      await Promise.race([Promise.all([document.fonts ? document.fonts.ready : null, ...images]), deadline]);
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    },
    Math.max(1_000, timeoutMs - 1_000)
  );
}

let lastCheck = null;

/**
 * Launch the export browser once and render a tiny page. Used at startup (logged) and at
 * Docker build time, so a missing browser shows up before a user's export fails.
 */
async function checkExportBrowser() {
  const startedAt = Date.now();
  const found = await resolveExportBrowser();
  try {
    if (!found) throw new BrowserUnavailableError();
    // Its own browser: the boot check shouldn't leave a shared Chrome running on an idle server.
    const result = await withExportPage(
      async (page) => {
        await page.setContent('<p style="font-family:sans-serif">ok</p>');
        const text = await page.$eval('p', (p) => p.textContent);
        if (text !== 'ok') throw new Error('Export browser rendered an empty page');
        return { version: await page.browser().version() };
      },
      { shared: false }
    );
    lastCheck = {
      ok: true,
      source: found.source,
      executablePath: found.executablePath,
      version: result.version,
      ms: Date.now() - startedAt,
      checkedAt: new Date().toISOString(),
    };
  } catch (err) {
    lastCheck = {
      ok: false,
      source: found?.source || null,
      executablePath: found?.executablePath || null,
      error: String(err?.message || err).slice(0, 500),
      ms: Date.now() - startedAt,
      checkedAt: new Date().toISOString(),
    };
  }
  return lastCheck;
}

function lastExportBrowserCheck() {
  return lastCheck;
}

module.exports = {
  BrowserUnavailableError,
  resolveExportBrowser,
  launchExportBrowser,
  withExportPage,
  setContentAndSettle,
  checkExportBrowser,
  lastExportBrowserCheck,
  closeSharedBrowser,
  exportBrowserStats,
  runWithExportSignal,
  currentExportSignal,
  noteExportRenderer,
  throwIfExportCancelled,
  ExportCancelledError,
};
