const fs = require('fs');
const path = require('path');
const os = require('os');

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

/** Run `fn(page)` in a fresh browser that is always closed afterwards. */
async function withExportPage(fn, { args = [] } = {}) {
  let browser;
  try {
    browser = await launchExportBrowser({ args });
    const page = await browser.newPage();
    return await fn(page);
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
        // ignore
      }
    }
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
    const result = await withExportPage(async (page) => {
      await page.setContent('<p style="font-family:sans-serif">ok</p>');
      const text = await page.$eval('p', (p) => p.textContent);
      if (text !== 'ok') throw new Error('Export browser rendered an empty page');
      return { version: await page.browser().version() };
    });
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
};
