const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Resolve a Chrome/Chromium binary Puppeteer can launch.
 *
 * Order: explicit env override, then Puppeteer's own Chrome-for-Testing download, then the
 * system Chrome install. The bundled binary is preferred because launching the *desktop*
 * Chrome on Windows pops a visible window even with `headless: true`.
 */
function resolveChromeExecutable() {
  const fromEnv = String(process.env.PUPPETEER_EXECUTABLE_PATH || process.env.CHROME_PATH || '').trim();
  if (fromEnv && fs.existsSync(fromEnv)) return fromEnv;

  try {
    const puppeteer = require('puppeteer');
    const bundled = typeof puppeteer.executablePath === 'function' ? puppeteer.executablePath() : null;
    if (bundled && fs.existsSync(bundled)) return bundled;
  } catch {
    // fall through to a system install
  }

  const home = os.homedir();
  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ];

  for (const candidate of candidates) {
    try {
      if (candidate && fs.existsSync(candidate)) return candidate;
    } catch {
      // keep looking
    }
  }

  return null;
}

module.exports = {
  resolveChromeExecutable,
};
