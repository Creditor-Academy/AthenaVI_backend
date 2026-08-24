const React = require('react');
const { continueRender, delayRender } = require('remotion');
const { googleFontsHref } = require('../../../shared/fonts/googleFontsCss');

const GENERIC_FAMILIES = new Set([
  'sans-serif',
  'serif',
  'monospace',
  'cursive',
  'fantasy',
  'system-ui',
  'ui-sans-serif',
  'ui-serif',
  'ui-monospace',
  'ui-rounded',
  'emoji',
  'math',
  'fangsong',
  'inherit',
  'initial',
  'unset',
]);

/**
 * Extract unique Google Font family names from scene elements.
 * Strips CSS stacks like "Inter, system-ui, sans-serif" → "Inter".
 */
function collectFontFamilies(elements = []) {
  const families = new Set();
  for (const el of elements) {
    const content = el?.content && typeof el.content === 'object' ? el.content : {};
    const style = el?.style && typeof el.style === 'object' ? el.style : {};
    for (const raw of [content.fontFamily, style.fontFamily]) {
      const primary = String(raw || '')
        .split(',')[0]
        .replace(/['"]/g, '')
        .trim();
      if (!primary) continue;
      if (GENERIC_FAMILIES.has(primary.toLowerCase())) continue;
      families.add(primary);
    }
    if (Array.isArray(content.runs)) {
      for (const run of content.runs) {
        const runFamily = String(run?.fontFamily || '')
          .split(',')[0]
          .replace(/['"]/g, '')
          .trim();
        if (runFamily && !GENERIC_FAMILIES.has(runFamily.toLowerCase())) {
          families.add(runFamily);
        }
      }
    }
  }
  return [...families];
}

function ensureStylesheetLink(href) {
  if (typeof document === 'undefined' || !href) return;
  const existing = Array.from(document.querySelectorAll('link[data-athena-fonts]')).find(
    (el) => el.getAttribute('data-athena-fonts') === href
  );
  if (existing) return;
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = href;
  link.setAttribute('data-athena-fonts', href);
  document.head.appendChild(link);
}

async function waitForFamilies(families) {
  if (typeof document === 'undefined' || !document.fonts) return;
  await Promise.all(
    families.map((family) =>
      document.fonts.load(`400 16px "${family}"`).catch(() => null)
    )
  );
  if (document.fonts.ready) {
    await Promise.race([
      document.fonts.ready.catch(() => null),
      new Promise((resolve) => setTimeout(resolve, 5000)),
    ]);
  }
}

/**
 * Remotion helper: inject Google Fonts CSS and delay paint until faces load.
 * Font CDN failures degrade to the browser fallback (never fail the render).
 */
function useSceneFonts(elements) {
  const families = React.useMemo(() => collectFontFamilies(elements), [elements]);
  const [handle] = React.useState(() =>
    families.length ? delayRender(`Load fonts: ${families.join(', ')}`) : null
  );

  React.useEffect(() => {
    if (!handle) return undefined;

    let cancelled = false;
    const href = googleFontsHref(families);

    (async () => {
      try {
        ensureStylesheetLink(href);
        await waitForFamilies(families);
      } catch {
        // degrade to system fallback
      } finally {
        if (!cancelled) {
          continueRender(handle);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [handle, families]);
}

module.exports = {
  collectFontFamilies,
  useSceneFonts,
};
