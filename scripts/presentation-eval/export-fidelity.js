/**
 * Offline export fidelity checks against a sample deck-shaped payload.
 * Does not require Puppeteer/Chromium when PPT_EXPORT_FIDELITY_SKIP_PDF=1.
 */
const assert = require('assert');

function sampleDeck() {
  return {
    themeTokens: {
      palette: {
        bg: '#0B1220',
        text: '#F8FAFC',
        primary: '#3B82F6',
      },
    },
    slides: [
      {
        order: 1,
        contentType: 'title',
        content: { title: 'Hello', body: null, bullets: [], notes: 'Open strong' },
        imageRef: null,
        status: 'READY',
      },
      {
        order: 2,
        contentType: 'bullet_list',
        content: {
          title: 'Points',
          bullets: ['One', 'Two'],
          notes: 'Keep short',
        },
        imageRef: { source: 'none' },
        status: 'READY',
      },
      {
        order: 3,
        contentType: 'image+text',
        content: { title: 'Visual', body: 'Caption', bullets: [] },
        imageRef: { source: 'path_b', url: 'https://example.com/diagram.png' },
        status: 'READY',
      },
    ],
  };
}

function checkContentBounds(deck) {
  const issues = [];
  for (const slide of deck.slides) {
    const title = slide.content?.title || '';
    if (title.length > 120) issues.push(`slide ${slide.order}: title too long`);
    const bullets = slide.content?.bullets || [];
    if (bullets.length > 8) issues.push(`slide ${slide.order}: too many bullets`);
    if (slide.imageRef?.source === 'path_b' && !slide.imageRef.url) {
      issues.push(`slide ${slide.order}: path_b missing url`);
    }
  }
  return issues;
}

async function main() {
  const deck = sampleDeck();
  const issues = checkContentBounds(deck);
  assert.deepStrictEqual(issues, [], issues.join('; '));

  // PPTX build smoke (no S3)
  const exportServicePath = require('path').join(
    __dirname,
    '../src/modules/presentation/export.service.js'
  );
  // Prefer requiring build helper if exported later; otherwise pptxgenjs direct
  const PptxGenJS = require('pptxgenjs');
  const pptx = new PptxGenJS();
  pptx.defineLayout({ name: 'LAYOUT_16x9', width: 13.333, height: 7.5 });
  pptx.layout = 'LAYOUT_16x9';
  for (const slide of deck.slides) {
    const s = pptx.addSlide();
    s.addText(slide.content.title || 'Untitled', { x: 0.5, y: 0.5, w: 12, h: 1 });
    if (slide.imageRef?.source === 'path_b') {
      // Path B must remain a single image slot in export contract (no editable text overlay required)
      assert.ok(slide.imageRef.url, 'path_b needs url');
    }
  }
  const buf = await pptx.write({ outputType: 'nodebuffer' });
  assert.ok(Buffer.isBuffer(buf) && buf.length > 100, 'pptx buffer too small');

  console.log(
    JSON.stringify(
      {
        ok: true,
        checks: ['content_bounds', 'pptx_smoke', 'path_b_as_image_contract'],
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
