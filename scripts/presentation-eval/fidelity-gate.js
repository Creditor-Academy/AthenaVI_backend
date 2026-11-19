/**
 * Phase 7.3 — the export fidelity gate for CI.
 *
 *   node scripts/presentation-eval/fidelity-gate.js <scores.json> [--baseline file]
 *
 * Reads the scores export-fidelity.js wrote and fails (exit 1) when exports got worse:
 *   - any deck errored, or a deck in the baseline wasn't measured;
 *   - PDF: a deck's average is below the target (0.98), or a slide dropped more than 0.02 below
 *     the baseline;
 *   - PPTX: a deck's average dropped more than 0.01 below the baseline, or a slide more than 0.03.
 *     (PPTX is drawn by LibreOffice, which doesn't draw every PowerPoint effect, so it is held to
 *     "no worse than before" rather than to the 0.95 target. Raise the baseline as it improves.)
 *
 * The baseline defaults to baselines/ci-baseline.json. To accept new scores on purpose (a change
 * that is meant to look different), copy the run's scores.json over it in the same change.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_RULES = {
  pdfTarget: 0.98,
  pdfSlideDrop: 0.02,
  pptxDeckDrop: 0.01,
  pptxSlideDrop: 0.03,
};

const DEFAULT_BASELINE = path.join(__dirname, 'baselines', 'ci-baseline.json');

const fmt = (n) => (typeof n === 'number' ? n.toFixed(3) : String(n));

/** Problems found in `scores` against `baseline` (empty = pass). */
function checkFidelity(scores, baseline, rules = DEFAULT_RULES) {
  const r = { ...DEFAULT_RULES, ...rules };
  const problems = [];
  const decks = scores?.decks || {};
  const base = baseline?.decks || {};

  for (const name of Object.keys(base)) {
    if (!decks[name]) problems.push(`${name}: not measured (it is in the baseline)`);
  }
  for (const [name, deck] of Object.entries(decks)) {
    for (const err of deck.errors || []) problems.push(`${name}: ${err}`);
    const was = base[name];
    if (deck.pdf && typeof deck.pdf.mean === 'number' && deck.pdf.mean < r.pdfTarget) {
      problems.push(`${name}: PDF average ${fmt(deck.pdf.mean)} is below the target ${fmt(r.pdfTarget)}`);
    }
    if (!was) continue;
    if (deck.pptx && was.pptx && deck.pptx.mean < was.pptx.mean - r.pptxDeckDrop) {
      problems.push(`${name}: PPTX average ${fmt(deck.pptx.mean)}, was ${fmt(was.pptx.mean)}`);
    }
    const before = new Map((was.slides || []).map((s) => [s.id, s]));
    for (const s of deck.slides || []) {
      const b = before.get(s.id);
      if (!b) continue;
      if (typeof s.pdf === 'number' && typeof b.pdf === 'number' && s.pdf < b.pdf - r.pdfSlideDrop) {
        problems.push(`${name} slide ${s.n} (${s.layoutId || s.id}): PDF ${fmt(s.pdf)}, was ${fmt(b.pdf)}`);
      }
      if (typeof s.pptx === 'number' && typeof b.pptx === 'number' && s.pptx < b.pptx - r.pptxSlideDrop) {
        problems.push(`${name} slide ${s.n} (${s.layoutId || s.id}): PPTX ${fmt(s.pptx)}, was ${fmt(b.pptx)}`);
      }
    }
  }
  return problems;
}

function main() {
  const args = process.argv.slice(2);
  const scoresFile = args.find((a) => !a.startsWith('--'));
  const i = args.indexOf('--baseline');
  const baselineFile = i > -1 ? args[i + 1] : DEFAULT_BASELINE;
  if (!scoresFile) {
    console.error('Usage: node scripts/presentation-eval/fidelity-gate.js <scores.json> [--baseline file]');
    process.exit(2);
  }
  const scores = JSON.parse(fs.readFileSync(path.resolve(scoresFile), 'utf8'));
  const baseline = JSON.parse(fs.readFileSync(path.resolve(baselineFile), 'utf8'));
  const problems = checkFidelity(scores, baseline);
  const decks = Object.keys(scores.decks || {}).length;
  if (problems.length) {
    console.error(`Export fidelity got worse (${problems.length}):`);
    for (const p of problems) console.error(`  - ${p}`);
    console.error(`Baseline: ${path.relative(process.cwd(), baselineFile)}. If the change is intended, update the baseline with the new scores.json.`);
    process.exit(1);
  }
  console.log(`Export fidelity OK: ${decks} decks, no drop against ${path.relative(process.cwd(), baselineFile)}.`);
}

if (require.main === module) main();

module.exports = { checkFidelity, DEFAULT_RULES, DEFAULT_BASELINE };
