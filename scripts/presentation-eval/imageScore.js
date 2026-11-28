/**
 * Image comparison shared by the presentation harnesses (export-fidelity.js, present-eval.js).
 *
 * SSIM (structural similarity, 0–1, 1 = identical) of two pictures of the same slide, compared
 * at COMPARE_WIDTH, in grayscale, lightly blurred (σ 1) so anti-aliasing differences between
 * renderers don't read as layout differences.
 */

const fs = require('fs');
const sharp = require('sharp');

const COMPARE_WIDTH = 480;

/** Grayscale pixels of `file` at width × height, flattened on white and blurred σ 1. */
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

/** SSIM of a candidate picture against the reference, both seen at the slide's aspect ratio. */
async function score(referenceFile, candidateFile, aspect) {
  if (!candidateFile || !fs.existsSync(candidateFile)) return null;
  const height = Math.round(COMPARE_WIDTH / aspect);
  const [a, b] = await Promise.all([
    grayscale(referenceFile, COMPARE_WIDTH, height),
    grayscale(candidateFile, COMPARE_WIDTH, height),
  ]);
  return Math.round(ssim(a, b, COMPARE_WIDTH, height) * 1000) / 1000;
}

module.exports = { COMPARE_WIDTH, grayscale, ssim, score };
