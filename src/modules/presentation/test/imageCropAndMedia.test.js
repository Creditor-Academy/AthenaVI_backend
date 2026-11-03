'use strict';

const assert = require('assert');
const { test } = require('node:test');
const sharp = require('sharp');
const { normalizeCrop, cropPixelRect, croppedImageCss } = require('../imageCrop');
const { cropImageBuffer } = require('../slideHtml');
const { applyImageToElements } = require('../slideMedia.service');
const { mergeElementContent } = require('../slideEditor.service');

async function twoColourPng() {
  // 100×50: left half red, right half blue.
  const red = await sharp({ create: { width: 50, height: 50, channels: 3, background: '#ff0000' } }).png().toBuffer();
  const blue = await sharp({ create: { width: 50, height: 50, channels: 3, background: '#0000ff' } }).png().toBuffer();
  return sharp({ create: { width: 100, height: 50, channels: 3, background: '#000000' } })
    .composite([{ input: red, left: 0, top: 0 }, { input: blue, left: 50, top: 0 }])
    .png()
    .toBuffer();
}

test('normalizeCrop: full or missing crop means no crop', () => {
  assert.strictEqual(normalizeCrop(null), null);
  assert.strictEqual(normalizeCrop({ x: 0, y: 0, width: 1, height: 1 }), null);
  assert.deepStrictEqual(cropPixelRect({ x: 0.5, y: 0, width: 0.5, height: 1 }, 100, 50), { left: 50, top: 0, width: 50, height: 50 });
});

test('cropImageBuffer cuts out exactly the stored region', async () => {
  const src = await twoColourPng();
  const out = await cropImageBuffer(src, { x: 0.5, y: 0, width: 0.5, height: 1 });
  const { data, info } = await sharp(out).raw().toBuffer({ resolveWithObject: true });
  assert.strictEqual(info.width, 50);
  assert.strictEqual(info.height, 50);
  // every pixel is blue
  for (let i = 0; i < data.length; i += info.channels) {
    assert.ok(data[i] < 10 && data[i + 2] > 245, 'pixel should be blue');
  }
  assert.strictEqual(await cropImageBuffer(src, null), src, 'no crop returns the original buffer');
});

test('croppedImageCss scales and offsets the image', () => {
  const css = croppedImageCss({ x: 0.25, y: 0.5, width: 0.5, height: 0.25 });
  assert.match(css, /left:-50%/);
  assert.match(css, /top:-200%/);
  assert.match(css, /width:200%/);
  assert.match(css, /height:400%/);
  assert.strictEqual(croppedImageCss(undefined), null);
});

const frame = { id: 'frm', type: 'shape', layer: 8, placement: { x: 100, y: 100, width: 400, height: 800 }, content: { deviceFrame: 'phone', layoutSurface: true } };
const screen = { id: 'scr', type: 'image', layer: 10, placement: { x: 110, y: 110, width: 380, height: 780 }, content: { url: 'https://x/old.png' } };
const photo = { id: 'pho', type: 'image', layer: 5, placement: { x: 900, y: 100, width: 600, height: 400 }, content: { url: 'https://x/photo.png' } };
const empty = { id: 'emp', type: 'image', layer: 5, placement: { x: 900, y: 600, width: 300, height: 200 }, content: { url: null } };
const title = { id: 'ttl', type: 'text', placement: { x: 0, y: 0, width: 500, height: 80 }, content: { text: 'Hi' } };
const doc = (els) => ({ version: 1, canvas: { width: 1920, height: 1080 }, elements: els.map((e) => JSON.parse(JSON.stringify(e))) });

test('applyImageToElements: a layout device frame fills its screen image', () => {
  const out = applyImageToElements(doc([frame, screen, photo]), { url: 'https://x/new.png', elementId: 'frm' });
  assert.strictEqual(out.elements.find((e) => e.id === 'scr').content.url, 'https://x/new.png');
  assert.strictEqual(out.elements.find((e) => e.id === 'frm').content.url, undefined);
  assert.strictEqual(out.elements.find((e) => e.id === 'pho').content.url, 'https://x/photo.png');
});

test('applyImageToElements: a selected image is replaced', () => {
  const out = applyImageToElements(doc([photo, empty]), { url: 'https://x/new.png', elementId: 'pho' });
  assert.strictEqual(out.elements.find((e) => e.id === 'pho').content.url, 'https://x/new.png');
});

test('applyImageToElements: no target fills an empty slot, never an existing picture', () => {
  const filled = applyImageToElements(doc([photo, empty]), { url: 'https://x/new.png' });
  assert.strictEqual(filled.elements.find((e) => e.id === 'emp').content.url, 'https://x/new.png');
  assert.strictEqual(filled.elements.find((e) => e.id === 'pho').content.url, 'https://x/photo.png');

  const added = applyImageToElements(doc([photo, title]), { url: 'https://x/new.png', elementId: 'ttl' });
  assert.strictEqual(added.elements.length, 3, 'a non-image selection adds a new image');
  assert.strictEqual(added.elements.find((e) => e.id === 'pho').content.url, 'https://x/photo.png');
});

test('applyImageToElements: unknown element id is still a 404', () => {
  assert.throws(() => applyImageToElements(doc([photo]), { url: 'https://x/new.png', elementId: 'nope' }), /not found/i);
});

test('mergeElementContent drops a stale s3Key when the image changes', () => {
  const current = { url: 'https://signed/old', s3Key: 'workspace/old.png', fit: 'cover' };
  // Replace without a key → old key must not survive.
  assert.strictEqual(mergeElementContent(current, { url: 'https://cdn/new.png', src: 'https://cdn/new.png' }).s3Key, undefined);
  // Replace with the new key → new key kept.
  assert.strictEqual(mergeElementContent(current, { url: 'https://cdn/new.png', s3Key: 'workspace/new.png' }).s3Key, 'workspace/new.png');
  // Explicit null → derive from url.
  assert.strictEqual(mergeElementContent(current, { url: 'https://cdn/new.png', s3Key: null }).s3Key, undefined);
  // Non-image edits keep the key.
  assert.strictEqual(mergeElementContent(current, { opacity: 0.5 }).s3Key, 'workspace/old.png');
  // Re-signed url sent with its key (normal save) keeps the key.
  assert.strictEqual(mergeElementContent(current, { url: 'https://signed/fresh', s3Key: 'workspace/old.png', opacity: 1 }).s3Key, 'workspace/old.png');
});
