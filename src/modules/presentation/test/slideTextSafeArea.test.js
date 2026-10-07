'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  slideTextSafeRect,
  clampPlacementToSafeRect,
  SLIDE_TEXT_SAFE_INSET_X,
} = require('../slideTextSafeArea');
const { applySlideTextSafeArea } = require('../layoutToElements');
const { inferTypographyRole } = require('../artDirection/typographyRoles');
const { resolveTypeScaleFontSize } = require('../canvasTypography');

test('slideTextSafeRect uses configured horizontal inset', () => {
  const safe = slideTextSafeRect(1920, 1080);
  assert.equal(safe.x, SLIDE_TEXT_SAFE_INSET_X);
  assert.equal(safe.width, 1920 - SLIDE_TEXT_SAFE_INSET_X * 2);
});

test('applySlideTextSafeArea clamps text only', () => {
  const doc = {
    canvas: { width: 1920, height: 1080 },
    elements: [
      {
        id: 't1',
        type: 'text',
        slotId: 'BODY',
        placement: { x: 0, y: 0, width: 1900, height: 200 },
      },
      {
        id: 'img1',
        type: 'image',
        slotId: 'HERO_IMAGE',
        placement: { x: 0, y: 0, width: 1920, height: 1080 },
      },
    ],
  };
  const out = applySlideTextSafeArea(doc, { layout_id: 'bullet_list_v1' }, { width: 1920, height: 1080 });
  const text = out.elements.find((e) => e.id === 't1');
  const img = out.elements.find((e) => e.id === 'img1');
  assert.ok(text.placement.x >= SLIDE_TEXT_SAFE_INSET_X);
  assert.equal(img.placement.width, 1920);
});

test('card title typography role and fallback sizes differ from body', () => {
  const role = inferTypographyRole({
    slot: { id: 'CARD_1_TITLE', role: 'heading' },
    layoutSchema: { layout_id: 'three_cards_image_text_v1' },
  });
  assert.equal(role, 'cardTitle');
  const scale = { body: 16, subtitle: 22 };
  const titleSize = resolveTypeScaleFontSize('heading', scale, 'CARD_1_TITLE');
  const bodySize = resolveTypeScaleFontSize('body', scale, 'CARD_1_BODY');
  assert.ok(titleSize > bodySize);
});
