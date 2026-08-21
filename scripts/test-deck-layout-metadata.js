/**
 * DeckLayout metadata registry checks.
 * Run: node scripts/test-deck-layout-metadata.js
 */
const assert = require('assert');
const path = require('path');

const seed = require('../src/modules/presentation/templates/seed-layouts.json');
const {
  listDeckLayouts,
  getDeckLayout,
  getDeckLayoutElements,
  validateDeckLayout,
  validateDeckLayoutCollection,
} = require('../src/modules/presentation/deckLayout');
const example = require('../src/modules/presentation/deckLayout/examples/title_hero_right_fade_v1.deckLayout.json');

const layouts = listDeckLayouts();
assert.ok(layouts.length >= 120, `expected 120+ layouts, got ${layouts.length}`);
assert.strictEqual(layouts.length, seed.length, 'registry count matches seed-layouts.json');

const collection = validateDeckLayoutCollection(layouts);
if (!collection.ok) {
  console.error(collection.errors.slice(0, 40).join('\n'));
}
assert.ok(collection.ok, `registry validation failed (${collection.errors.length} errors)`);

const ids = layouts.map((l) => l.id);
const unique = new Set(ids);
assert.strictEqual(unique.size, ids.length, 'every layout id is unique');

for (const layout of layouts) {
  assert.ok(layout.id, 'layout has id');
  assert.strictEqual(layout.id, layout.schema.layout_id, 'id matches schema.layout_id');
  assert.ok(layout.category, 'layout has category');
}

const splitHero = getDeckLayout('title_hero_right_fade_v1');
assert.ok(splitHero, 'title_hero_right_fade_v1 exists');
assert.strictEqual(splitHero.name, 'Split Hero');
assert.strictEqual(splitHero.category, 'hero');
assert.deepStrictEqual(splitHero.slidePurposes, ['cover', 'introduction', 'product']);
assert.deepStrictEqual(splitHero.contentTypes, ['title', 'subtitle', 'image']);
assert.strictEqual(splitHero.contentCapacity.density, 'low');
assert.strictEqual(splitHero.composition.structure, 'split');
assert.strictEqual(splitHero.composition.imagePosition, 'right');
assert.strictEqual(splitHero.supportedElements.image, true);
assert.strictEqual(splitHero.supportedElements.chart, false);
assert.ok(Array.isArray(splitHero.schema.slots) && splitHero.schema.slots.length >= 3);
assert.deepStrictEqual(splitHero.elements, []);

const exampleCheck = validateDeckLayout(example);
assert.ok(exampleCheck.ok, `example fixture invalid: ${exampleCheck.errors.join('; ')}`);
assert.strictEqual(example.id, 'title_hero_right_fade_v1');

const compiled = getDeckLayoutElements('title_hero_right_fade_v1');
assert.ok(compiled.length > 0, 'compiled canvas elements from slots');
const compiledCheck = validateDeckLayout({ ...splitHero, elements: compiled });
assert.ok(compiledCheck.ok, `compiled elements invalid: ${compiledCheck.errors.join('; ')}`);
assert.ok(compiled.every((el) => el.placement && typeof el.placement.x === 'number'));

const missing = validateDeckLayout({});
assert.ok(missing.errors.some((e) => /missing ID/i.test(e)));
assert.ok(missing.errors.some((e) => /missing category/i.test(e)));

const badTypes = validateDeckLayout({
  ...splitHero,
  contentTypes: ['not-a-type'],
});
assert.ok(badTypes.errors.some((e) => /contentTypes/.test(e)));

const badCapacity = validateDeckLayout({
  ...splitHero,
  contentCapacity: { ...splitHero.contentCapacity, maxBullets: -1 },
});
assert.ok(badCapacity.errors.some((e) => /maxBullets/.test(e)));

const badElement = validateDeckLayout({
  ...splitHero,
  elements: [{ id: 'x', type: 'widget', placement: { x: 0, y: 0, width: 10, height: 10 } }],
});
assert.ok(badElement.errors.some((e) => /unsupported/.test(e)));

const dup = validateDeckLayoutCollection([splitHero, { ...splitHero }]);
assert.ok(dup.errors.some((e) => /duplicate layout ID/.test(e)));

assert.ok(getDeckLayout('does_not_exist_v1') == null);

console.log(`ok: ${layouts.length} DeckLayouts, unique ids, example title_hero_right_fade_v1, validation rules`);
console.log(`example fixture: ${path.basename('title_hero_right_fade_v1.deckLayout.json')}`);
