#!/usr/bin/env node
/**
 * FE/BE slot text parity — shared resolver vs frontend slot map.
 * Run: node --test test/content-contract-parity.test.mjs
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
import test from 'node:test'

const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)

const {
  normalizeContentForLayout,
  deriveContentContract,
} = require('../contentContract.js')
const { textForSlot, coerceSlotText } = require('../slotText.js')
const { clampSlotText } = require('../textNormalize.js')
const { getDeckLayout, listDeckLayouts } = require('../../../src/modules/presentation/deckLayout/index.js')

const feMappingUrl = pathToFileURL(
  join(__dirname, '../../../../AthenaVI/src/utils/contentSlotMapping.js')
).href
const { buildContentBySlotIdFromSlideContent } = await import(feMappingUrl)

const NON_TEXT_ROLES = new Set(['image', 'chart', 'decoration', 'background', 'table'])

const LAYOUT_IDS = listDeckLayouts()
  .filter((l) => Array.isArray(l.schema?.slots) && l.schema.slots.length >= 2)
  .map((l) => l.id)
  .filter((id, index, all) => all.indexOf(id) === index)
  .slice(0, 25)

const fixtures = JSON.parse(
  readFileSync(join(__dirname, 'fixtures/content-fixtures.json'), 'utf8')
)

function canonicalSlotTexts(content, schema) {
  const normalized = normalizeContentForLayout(content, schema)
  const contract = deriveContentContract(schema)
  const out = {}
  const slots = Array.isArray(schema?.slots) ? schema.slots : []
  for (const slot of slots) {
    if (!slot?.id) continue
    const role = String(slot.role || '').toLowerCase()
    if (NON_TEXT_ROLES.has(role)) continue
    const raw = coerceSlotText(textForSlot(slot.id, normalized, schema)).trim()
    const text = clampSlotText(raw, contract.slots[slot.id])
    if (text) out[slot.id] = text
  }
  return out
}

function compareSlotMaps(canonical, feMap, schema, layoutId, fixtureId) {
  const slots = Array.isArray(schema?.slots) ? schema.slots : []
  for (const slot of slots) {
    if (!slot?.id) continue
    const role = String(slot.role || '').toLowerCase()
    if (NON_TEXT_ROLES.has(role)) continue
    const a = canonical[slot.id] ?? ''
    const b = feMap[slot.id] ?? ''
    if (String(a) !== String(b)) {
      throw new Error(
        `[${layoutId} / ${fixtureId}] slot ${slot.id} mismatch:\n  canonical: ${JSON.stringify(a)}\n  fe: ${JSON.stringify(b)}`
      )
    }
  }
}

test('fixture catalog has 25 entries', () => {
  assert.equal(fixtures.length, 25)
})

test('layout catalog has 20+ core layouts', () => {
  assert.ok(LAYOUT_IDS.length >= 20)
  for (const id of LAYOUT_IDS) {
    assert.ok(getDeckLayout(id), `missing layout ${id}`)
  }
})

for (const layoutId of LAYOUT_IDS) {
  const layout = getDeckLayout(layoutId)
  const schema = layout?.schema
  if (!schema?.slots?.length) continue

  for (const fixture of fixtures) {
    test(`${layoutId} × ${fixture.id}`, () => {
      const canonical = canonicalSlotTexts(fixture.content, schema)
      const feMap = buildContentBySlotIdFromSlideContent(fixture.content, schema)
      compareSlotMaps(canonical, feMap, schema, layoutId, fixture.id)
    })
  }
}
