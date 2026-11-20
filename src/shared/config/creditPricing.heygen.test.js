'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

describe('normalizeHeygenVideoBillingEngine (via heygenVideoRate)', () => {
  const prevBilling = process.env.HEYGEN_BILLING_MODE;

  beforeEach(() => {
    process.env.HEYGEN_BILLING_MODE = 'enterprise';
  });

  afterEach(() => {
    if (prevBilling == null) delete process.env.HEYGEN_BILLING_MODE;
    else process.env.HEYGEN_BILLING_MODE = prevBilling;
  });

  it('maps legacy_v2 to Avatar III enterprise rate', () => {
    const { heygenVideoRate } = require('./creditPricing');
    const legacy = heygenVideoRate({ avatarEngine: 'legacy_v2' });
    const iii = heygenVideoRate({ avatarEngine: 'avatar_iii' });
    assert.equal(legacy.heygenCreditsPerSec, iii.heygenCreditsPerSec);
    assert.equal(legacy.heygenCreditsPerSec, 0.0033);
  });
});