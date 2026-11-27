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

  it('prices Avatar 6 Pro above Turbo on enterprise', () => {
    const { heygenVideoRate } = require('./creditPricing');
    const pro = heygenVideoRate({ avatarEngine: 'heygen-avatar-6' });
    const turbo = heygenVideoRate({ avatarEngine: 'heygen-avatar-6-turbo' });
    assert.equal(pro.heygenCreditsPerSec, 0.2);
    assert.equal(turbo.heygenCreditsPerSec, 0.1);
  });
});

describe('Avatar 6 PAYG rates', () => {
  const prevBilling = process.env.HEYGEN_BILLING_MODE;

  beforeEach(() => {
    process.env.HEYGEN_BILLING_MODE = 'payg';
  });

  afterEach(() => {
    if (prevBilling == null) delete process.env.HEYGEN_BILLING_MODE;
    else process.env.HEYGEN_BILLING_MODE = prevBilling;
  });

  it('uses per-engine USD/sec regardless of avatar type', () => {
    const { heygenVideoRate } = require('./creditPricing');
    const pro = heygenVideoRate({ avatarEngine: 'heygen-avatar-6', avatarType: 'studio_avatar' });
    const turbo = heygenVideoRate({
      avatarEngine: 'heygen-avatar-6-turbo',
      avatarType: 'photo_avatar',
    });
    assert.equal(pro.usdPerSec, 0.1);
    assert.equal(turbo.usdPerSec, 0.05);
  });

  it('uses published Avatar IV photo rate', () => {
    const { heygenVideoRate } = require('./creditPricing');
    assert.equal(heygenVideoRate({ avatarEngine: 'avatar_iv', avatarType: 'photo_avatar' }).usdPerSec, 0.0385);
  });
});

describe('HeyGen published PAYG rates (API pricing page)', () => {
  const keys = [
    'HEYGEN_BILLING_MODE',
    'HEYGEN_AVATAR_6_2K_USD_PER_SEC',
    'HEYGEN_AVATAR_6_TURBO_2K_USD_PER_SEC',
    'HEYGEN_SPEECH_USD_PER_SEC',
    'ATHENA_MARGIN_PERCENT',
    'ATHENA_AC_PER_USD',
  ];
  const prev = {};

  beforeEach(() => {
    for (const k of keys) prev[k] = process.env[k];
    process.env.HEYGEN_BILLING_MODE = 'payg';
    delete process.env.HEYGEN_AVATAR_6_2K_USD_PER_SEC;
    delete process.env.HEYGEN_AVATAR_6_TURBO_2K_USD_PER_SEC;
    delete process.env.HEYGEN_SPEECH_USD_PER_SEC;
    process.env.ATHENA_MARGIN_PERCENT = '0';
    process.env.ATHENA_AC_PER_USD = '1';
  });

  afterEach(() => {
    for (const k of keys) {
      if (prev[k] == null) delete process.env[k];
      else process.env[k] = prev[k];
    }
  });

  it('Avatar IV: photo $0.0385, studio and custom $0.0805 per second', () => {
    const { heygenVideoRate } = require('./creditPricing');
    assert.equal(heygenVideoRate({ avatarEngine: 'avatar_iv', avatarType: 'photo_avatar' }).usdPerSec, 0.0385);
    assert.equal(heygenVideoRate({ avatarEngine: 'avatar_iv', avatarType: 'studio_avatar' }).usdPerSec, 0.0805);
    assert.equal(heygenVideoRate({ avatarEngine: 'avatar_iv', avatarType: 'digital_twin' }).usdPerSec, 0.0805);
  });

  it('Avatar III: photo and studio $0.0165, custom $0.01 per second', () => {
    const { heygenVideoRate } = require('./creditPricing');
    assert.equal(heygenVideoRate({ avatarEngine: 'avatar_iii', avatarType: 'photo_avatar' }).usdPerSec, 0.0165);
    assert.equal(heygenVideoRate({ avatarEngine: 'avatar_iii', avatarType: 'studio_avatar' }).usdPerSec, 0.0165);
    assert.equal(heygenVideoRate({ avatarEngine: 'avatar_iii', avatarType: 'digital_twin' }).usdPerSec, 0.01);
  });

  it('Avatar V: $0.12 per second for every avatar type', () => {
    const { heygenVideoRate } = require('./creditPricing');
    for (const avatarType of ['photo_avatar', 'studio_avatar', 'digital_twin']) {
      assert.equal(heygenVideoRate({ avatarEngine: 'avatar_v', avatarType }).usdPerSec, 0.12);
    }
  });

  it('Avatar 6 at 2K uses the 2K rates; 1080p and 720p use the 1080p rates', () => {
    const { heygenVideoRate } = require('./creditPricing');
    assert.equal(heygenVideoRate({ avatarEngine: 'heygen-avatar-6', resolution: '2k' }).usdPerSec, 0.145);
    assert.equal(heygenVideoRate({ avatarEngine: 'heygen-avatar-6-turbo', resolution: '2K' }).usdPerSec, 0.0875);
    assert.equal(heygenVideoRate({ avatarEngine: 'heygen-avatar-6', resolution: '1080p' }).usdPerSec, 0.1);
    assert.equal(heygenVideoRate({ avatarEngine: 'heygen-avatar-6-turbo', resolution: '720p' }).usdPerSec, 0.05);
  });

  it('speech is billed per second of audio on PAYG (measured ~$0.0024/s)', () => {
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    // 100s => $0.24
    const result = calculateUsageCredits({
      feature: FEATURE.SPEECH_GENERATION,
      durationSeconds: 100,
      characters: 1000,
    });
    assert.ok(Math.abs(result.heygenUsdCost - 0.24) < 1e-12, String(result.heygenUsdCost));
    assert.equal(result.breakdown.rateSource, 'payg_usd_per_sec');
  });

  it('speech price does not depend on character count on PAYG', () => {
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    const short = calculateUsageCredits({ feature: FEATURE.SPEECH_GENERATION, durationSeconds: 10, characters: 3 });
    const long = calculateUsageCredits({ feature: FEATURE.SPEECH_GENERATION, durationSeconds: 10, characters: 700 });
    assert.equal(short.heygenUsdCost, long.heygenUsdCost);
    assert.ok(Math.abs(short.heygenUsdCost - 0.024) < 1e-12, String(short.heygenUsdCost));
  });

  it('speech has a $0.01 minimum per call on PAYG, so sub-second calls are not under-billed', () => {
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    const tiny = calculateUsageCredits({ feature: FEATURE.SPEECH_GENERATION, durationSeconds: 0.86, characters: 5 });
    assert.ok(Math.abs(tiny.heygenUsdCost - 0.01) < 1e-12, String(tiny.heygenUsdCost));
    const none = calculateUsageCredits({ feature: FEATURE.SPEECH_GENERATION, durationSeconds: 0 });
    assert.equal(none.heygenUsdCost, 0);
  });

  it('speech per-second rate can be overridden with HEYGEN_SPEECH_USD_PER_SEC', () => {
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    const prev = process.env.HEYGEN_SPEECH_USD_PER_SEC;
    process.env.HEYGEN_SPEECH_USD_PER_SEC = '0.004';
    try {
      const result = calculateUsageCredits({ feature: FEATURE.SPEECH_GENERATION, durationSeconds: 10 });
      assert.ok(Math.abs(result.heygenUsdCost - 0.04) < 1e-12, String(result.heygenUsdCost));
    } finally {
      if (prev === undefined) delete process.env.HEYGEN_SPEECH_USD_PER_SEC;
      else process.env.HEYGEN_SPEECH_USD_PER_SEC = prev;
    }
  });

  it('PAYG video is billed in whole seconds rounded down, matching the HeyGen wallet', () => {
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    const price = (durationSeconds) =>
      calculateUsageCredits({
        feature: FEATURE.HEYGEN_VIDEO,
        avatarEngine: 'heygen-avatar-6-turbo',
        resolution: '1080p',
        durationSeconds,
      });
    // Turbo is $0.05/s: 5.9s bills as 5s.
    const fractional = price(5.9);
    assert.ok(Math.abs(fractional.heygenUsdCost - 0.25) < 1e-12, String(fractional.heygenUsdCost));
    assert.equal(fractional.breakdown.billedSeconds, 5);
    assert.equal(fractional.breakdown.durationSeconds, 5.9);
    const whole = price(5);
    assert.ok(Math.abs(whole.heygenUsdCost - 0.25) < 1e-12, String(whole.heygenUsdCost));
  });

  it('PAYG video has a 1 second minimum and zero length stays free', () => {
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    const base = { feature: FEATURE.HEYGEN_VIDEO, avatarEngine: 'heygen-avatar-6-turbo', resolution: '1080p' };
    const tiny = calculateUsageCredits({ ...base, durationSeconds: 0.4 });
    assert.ok(Math.abs(tiny.heygenUsdCost - 0.05) < 1e-12, String(tiny.heygenUsdCost));
    assert.equal(tiny.breakdown.billedSeconds, 1);
    assert.equal(calculateUsageCredits({ ...base, durationSeconds: 0 }).heygenUsdCost, 0);
  });

  it('enterprise video billing keeps exact seconds (contract billing is unverified)', () => {
    process.env.HEYGEN_BILLING_MODE = 'enterprise';
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    const result = calculateUsageCredits({
      feature: FEATURE.HEYGEN_VIDEO,
      avatarEngine: 'heygen-avatar-6-turbo',
      resolution: '1080p',
      durationSeconds: 5.9,
    });
    assert.equal(result.breakdown.billedSeconds, 5.9);
  });

  it('avatar creation: photo $1.32, custom digital twin $2.13 per call', () => {
    const { calculateUsageCredits, FEATURE } = require('./creditPricing');
    const photo = calculateUsageCredits({ feature: FEATURE.AVATAR_CREATE, avatarType: 'photo' });
    const custom = calculateUsageCredits({ feature: FEATURE.AVATAR_CREATE, avatarType: 'digital_twin' });
    assert.equal(photo.heygenUsdCost, 1.32);
    assert.equal(custom.heygenUsdCost, 2.13);
  });
});