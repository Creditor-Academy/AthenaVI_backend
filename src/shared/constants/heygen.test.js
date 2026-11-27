'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  HEYGEN_AVATAR_ENGINES,
  normalizeHeygenAvatarEngine,
  usesHeygenLegacyV2VideoApi,
  usesHeygenLegacyV2VideoLook,
  isAvatarIiiOnlyLegacyLook,
  buildHeygenVideoEnginePayload,
  coerceEngineForAvatarType,
  resolveVideoPlanForLook,
  getEffectiveSupportedApiEnginesFromLook,
} = require('./heygen');

const III_ONLY_LOOK = {
  id: 'Diora_public_3',
  supported_api_engines: ['avatar_iii'],
  avatar_type: 'studio_avatar',
};

const IV_V_LOOK = {
  id: 'some_public_look',
  supported_api_engines: ['avatar_iv', 'avatar_v'],
  avatar_type: 'photo_avatar',
};

const EXPRESSIVE_V2_LOOK = {
  id: 'Presenter_expressive1_public',
  supported_api_engines: [],
};

const EMPTY_ENGINES_LOOK = {
  id: 'custom_group_slug',
  supported_api_engines: [],
};

/** Plan-gated look: HeyGen 400s "available only with Avatar 6 Pro or Turbo" for IV/V. */
const AVATAR_6_ONLY_LOOK = {
  id: 'fcc5f5ec957d429f96c2a4146cc49086',
  avatar_type: 'photo_avatar',
  supported_api_engines: ['heygen-avatar-6', 'heygen-avatar-6-turbo'],
};

const ALL_ENGINES_LOOK = {
  id: 'all_engines_look',
  avatar_type: 'photo_avatar',
  supported_api_engines: [
    'avatar_iii',
    'avatar_iv',
    'avatar_v',
    'heygen-avatar-6',
    'heygen-avatar-6-turbo',
  ],
};

describe('usesHeygenLegacyV2VideoApi', () => {
  it('detects expressive public look ids', () => {
    assert.equal(usesHeygenLegacyV2VideoApi('Actor_expressive2_public'), true);
    assert.equal(usesHeygenLegacyV2VideoApi('normal_look_id'), false);
  });
});

describe('usesHeygenLegacyV2VideoLook', () => {
  it('treats avatar_iii-only metadata as legacy metadata look', () => {
    assert.equal(usesHeygenLegacyV2VideoLook(III_ONLY_LOOK), true);
  });

  it('treats explicitly empty supported_api_engines as legacy metadata look', () => {
    assert.equal(usesHeygenLegacyV2VideoLook(EMPTY_ENGINES_LOOK), true);
  });

  it('does not treat IV/V look as legacy metadata look', () => {
    assert.equal(usesHeygenLegacyV2VideoLook(IV_V_LOOK), false);
  });
});

describe('isAvatarIiiOnlyLegacyLook', () => {
  it('is true for avatar_iii only studio look', () => {
    assert.equal(isAvatarIiiOnlyLegacyLook(III_ONLY_LOOK), true);
  });

  it('is false for expressive public id even with III engines', () => {
    assert.equal(
      isAvatarIiiOnlyLegacyLook({
        id: 'Actor_expressive1_public',
        supported_api_engines: ['avatar_iii'],
      }),
      false
    );
  });

  it('is false for empty engines array', () => {
    assert.equal(isAvatarIiiOnlyLegacyLook(EMPTY_ENGINES_LOOK), false);
  });
});

describe('normalizeHeygenAvatarEngine', () => {
  it('normalizes avatar_iii aliases', () => {
    assert.equal(normalizeHeygenAvatarEngine('avatar_iii'), HEYGEN_AVATAR_ENGINES.III);
    assert.equal(normalizeHeygenAvatarEngine('III'), HEYGEN_AVATAR_ENGINES.III);
    assert.equal(normalizeHeygenAvatarEngine('avatar_3'), HEYGEN_AVATAR_ENGINES.III);
  });

  it('defaults empty to avatar_iv', () => {
    assert.equal(normalizeHeygenAvatarEngine(null), HEYGEN_AVATAR_ENGINES.IV);
  });

  it('normalizes Avatar 6 aliases', () => {
    assert.equal(normalizeHeygenAvatarEngine('heygen-avatar-6'), HEYGEN_AVATAR_ENGINES.AVATAR_6);
    assert.equal(normalizeHeygenAvatarEngine('avatar_6_pro'), HEYGEN_AVATAR_ENGINES.AVATAR_6);
    assert.equal(
      normalizeHeygenAvatarEngine('HeyGen-Avatar-6-Turbo'),
      HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO
    );
    assert.equal(normalizeHeygenAvatarEngine('avatar_6_turbo'), HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO);
  });
});

describe('buildHeygenVideoEnginePayload', () => {
  it('builds avatar_iii engine object', () => {
    assert.deepEqual(buildHeygenVideoEnginePayload(HEYGEN_AVATAR_ENGINES.III), {
      type: 'avatar_iii',
    });
  });
});

describe('coerceEngineForAvatarType', () => {
  it('maps IV to V for digital twin', () => {
    assert.equal(
      coerceEngineForAvatarType(HEYGEN_AVATAR_ENGINES.IV, 'digital_twin'),
      HEYGEN_AVATAR_ENGINES.V
    );
  });
});

describe('resolveVideoPlanForLook', () => {
  it('routes III-only look to v3 avatar_iii', () => {
    const plan = resolveVideoPlanForLook(III_ONLY_LOOK, null, 'studio_avatar');
    assert.equal(plan.videoApi, 'v3');
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.III);
    assert.deepEqual(plan.supportedApiEngines, [HEYGEN_AVATAR_ENGINES.III]);
  });

  it('routes expressive public studio look to v3 avatar_iii', () => {
    const plan = resolveVideoPlanForLook(EXPRESSIVE_V2_LOOK, null, 'studio_avatar');
    assert.equal(plan.videoApi, 'v3');
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.III);
  });

  it('uses v3 IV for standard photo look', () => {
    const plan = resolveVideoPlanForLook(IV_V_LOOK, HEYGEN_AVATAR_ENGINES.IV, 'photo_avatar');
    assert.equal(plan.videoApi, 'v3');
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.IV);
  });

  it('keeps IV for a studio look that lists IV (current HeyGen docs support it)', () => {
    const plan = resolveVideoPlanForLook(IV_V_LOOK, HEYGEN_AVATAR_ENGINES.IV, 'studio_avatar');
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.IV);
    assert.equal(plan.engineCoerced, false);
    assert.equal(plan.defaultAvatarEngine, HEYGEN_AVATAR_ENGINES.IV);
  });

  it('uses V for a studio look that does not list IV', () => {
    const plan = resolveVideoPlanForLook(
      { id: 'studio_v_only', avatar_type: 'studio_avatar', supported_api_engines: ['avatar_v'] },
      HEYGEN_AVATAR_ENGINES.IV,
      'studio_avatar'
    );
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.V);
    assert.equal(plan.engineCoerced, true);
  });

  it('uses IV for a digital twin that lists IV', () => {
    const plan = resolveVideoPlanForLook(
      { id: 'twin_look', avatar_type: 'digital_twin', supported_api_engines: ['avatar_iv', 'avatar_v'] },
      HEYGEN_AVATAR_ENGINES.IV,
      'digital_twin'
    );
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.IV);
    assert.equal(plan.engineCoerced, false);
  });

  it('keeps IV on a look that lists every engine', () => {
    const plan = resolveVideoPlanForLook(ALL_ENGINES_LOOK, HEYGEN_AVATAR_ENGINES.IV, 'photo_avatar');
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.IV);
    assert.equal(plan.engineCoerced, false);
  });

  it('coerces IV to Avatar 6 Turbo on an Avatar-6-only photo look', () => {
    const plan = resolveVideoPlanForLook(AVATAR_6_ONLY_LOOK, HEYGEN_AVATAR_ENGINES.IV, 'photo_avatar');
    assert.equal(plan.videoApi, 'v3');
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO);
    assert.equal(plan.engineCoerced, true);
    assert.equal(plan.defaultAvatarEngine, HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO);
  });

  it('coerces V to Avatar 6 Turbo on an Avatar-6-only studio look', () => {
    const plan = resolveVideoPlanForLook(
      { ...AVATAR_6_ONLY_LOOK, avatar_type: 'studio_avatar' },
      HEYGEN_AVATAR_ENGINES.V,
      'studio_avatar'
    );
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO);
    assert.equal(plan.defaultAvatarEngine, HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO);
  });

  it('honours an explicit Avatar 6 (Pro) request when the look supports it', () => {
    const plan = resolveVideoPlanForLook(
      AVATAR_6_ONLY_LOOK,
      HEYGEN_AVATAR_ENGINES.AVATAR_6,
      'photo_avatar'
    );
    assert.equal(plan.engine, HEYGEN_AVATAR_ENGINES.AVATAR_6);
    assert.equal(plan.engineCoerced, false);
  });
});

describe('Avatar 6 looks', () => {
  const { enrichLookWithEngineHints } = require('./heygen');

  it('are not treated as legacy metadata looks', () => {
    assert.equal(usesHeygenLegacyV2VideoLook(AVATAR_6_ONLY_LOOK), false);
    assert.equal(isAvatarIiiOnlyLegacyLook(AVATAR_6_ONLY_LOOK), false);
  });

  it('expose Avatar 6 engines in supportedApiEngines', () => {
    const look = enrichLookWithEngineHints({ ...AVATAR_6_ONLY_LOOK });
    assert.equal(look.usesLegacyV2Video, false);
    assert.ok(look.supportedApiEngines.includes(HEYGEN_AVATAR_ENGINES.AVATAR_6));
    assert.ok(look.supportedApiEngines.includes(HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO));
  });

  it('builds the Avatar 6 engine payload', () => {
    assert.deepEqual(buildHeygenVideoEnginePayload(HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO), {
      type: 'heygen-avatar-6-turbo',
    });
  });

  it('forwards motion_expressiveness only for Avatar 6', () => {
    assert.deepEqual(
      buildHeygenVideoEnginePayload(HEYGEN_AVATAR_ENGINES.AVATAR_6, {
        motionExpressiveness: 'less',
      }),
      { type: 'heygen-avatar-6', motion_expressiveness: 'less' }
    );
    assert.deepEqual(
      buildHeygenVideoEnginePayload(HEYGEN_AVATAR_ENGINES.IV, { motionExpressiveness: 'less' }),
      { type: 'avatar_iv' }
    );
  });
});

describe('getEffectiveSupportedApiEnginesFromLook', () => {
  it('returns avatar_iii for III-only look', () => {
    assert.deepEqual(getEffectiveSupportedApiEnginesFromLook(III_ONLY_LOOK), [
      HEYGEN_AVATAR_ENGINES.III,
    ]);
  });
});

describe('enrichLookWithEngineHints', () => {
  const { enrichLookWithEngineHints } = require('./heygen');

  it('marks III-only look as v3 without legacy v2 flag', () => {
    const look = enrichLookWithEngineHints({ ...III_ONLY_LOOK });
    assert.equal(look.videoApi, 'v3');
    assert.equal(look.usesLegacyV2Video, false);
    assert.ok(look.supportedApiEngines.includes(HEYGEN_AVATAR_ENGINES.III));
  });
});