'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const AppError = require('../utils/AppError');
const messages = require('../utils/messages');

describe('heygenPolicy digital twin gate', () => {
  const prev = process.env.HEYGEN_DIGITAL_TWIN_CREATE_ENABLED;

  afterEach(() => {
    if (prev == null) delete process.env.HEYGEN_DIGITAL_TWIN_CREATE_ENABLED;
    else process.env.HEYGEN_DIGITAL_TWIN_CREATE_ENABLED = prev;
    delete require.cache[require.resolve('./heygenPolicy')];
  });

  it('blocks digital_twin create by default', () => {
    delete process.env.HEYGEN_DIGITAL_TWIN_CREATE_ENABLED;
    delete require.cache[require.resolve('./heygenPolicy')];
    const { assertHeygenAvatarCreateTypeAllowed } = require('./heygenPolicy');
    assert.throws(
      () => assertHeygenAvatarCreateTypeAllowed('digital_twin'),
      (err) =>
        err instanceof AppError &&
        err.statusCode === 403 &&
        err.message === messages.HEYGEN_DIGITAL_TWIN_CREATE_DISABLED
    );
  });

  it('allows photo avatars when twin create is off', () => {
    delete process.env.HEYGEN_DIGITAL_TWIN_CREATE_ENABLED;
    delete require.cache[require.resolve('./heygenPolicy')];
    const { assertHeygenAvatarCreateTypeAllowed } = require('./heygenPolicy');
    assert.doesNotThrow(() => assertHeygenAvatarCreateTypeAllowed('photo'));
  });

  it('allows digital_twin when explicitly enabled', () => {
    process.env.HEYGEN_DIGITAL_TWIN_CREATE_ENABLED = 'true';
    delete require.cache[require.resolve('./heygenPolicy')];
    const { assertHeygenAvatarCreateTypeAllowed } = require('./heygenPolicy');
    assert.doesNotThrow(() => assertHeygenAvatarCreateTypeAllowed('digital_twin'));
  });

  it('blocks training video upload when twin create is off', () => {
    delete process.env.HEYGEN_DIGITAL_TWIN_CREATE_ENABLED;
    delete require.cache[require.resolve('./heygenPolicy')];
    const { assertHeygenAvatarTrainingUploadAllowed } = require('./heygenPolicy');
    assert.throws(
      () => assertHeygenAvatarTrainingUploadAllowed('video/mp4'),
      (err) => err instanceof AppError && err.statusCode === 403
    );
    assert.doesNotThrow(() => assertHeygenAvatarTrainingUploadAllowed('image/jpeg'));
  });
});