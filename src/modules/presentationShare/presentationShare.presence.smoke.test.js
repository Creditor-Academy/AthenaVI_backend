const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { redisClient } = require('../../shared/config/redis');
const presence = require('./presentationShare.presence');
const { toPublicSlide } = require('../presentation/deckRender.service');
const { enrichSlideForClient } = require('../presentation/elementContent.normalize');
const shareValidations = require('../validations/presentationShare.validations');
const { DECK_SLIDE_MAX } = require('../presentation/presentation.constants');
const { MAX_PAGE_LIMIT } = require('../presentation/deckRender.service');
const presentationValidations = require('../validations/presentation.validations');
const messages = require('../../shared/utils/messages');

function installMemoryRedis() {
  const store = new Map();
  const zsets = new Map();

  redisClient.get = async (key) => (store.has(key) ? store.get(key) : null);
  redisClient.set = async (key, value, opts = {}) => {
    if (opts.NX && store.has(key)) return null;
    store.set(key, value);
    return 'OK';
  };
  redisClient.del = async (keyOrKeys) => {
    const keys = Array.isArray(keyOrKeys) ? keyOrKeys : [keyOrKeys];
    for (const key of keys) store.delete(key);
    return keys.length;
  };
  redisClient.zAdd = async (key, { value }) => {
    if (!zsets.has(key)) zsets.set(key, new Set());
    zsets.get(key).add(value);
  };
  redisClient.zRem = async (key, value) => {
    zsets.get(key)?.delete(value);
  };
  redisClient.zCard = async (key) => zsets.get(key)?.size || 0;
  redisClient.zRangeWithScores = async (key) =>
    [...(zsets.get(key) || [])].map((value) => ({ value, score: 1 }));
  redisClient.zRemRangeByScore = async () => 0;
  redisClient.expire = async () => true;
  return store;
}

describe('Present lock smoke', () => {
  const projectId = 'deck_1';
  beforeEach(() => {
    installMemoryRedis();
  });

  it('first writer wins, leaveToken only on NX, seq bumps, public cursor hides secrets', async () => {
    const first = await presence.acquireOrRefreshPresenter({
      projectId,
      userId: 'u1',
      displayName: 'Alex',
      slideIndex: 2,
      presenting: true,
    });
    assert.equal(first.acquired, true);
    assert.ok(first.leaveToken);
    assert.equal(first.presenter.slideIndex, 2);
    assert.equal(first.presenter.seq, 1);
    assert.equal('userId' in first.presenter, false);
    assert.equal('leaveToken' in first.presenter, false);

    const again = await presence.acquireOrRefreshPresenter({
      projectId,
      userId: 'u1',
      displayName: 'Alex',
      slideIndex: 3,
      presenting: true,
    });
    assert.equal(again.acquired, false);
    assert.equal(again.leaveToken, null);
    assert.equal(again.presenter.seq, 2);
    assert.equal(again.presenter.slideIndex, 3);

    await assert.rejects(
      () =>
        presence.acquireOrRefreshPresenter({
          projectId,
          userId: 'u2',
          displayName: 'Sam',
          slideIndex: 0,
          presenting: true,
        }),
      (err) => {
        assert.equal(err.statusCode, 409);
        assert.equal(err.message, messages.PRESENTATION_ALREADY_PRESENTING);
        assert.equal(err.errors[0].presentingUserId, 'u1');
        assert.equal(err.errors[0].displayName, 'Alex');
        return true;
      }
    );

    const pub = await presence.getPublicPresenter(projectId);
    assert.deepEqual(Object.keys(pub).sort(), ['displayName', 'seq', 'slideIndex', 'updatedAt']);

    const released = await presence.leavePresenter(projectId, { leaveToken: first.leaveToken });
    assert.equal(released.released, true);
    assert.equal(await presence.getPublicPresenter(projectId), null);
  });

  it('presenting:false from holder releases; other users keep the lock and can follow', async () => {
    await presence.acquireOrRefreshPresenter({
      projectId,
      userId: 'u1',
      displayName: 'Alex',
      presenting: true,
    });

    const follow = await presence.acquireOrRefreshPresenter({
      projectId,
      userId: 'u2',
      displayName: 'Sam',
      presenting: false,
      slideIndex: 0,
    });
    assert.equal(follow.released, false);
    assert.equal(follow.presenter.displayName, 'Alex');

    const stop = await presence.acquireOrRefreshPresenter({
      projectId,
      userId: 'u1',
      displayName: 'Alex',
      presenting: false,
    });
    assert.equal(stop.released, true);
    assert.equal(await presence.getPublicPresenter(projectId), null);
  });

  it('Bearer leave matches holder userId; wrong token is a no-op', async () => {
    await presence.acquireOrRefreshPresenter({
      projectId,
      userId: 'u1',
      displayName: 'Alex',
      presenting: true,
    });
    const miss = await presence.leavePresenter(projectId, { leaveToken: 'not-the-token-value-xx' });
    assert.equal(miss.released, false);
    assert.ok(await presence.getPublicPresenter(projectId));

    const ok = await presence.leavePresenter(projectId, { userId: 'u1' });
    assert.equal(ok.released, true);
  });

  it('clearRoom deletes presenter lock', async () => {
    await presence.acquireOrRefreshPresenter({
      projectId,
      userId: 'u1',
      displayName: 'Alex',
      presenting: true,
    });
    await presence.clearRoom(projectId);
    assert.equal(await presence.getPublicPresenter(projectId), null);
  });
});

describe('Notes + validation smoke', () => {
  it('MAX_PAGE_LIMIT matches DECK_SLIDE_MAX and Joi preview max', () => {
    assert.equal(MAX_PAGE_LIMIT, DECK_SLIDE_MAX);
    const ok = presentationValidations.presentationPreviewSchema.validate({
      params: {
        workspaceId: '11111111-1111-1111-1111-111111111111',
        presentationId: 'p1',
      },
      query: { offset: 0, limit: 40 },
    });
    assert.equal(ok.error, undefined);
    const over = presentationValidations.presentationPreviewSchema.validate({
      params: {
        workspaceId: '11111111-1111-1111-1111-111111111111',
        presentationId: 'p1',
      },
      query: { offset: 0, limit: 41 },
    });
    assert.ok(over.error);
  });

  it('member preview notes come from elements/content; guest omits the key', () => {
    const raw = {
      id: 's1',
      order: 0,
      status: 'READY',
      content: { speakerNotes: 'from content' },
      elements: { speakerNotes: 'from elements', elements: [] },
    };
    const enriched = enrichSlideForClient(raw);
    assert.equal(enriched.speakerNotes, 'from elements');
    const guest = toPublicSlide(enriched);
    assert.equal('speakerNotes' in guest, false);
    const member = toPublicSlide(enriched, { includeNotes: true });
    assert.equal(member.speakerNotes, 'from elements');
  });

  it('member leave accepts query leaveToken (sendBeacon); heartbeat requires presenting true to hold lock', () => {
    const leave = shareValidations.memberPresenceLeaveSchema.validate({
      params: {
        workspaceId: '11111111-1111-1111-1111-111111111111',
        presentationId: 'p1',
      },
      query: { leaveToken: 'abcdefghijklmnopqrstuvwxyz012345' },
      body: {},
    });
    assert.equal(leave.error, undefined);

    const hb = shareValidations.memberPresenceHeartbeatSchema.validate({
      params: {
        workspaceId: '11111111-1111-1111-1111-111111111111',
        presentationId: 'p1',
      },
      body: { slideIndex: 0 },
    });
    assert.equal(hb.error, undefined);
    assert.equal(hb.value.body.presenting, false);
  });
});
