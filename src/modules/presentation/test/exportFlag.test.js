'use strict';

// PPT_EXPORT_V2 (Phase 7.1): who gets the new export pipeline, and what queueExport does with it.

const assert = require('assert');
const { test, afterEach } = require('node:test');

const { exportV2Mode, useExportV2, exportV2Status, emailDomain } = require('../exportFlag');

const ENV_KEYS = ['PPT_EXPORT_V2', 'PPT_EXPORT_V2_WORKSPACES', 'PPT_EXPORT_V2_EMAIL_DOMAINS'];
const savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

test('mode: on by default (today’s behaviour), off and internal when set; unknown values mean on', () => {
  assert.equal(exportV2Mode({}), 'on');
  assert.equal(exportV2Mode({ PPT_EXPORT_V2: '' }), 'on');
  assert.equal(exportV2Mode({ PPT_EXPORT_V2: 'OFF' }), 'off');
  assert.equal(exportV2Mode({ PPT_EXPORT_V2: 'false' }), 'off');
  assert.equal(exportV2Mode({ PPT_EXPORT_V2: ' internal ' }), 'internal');
  assert.equal(exportV2Mode({ PPT_EXPORT_V2: 'true' }), 'on');
  assert.equal(exportV2Mode({ PPT_EXPORT_V2: 'everyone?' }), 'on');
});

test('internal: listed workspaces and email domains get V2, everyone else does not', async () => {
  const env = {
    PPT_EXPORT_V2: 'internal',
    PPT_EXPORT_V2_WORKSPACES: 'ws-internal, WS-Other',
    PPT_EXPORT_V2_EMAIL_DOMAINS: '@studio.test,team.test',
  };
  let lookups = 0;
  const findUserEmail = async (id) => {
    lookups += 1;
    return { u1: 'a@studio.test', u2: 'b@Team.Test', u3: 'c@customer.test' }[id] || null;
  };
  assert.equal(await useExportV2({ workspaceId: 'ws-internal', userId: 'u3', findUserEmail }, env), true);
  assert.equal(await useExportV2({ workspaceId: 'ws-other', userId: 'u3', findUserEmail }, env), true, 'ids ignore case');
  assert.equal(lookups, 0, 'a listed workspace needs no user lookup');
  assert.equal(await useExportV2({ workspaceId: 'w9', userId: 'u1', findUserEmail }, env), true);
  assert.equal(await useExportV2({ workspaceId: 'w9', userId: 'u2', findUserEmail }, env), true, 'domains ignore case');
  assert.equal(await useExportV2({ workspaceId: 'w9', userId: 'u3', findUserEmail }, env), false);
  assert.equal(await useExportV2({ workspaceId: 'w9', userId: 'nobody', findUserEmail }, env), false);
  const broken = async () => {
    throw new Error('db down');
  };
  assert.equal(await useExportV2({ workspaceId: 'w9', userId: 'u1', findUserEmail: broken }, env), false, 'a failed lookup is not V2');
});

test('on and off ignore the lists', async () => {
  const lists = { PPT_EXPORT_V2_WORKSPACES: 'w1', PPT_EXPORT_V2_EMAIL_DOMAINS: 'studio.test' };
  assert.equal(await useExportV2({ workspaceId: 'w2' }, { ...lists, PPT_EXPORT_V2: 'on' }), true);
  assert.equal(await useExportV2({ workspaceId: 'w1' }, { ...lists, PPT_EXPORT_V2: 'off' }), false);
});

test('health status shows the mode and how many entries each list has, never the entries', () => {
  const status = exportV2Status({ PPT_EXPORT_V2: 'internal', PPT_EXPORT_V2_WORKSPACES: 'a,b', PPT_EXPORT_V2_EMAIL_DOMAINS: 'x.test' });
  assert.deepEqual(status, { mode: 'internal', workspaces: 2, emailDomains: 1 });
  assert.equal(emailDomain('Name@Example.COM'), 'example.com');
  assert.equal(emailDomain('no-at-sign'), '');
});

test('queueExport stores the decision on the job; without V2 the job runs in this process', async () => {
  const deckGeneration = require('../deckGeneration.service');
  const presentationDao = require('../presentation.dao');
  const presentationCredit = require('../presentationCredit.service');
  const exportQueue = require('../exportQueue');
  const userDao = require('../../user/user.dao');
  deckGeneration.loadPresentationDeck = async () => ({ deck: { id: 'deck1', slides: [] }, project: { id: 'p1', name: 'Deck' } });
  presentationCredit.assertAfford = async () => {};
  let n = 0;
  presentationDao.createExport = async (data) => ({ id: `e${(n += 1)}`, ...data });
  const queued = [];
  exportQueue.enqueue = async (data, opts = {}) => {
    queued.push({ exportV2: data.exportV2, local: Boolean(opts.local) });
    return opts.local ? 'local' : 'bullmq';
  };
  userDao.getUserById = async (id) => ({ email: id === 'staff' ? 'me@studio.test' : 'x@customer.test' });
  const exportService = require('../export.service');
  const ask = (userId) => exportService.queueExport({ workspaceId: 'w1', presentationId: 'p1', userId, format: 'PDF' });

  delete process.env.PPT_EXPORT_V2;
  await ask('customer');
  process.env.PPT_EXPORT_V2 = 'internal';
  process.env.PPT_EXPORT_V2_EMAIL_DOMAINS = 'studio.test';
  await ask('staff');
  await ask('customer');
  process.env.PPT_EXPORT_V2 = 'off';
  await ask('staff');

  assert.deepEqual(queued, [
    { exportV2: true, local: false },
    { exportV2: true, local: false },
    { exportV2: false, local: true },
    { exportV2: false, local: true },
  ]);
});
