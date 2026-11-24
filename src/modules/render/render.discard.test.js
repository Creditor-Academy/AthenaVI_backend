'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SRC = path.resolve(__dirname, '../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const deleted = [];
let deleteShouldFail = false;
stub('modules/s3/s3.service.js', {
  async uploadFileToKey() {
    throw new Error('not used');
  },
  async getPresignedGetUrl() {
    throw new Error('not used');
  },
  async deleteFile(key) {
    if (deleteShouldFail) throw new Error('s3 down');
    deleted.push(key);
  },
});

const renderDao = require('./render.dao');
const { discardUnbilledRenderOutput } = require('./render.service');

const realFind = renderDao.findProjectRenderByIdOnly;
function withRender(row, fn) {
  renderDao.findProjectRenderByIdOnly = async () => row;
  return fn().finally(() => {
    renderDao.findProjectRenderByIdOnly = realFind;
  });
}

test('does nothing when no file was uploaded', async () => {
  deleted.length = 0;
  assert.deepEqual(await discardUnbilledRenderOutput('r1', null), {});
  assert.equal(deleted.length, 0);
});

test('deletes the upload and clears the output columns when the render was not billed', async () => {
  deleted.length = 0;
  const cleared = await withRender({ billingStatus: 'pending' }, () =>
    discardUnbilledRenderOutput('r1', 'renders/r1/final.mp4')
  );
  assert.deepEqual(deleted, ['renders/r1/final.mp4']);
  assert.deepEqual(cleared, { s3Key: null, outputUrl: null, fileSizeBytes: null, completedAt: null });
});

test('never deletes the video of a render that was already billed', async () => {
  deleted.length = 0;
  const cleared = await withRender({ billingStatus: 'charged' }, () =>
    discardUnbilledRenderOutput('r1', 'renders/r1/final.mp4')
  );
  assert.equal(deleted.length, 0);
  assert.deepEqual(cleared, {});
});

test('keeps the row pointing at the file when the delete itself fails', async () => {
  deleted.length = 0;
  deleteShouldFail = true;
  const realError = console.error;
  console.error = () => {};
  try {
    const cleared = await withRender({ billingStatus: 'pending' }, () =>
      discardUnbilledRenderOutput('r1', 'renders/r1/final.mp4')
    );
    assert.deepEqual(cleared, {});
  } finally {
    console.error = realError;
    deleteShouldFail = false;
  }
});
