'use strict';

/**
 * Slide revisions (CANVAS_FIX_PLAN_25NOV2026, D-1).
 *
 * Every write to a slide's `elements` doc bumps `elements.revision`. A client that sends the
 * revision it edited (`baseRevision`) gets 409 instead of overwriting a newer slide; requests
 * without it keep last-write-wins, so older frontends keep working. Same idea as the Canvas
 * module (`canvas.data.js` readRevision / isRevisionConflict).
 */
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

function readSlideRevision(elementsDoc) {
  const revision = Number(elementsDoc?.revision);
  return Number.isInteger(revision) && revision >= 0 ? revision : 0;
}

/** True when the client edited an older revision than the one stored. */
function isSlideRevisionConflict(baseRevision, storedRevision) {
  if (baseRevision === undefined || baseRevision === null || baseRevision === '') return false;
  return Number(baseRevision) !== storedRevision;
}

/** The doc to store, carrying its new revision (non-object docs are stored as given). */
function withSlideRevision(elementsDoc, revision) {
  if (!elementsDoc || typeof elementsDoc !== 'object' || Array.isArray(elementsDoc)) return elementsDoc;
  return { ...elementsDoc, revision };
}

function slideRevisionConflict() {
  const err = new AppError(messages.PRESENTATION_SLIDE_REVISION_CONFLICT, 409);
  err.slideRevisionConflict = true;
  return err;
}

function isSlideRevisionConflictError(err) {
  return Boolean(err && err.slideRevisionConflict);
}

/**
 * Run a server-side read-modify-write again when another write landed between its read and its
 * write (it passed the revision it read as `baseRevision`). Keeps both changes instead of the
 * second request silently dropping the first one.
 */
async function retryOnSlideRevisionConflict(fn, attempts = 3) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      if (!isSlideRevisionConflictError(err) || attempt >= attempts) throw err;
    }
  }
}

module.exports = {
  readSlideRevision,
  isSlideRevisionConflict,
  withSlideRevision,
  slideRevisionConflict,
  isSlideRevisionConflictError,
  retryOnSlideRevisionConflict,
};
