const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createUserLifecycleService } = require('./superadminUserLifecycle.service');
const {
  pauseUserBodySchema,
  deleteUserBodySchema,
} = require('../validations/superadmin.validations');
const { isUserPaused, assertAccountActive } = require('../../shared/utils/accountStatus');

const ADMIN = '11111111-1111-1111-1111-111111111111';
const TARGET = '22222222-2222-2222-2222-222222222222';

function makeDeps(overrides = {}) {
  const calls = { paused: [], revoked: [], deleted: [] };
  const state = { target: { id: TARGET, email: 'jane@example.com', isPlatformSuperadmin: false, pausedAt: null } };
  const deps = {
    superadminDao: {
      findUserLifecycleState: async () => state.target,
      setUserPaused: async (id, data) => {
        calls.paused.push({ id, ...data });
        return { id, email: 'jane@example.com', storageLimit: 1024n, storageUsed: 0n, ...data };
      },
      findOwnedSharedTeamWorkspaces: async () => [],
      findUserSummaryById: async (id) => ({
        id,
        email: 'jane@example.com',
        storageLimit: 1024n,
        storageUsed: 0n,
        pausedAt: state.target.pausedAt,
      }),
    },
    revokeAllSessions: async (id) => {
      calls.revoked.push(id);
    },
    permanentlyDeleteUser: async (id) => {
      calls.deleted.push(id);
      return true;
    },
    logger: { info() {}, warn() {}, error() {} },
    ...overrides,
  };
  return { deps, calls, state };
}

async function assertAppError(promise, status, part) {
  await assert.rejects(promise, (err) => {
    assert.equal(err.statusCode, status);
    if (part) assert.match(String(err.message), part);
    return true;
  });
}

describe('accountStatus', () => {
  it('treats a user with pausedAt as paused', () => {
    assert.equal(isUserPaused({ pausedAt: new Date() }), true);
    assert.equal(isUserPaused({ pausedAt: null }), false);
    assert.equal(isUserPaused(null), false);
  });

  it('assertAccountActive throws 403 for a paused user and passes otherwise', () => {
    assert.throws(() => assertAccountActive({ pausedAt: new Date() }), (e) => e.statusCode === 403);
    assert.doesNotThrow(() => assertAccountActive({ pausedAt: null }));
    assert.doesNotThrow(() => assertAccountActive({}));
  });
});

describe('lifecycle validation schemas', () => {
  const validate = (schema, params, body) => schema.validate({ params, query: {}, body }, { stripUnknown: true });

  it('pause: reason is optional, trimmed, capped at 500, and userId must be a uuid', () => {
    assert.equal(validate(pauseUserBodySchema, { userId: TARGET }, {}).error, undefined);
    assert.equal(validate(pauseUserBodySchema, { userId: TARGET }, { reason: '  billing issue ' }).value.body.reason, 'billing issue');
    assert.ok(validate(pauseUserBodySchema, { userId: TARGET }, { reason: 'x'.repeat(501) }).error);
    assert.ok(validate(pauseUserBodySchema, { userId: 'nope' }, {}).error);
  });

  it('delete: requires a valid confirmEmail and normalizes it', () => {
    assert.ok(validate(deleteUserBodySchema, { userId: TARGET }, {}).error);
    assert.ok(validate(deleteUserBodySchema, { userId: TARGET }, { confirmEmail: 'nope' }).error);
    assert.equal(
      validate(deleteUserBodySchema, { userId: TARGET }, { confirmEmail: ' Jane@Example.COM ' }).value.body.confirmEmail,
      'jane@example.com'
    );
  });
});

describe('pauseUser', () => {
  it('pauses, stores the trimmed reason and revokes every session', async () => {
    const { deps, calls } = makeDeps();
    const result = await createUserLifecycleService(deps).pauseUser({
      targetUserId: TARGET,
      actorId: ADMIN,
      reason: '  non-payment ',
    });
    assert.equal(result.changed, true);
    assert.equal(calls.paused.length, 1);
    assert.equal(calls.paused[0].pauseReason, 'non-payment');
    assert.ok(calls.paused[0].pausedAt instanceof Date);
    assert.deepEqual(calls.revoked, [TARGET]);
    assert.equal(typeof result.user.storageLimit, 'number'); // BigInt serialized
  });

  it('stores null for a blank reason and truncates an over-long one', async () => {
    const { deps, calls } = makeDeps();
    const svc = createUserLifecycleService(deps);
    await svc.pauseUser({ targetUserId: TARGET, actorId: ADMIN, reason: '   ' });
    await svc.pauseUser({ targetUserId: TARGET, actorId: ADMIN, reason: 'y'.repeat(900) });
    assert.equal(calls.paused[0].pauseReason, null);
    assert.equal(calls.paused[1].pauseReason.length, 500);
  });

  it('is idempotent but still revokes sessions when already paused', async () => {
    const { deps, calls, state } = makeDeps();
    state.target.pausedAt = new Date();
    const result = await createUserLifecycleService(deps).pauseUser({ targetUserId: TARGET, actorId: ADMIN });
    assert.equal(result.changed, false);
    assert.equal(calls.paused.length, 0);
    assert.deepEqual(calls.revoked, [TARGET]);
  });

  it('refuses to pause yourself', async () => {
    const { deps, calls } = makeDeps();
    await assertAppError(createUserLifecycleService(deps).pauseUser({ targetUserId: ADMIN, actorId: ADMIN }), 400);
    assert.equal(calls.paused.length, 0);
  });

  it('returns 404 for an unknown user', async () => {
    const { deps } = makeDeps();
    deps.superadminDao.findUserLifecycleState = async () => null;
    await assertAppError(createUserLifecycleService(deps).pauseUser({ targetUserId: TARGET, actorId: ADMIN }), 404);
  });

  it('refuses to pause a platform superadmin (flag or env allowlist)', async () => {
    const { deps, state } = makeDeps();
    state.target.isPlatformSuperadmin = true;
    await assertAppError(createUserLifecycleService(deps).pauseUser({ targetUserId: TARGET, actorId: ADMIN }), 400, /administrator/i);

    state.target.isPlatformSuperadmin = false;
    const prev = process.env.PLATFORM_SUPERADMIN_EMAILS;
    process.env.PLATFORM_SUPERADMIN_EMAILS = 'jane@example.com';
    try {
      await assertAppError(createUserLifecycleService(deps).pauseUser({ targetUserId: TARGET, actorId: ADMIN }), 400);
    } finally {
      if (prev === undefined) delete process.env.PLATFORM_SUPERADMIN_EMAILS;
      else process.env.PLATFORM_SUPERADMIN_EMAILS = prev;
    }
  });

  it('propagates a session-revocation failure so the admin can retry', async () => {
    const { deps } = makeDeps({
      revokeAllSessions: async () => {
        throw new Error('redis down');
      },
    });
    await assert.rejects(createUserLifecycleService(deps).pauseUser({ targetUserId: TARGET, actorId: ADMIN }), /redis down/);
  });
});

describe('resumeUser', () => {
  it('clears pausedAt and the reason', async () => {
    const { deps, calls, state } = makeDeps();
    state.target.pausedAt = new Date();
    const result = await createUserLifecycleService(deps).resumeUser({ targetUserId: TARGET, actorId: ADMIN });
    assert.equal(result.changed, true);
    assert.deepEqual(calls.paused[0], { id: TARGET, pausedAt: null, pauseReason: null });
  });

  it('is a no-op for a user who is not paused', async () => {
    const { deps, calls } = makeDeps();
    const result = await createUserLifecycleService(deps).resumeUser({ targetUserId: TARGET, actorId: ADMIN });
    assert.equal(result.changed, false);
    assert.equal(calls.paused.length, 0);
  });

  it('returns 404 for an unknown user', async () => {
    const { deps } = makeDeps();
    deps.superadminDao.findUserLifecycleState = async () => null;
    await assertAppError(createUserLifecycleService(deps).resumeUser({ targetUserId: TARGET, actorId: ADMIN }), 404);
  });
});

describe('deleteUser', () => {
  const input = { targetUserId: TARGET, actorId: ADMIN, confirmEmail: 'jane@example.com' };

  it('revokes sessions then permanently deletes when the confirmation matches', async () => {
    const { deps, calls } = makeDeps();
    const result = await createUserLifecycleService(deps).deleteUser(input);
    assert.deepEqual(result, { deletedUserId: TARGET });
    assert.deepEqual(calls.revoked, [TARGET]);
    assert.deepEqual(calls.deleted, [TARGET]);
  });

  it('matches the confirmation email case- and whitespace-insensitively', async () => {
    const { deps, calls } = makeDeps();
    await createUserLifecycleService(deps).deleteUser({ ...input, confirmEmail: '  JANE@Example.com ' });
    assert.equal(calls.deleted.length, 1);
  });

  it('rejects a wrong or missing confirmation without touching anything', async () => {
    const { deps, calls } = makeDeps();
    const svc = createUserLifecycleService(deps);
    await assertAppError(svc.deleteUser({ ...input, confirmEmail: 'other@example.com' }), 400, /does not match/);
    await assertAppError(svc.deleteUser({ ...input, confirmEmail: undefined }), 400);
    assert.equal(calls.revoked.length, 0);
    assert.equal(calls.deleted.length, 0);
  });

  it('refuses when the user owns team workspaces other members still use', async () => {
    const { deps, calls } = makeDeps();
    deps.superadminDao.findOwnedSharedTeamWorkspaces = async () => [{ id: 'w1', name: 'Acme Team' }];
    await assertAppError(createUserLifecycleService(deps).deleteUser(input), 409, /Acme Team/);
    assert.equal(calls.revoked.length, 0);
    assert.equal(calls.deleted.length, 0);
  });

  it('refuses self-deletion and platform superadmins', async () => {
    const { deps, state, calls } = makeDeps();
    const svc = createUserLifecycleService(deps);
    await assertAppError(svc.deleteUser({ ...input, targetUserId: ADMIN }), 400);
    state.target.isPlatformSuperadmin = true;
    await assertAppError(svc.deleteUser(input), 400);
    assert.equal(calls.deleted.length, 0);
  });

  it('returns 404 when the user does not exist or vanished mid-delete', async () => {
    const { deps } = makeDeps();
    deps.superadminDao.findUserLifecycleState = async () => null;
    await assertAppError(createUserLifecycleService(deps).deleteUser(input), 404);

    const { deps: deps2 } = makeDeps({ permanentlyDeleteUser: async () => false });
    await assertAppError(createUserLifecycleService(deps2).deleteUser(input), 404);
  });

  it('maps a foreign-key violation to a 409 instead of a 500', async () => {
    const { deps } = makeDeps({
      permanentlyDeleteUser: async () => {
        const err = new Error('fk');
        err.code = 'P2003';
        throw err;
      },
    });
    await assertAppError(createUserLifecycleService(deps).deleteUser(input), 409, /still referenced/);
  });

  it('re-throws unexpected failures', async () => {
    const { deps } = makeDeps({
      permanentlyDeleteUser: async () => {
        throw new Error('s3 exploded');
      },
    });
    await assert.rejects(createUserLifecycleService(deps).deleteUser(input), /s3 exploded/);
  });
});
