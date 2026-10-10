const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Prisma } = require('@prisma/client');
const { createAdminUserService } = require('./superadminUserCreate.service');
const { createUserBodySchema } = require('../validations/superadmin.validations');
const buildAccountCreatedEmail = require('../../shared/templates/accountCreated.template');

const ADMIN_ID = '11111111-1111-1111-1111-111111111111';
const NEW_ID = '22222222-2222-2222-2222-222222222222';

function makeDeps(overrides = {}) {
  const calls = { create: [], email: [], token: [], hash: [], lookups: [] };
  const deps = {
    authDao: {
      findUserByEmail: async (email) => {
        calls.lookups.push(email);
        return null;
      },
      createUserWithPrivateWorkspace: async (data) => {
        calls.create.push(data);
        return { id: NEW_ID, name: data.name, email: data.email };
      },
    },
    superadminDao: {
      findUserSummaryById: async (id) => ({
        id,
        email: 'jane@example.com',
        name: 'Jane Doe',
        credits: 0,
        storageLimit: 1073741824n,
        storageUsed: 0n,
        isPlatformSuperadmin: false,
        createdAt: new Date('2026-10-10T00:00:00Z'),
      }),
    },
    generateResetToken: async (user, opts) => {
      calls.token.push({ user, opts });
      return 'raw-token-123';
    },
    sendEmail: async (mail) => {
      calls.email.push(mail);
    },
    hashPassword: async (plain) => {
      calls.hash.push(plain);
      return `hashed(${plain})`;
    },
    randomSecret: () => 'random-secret',
    getFrontendUrl: () => 'https://app.example.com',
    logger: { info() {}, warn() {}, error() {} },
    ...overrides,
  };
  return { deps, calls };
}

const validInput = {
  name: 'Jane Doe',
  email: 'jane@example.com',
  password: 'Sup3rSecret!',
  createdByUserId: ADMIN_ID,
};

async function assertAppError(promise, status, messagePart) {
  await assert.rejects(promise, (err) => {
    assert.equal(err.statusCode, status);
    if (messagePart) assert.match(String(err.message), messagePart);
    return true;
  });
}

describe('createUserBodySchema', () => {
  const validate = (body) =>
    createUserBodySchema.validate({ params: {}, query: {}, body }, { abortEarly: false, stripUnknown: true });

  it('accepts a minimal valid body and defaults sendWelcomeEmail to true', () => {
    const { error, value } = validate({ name: 'Jane', email: 'jane@example.com' });
    assert.equal(error, undefined);
    assert.equal(value.body.sendWelcomeEmail, true);
  });

  it('trims and lowercases the email and trims the name', () => {
    const { error, value } = validate({ name: '  Jane  ', email: '  Jane@Example.COM ' });
    assert.equal(error, undefined);
    assert.equal(value.body.email, 'jane@example.com');
    assert.equal(value.body.name, 'Jane');
  });

  it('rejects missing/short names and invalid emails', () => {
    assert.ok(validate({ email: 'a@b.co' }).error);
    assert.ok(validate({ name: 'J', email: 'a@b.co' }).error);
    assert.ok(validate({ name: 'x'.repeat(51), email: 'a@b.co' }).error);
    assert.ok(validate({ name: 'Jane', email: 'not-an-email' }).error);
    assert.ok(validate({ name: 'Jane' }).error);
  });

  it('rejects passwords shorter than 8 characters', () => {
    assert.ok(validate({ name: 'Jane', email: 'a@b.co', password: 'short' }).error);
  });

  it('rejects passwords over 72 bytes even when under the character limit (multi-byte)', () => {
    const emojiPassword = '😀'.repeat(20); // 20 chars, 80 bytes
    assert.ok(validate({ name: 'Jane', email: 'a@b.co', password: emojiPassword }).error);
  });

  it('treats an empty or null password as "not provided"', () => {
    assert.equal(validate({ name: 'Jane', email: 'a@b.co', password: '' }).error, undefined);
    assert.equal(validate({ name: 'Jane', email: 'a@b.co', password: null }).error, undefined);
  });

  it('rejects a body with neither a password nor the welcome email', () => {
    const { error } = validate({ name: 'Jane', email: 'a@b.co', sendWelcomeEmail: false });
    assert.ok(error);
    assert.match(error.message, /password or enable the welcome email/);
  });

  it('accepts a password with the welcome email disabled', () => {
    const { error } = validate({
      name: 'Jane',
      email: 'a@b.co',
      password: 'longenough1',
      sendWelcomeEmail: false,
    });
    assert.equal(error, undefined);
  });

  it('strips unknown fields so privilege flags cannot be smuggled in', () => {
    const { error, value } = validate({
      name: 'Jane',
      email: 'a@b.co',
      isPlatformSuperadmin: true,
      credits: 999999,
    });
    assert.equal(error, undefined);
    assert.equal('isPlatformSuperadmin' in value.body, false);
    assert.equal('credits' in value.body, false);
  });

  it('rejects an unexpected query string / params', () => {
    const { error } = createUserBodySchema.validate({
      params: {},
      query: { x: '1' },
      body: { name: 'Jane', email: 'a@b.co' },
    });
    assert.ok(error);
  });
});

describe('createUserByAdmin', () => {
  it('creates a verified user with the hashed admin-supplied password and sends the welcome email', async () => {
    const { deps, calls } = makeDeps();
    const { createUserByAdmin } = createAdminUserService(deps);

    const result = await createUserByAdmin(validInput);

    assert.equal(calls.create.length, 1);
    assert.deepEqual(calls.create[0], {
      name: 'Jane Doe',
      email: 'jane@example.com',
      password: 'hashed(Sup3rSecret!)',
      emailVerified: true,
    });
    assert.equal(result.welcomeEmailSent, true);
    assert.equal(result.user.id, NEW_ID);
    assert.equal(calls.email.length, 1);
    assert.equal(calls.email[0].to, 'jane@example.com');
  });

  it('serializes BigInt storage fields to JSON-safe numbers and never returns a password', async () => {
    const { deps } = makeDeps();
    const { user } = await createAdminUserService(deps).createUserByAdmin(validInput);

    assert.equal(user.storageLimit, 1073741824);
    assert.equal(typeof user.storageUsed, 'number');
    assert.equal('password' in user, false);
    assert.doesNotThrow(() => JSON.stringify(user));
  });

  it('normalizes the email for the duplicate lookup and the insert', async () => {
    const { deps, calls } = makeDeps();
    await createAdminUserService(deps).createUserByAdmin({ ...validInput, email: '  JANE@Example.COM ' });

    assert.deepEqual(calls.lookups, ['jane@example.com']);
    assert.equal(calls.create[0].email, 'jane@example.com');
  });

  it('trims the name', async () => {
    const { deps, calls } = makeDeps();
    await createAdminUserService(deps).createUserByAdmin({ ...validInput, name: '  Jane Doe  ' });
    assert.equal(calls.create[0].name, 'Jane Doe');
  });

  it('without a password, stores a random unknowable secret and emails a set-password link', async () => {
    const { deps, calls } = makeDeps();
    const result = await createAdminUserService(deps).createUserByAdmin({
      ...validInput,
      password: undefined,
    });

    assert.deepEqual(calls.hash, ['random-secret']);
    assert.equal(calls.create[0].password, 'hashed(random-secret)');
    assert.equal(result.welcomeEmailSent, true);
    assert.deepEqual(calls.token[0].opts, { expiryMinutes: 72 * 60 });
    assert.match(calls.email[0].text, /https:\/\/app\.example\.com\/reset-password\/raw-token-123/);
    assert.doesNotMatch(calls.email[0].text, /random-secret/);
  });

  it('never puts the admin-supplied password in the email', async () => {
    const { deps, calls } = makeDeps();
    await createAdminUserService(deps).createUserByAdmin(validInput);
    assert.doesNotMatch(calls.email[0].text, /Sup3rSecret!/);
    assert.doesNotMatch(calls.email[0].html, /Sup3rSecret!/);
  });

  it('does not send mail when sendWelcomeEmail is false', async () => {
    const { deps, calls } = makeDeps();
    const result = await createAdminUserService(deps).createUserByAdmin({
      ...validInput,
      sendWelcomeEmail: false,
    });
    assert.equal(result.welcomeEmailSent, false);
    assert.equal(calls.email.length, 0);
    assert.equal(calls.token.length, 0);
  });

  it('returns 409 when the email is already registered and does not create anything', async () => {
    const { deps, calls } = makeDeps();
    deps.authDao.findUserByEmail = async () => ({ id: 'existing' });
    await assertAppError(createAdminUserService(deps).createUserByAdmin(validInput), 409, /already registered/);
    assert.equal(calls.create.length, 0);
    assert.equal(calls.email.length, 0);
  });

  it('returns 409 when a concurrent signup wins the unique-constraint race', async () => {
    const { deps } = makeDeps();
    deps.authDao.createUserWithPrivateWorkspace = async () => {
      throw new Prisma.PrismaClientKnownRequestError('Unique constraint failed', {
        code: 'P2002',
        clientVersion: 'test',
      });
    };
    await assertAppError(createAdminUserService(deps).createUserByAdmin(validInput), 409);
  });

  it('re-throws unexpected database errors', async () => {
    const { deps } = makeDeps();
    deps.authDao.createUserWithPrivateWorkspace = async () => {
      throw new Error('connection lost');
    };
    await assert.rejects(createAdminUserService(deps).createUserByAdmin(validInput), /connection lost/);
  });

  it('keeps the account and reports welcomeEmailSent=false when sending fails', async () => {
    const { deps, calls } = makeDeps();
    deps.sendEmail = async () => {
      throw new Error('smtp down');
    };
    const result = await createAdminUserService(deps).createUserByAdmin(validInput);
    assert.equal(calls.create.length, 1);
    assert.equal(result.welcomeEmailSent, false);
    assert.equal(result.user.id, NEW_ID);
  });

  it('keeps the account when reset-token creation fails', async () => {
    const { deps } = makeDeps();
    deps.generateResetToken = async () => {
      throw new Error('db error');
    };
    const result = await createAdminUserService(deps).createUserByAdmin(validInput);
    assert.equal(result.welcomeEmailSent, false);
  });

  it('skips the email (without failing) when FRONTEND_URL is not configured', async () => {
    const { deps, calls } = makeDeps({ getFrontendUrl: () => '' });
    const result = await createAdminUserService(deps).createUserByAdmin(validInput);
    assert.equal(result.welcomeEmailSent, false);
    assert.equal(calls.email.length, 0);
    assert.equal(calls.create.length, 1);
  });

  it('rejects no-password + no-email so no unusable account is created', async () => {
    const { deps, calls } = makeDeps();
    await assertAppError(
      createAdminUserService(deps).createUserByAdmin({
        ...validInput,
        password: undefined,
        sendWelcomeEmail: false,
      }),
      400
    );
    assert.equal(calls.create.length, 0);
  });

  it('defends against bad input even if validation was bypassed', async () => {
    const { deps, calls } = makeDeps();
    const svc = createAdminUserService(deps);
    await assertAppError(svc.createUserByAdmin({ ...validInput, email: '   ' }), 400);
    await assertAppError(svc.createUserByAdmin({ ...validInput, name: '   ' }), 400);
    await assertAppError(svc.createUserByAdmin({ ...validInput, password: 'short' }), 400, /at least 8/);
    await assertAppError(svc.createUserByAdmin({ ...validInput, password: '😀'.repeat(20) }), 400, /72 bytes/);
    assert.equal(calls.create.length, 0);
  });

  it('falls back to the created row when the summary lookup returns nothing', async () => {
    const { deps } = makeDeps();
    deps.superadminDao.findUserSummaryById = async () => null;
    const { user } = await createAdminUserService(deps).createUserByAdmin(validInput);
    assert.deepEqual(user, { id: NEW_ID, email: 'jane@example.com', name: 'Jane Doe' });
  });
});

describe('buildAccountCreatedEmail', () => {
  const base = {
    name: 'Jane <script>',
    email: 'jane@example.com',
    setPasswordLink: 'https://app.example.com/reset-password/abc',
  };

  it('escapes the recipient name in HTML', () => {
    const { html } = buildAccountCreatedEmail(base);
    assert.doesNotMatch(html, /<script>/);
  });

  it('formats the expiry in days when it is a whole number of days', () => {
    assert.match(buildAccountCreatedEmail({ ...base, expiryHours: 72 }).text, /3 days/);
    assert.match(buildAccountCreatedEmail({ ...base, expiryHours: 24 }).text, /1 day\b/);
    assert.match(buildAccountCreatedEmail({ ...base, expiryHours: 12 }).text, /12 hours/);
  });

  it('falls back to a neutral greeting without a name', () => {
    assert.match(buildAccountCreatedEmail({ ...base, name: '' }).text, /^Hi there,/);
  });
});
