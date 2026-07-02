# Auth API

Base path: **`/api/auth`**

---

## OTP

### Generate OTP

Send OTP to the given email.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/otp/generate` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com"
}
```

**Response (200)** – `data`: `null`, `message`: `OTP sent to email`.

**Behavior:** Always returns **200** with the same message (anti-enumeration). If the email is **already registered**, no OTP email is sent.

**Errors**

| Status | When |
|--------|------|
| **400** | Invalid email (validation). |
| **429** | OTP requested too soon (`Please wait before requesting OTP again`) or too many resend attempts (`Too many OTP requests. Try again later`). |

---

### Resend OTP

Resend OTP to the same email.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/otp/resend` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com"
}
```

**Response (200)** – `data`: `null`, `message`: `OTP sent to email`.

Same behavior and errors as [Generate OTP](#generate-otp).

---

## Registration

### Verify OTP and register

Verify OTP and create a new user. Returns access token and sets refresh token cookie. New user gets a **private workspace** automatically.

When signing up from a workspace invitation link, include optional **`invitationToken`** (same UUID as in the invite URL). The email must match the invitation; on success the user is added to that workspace and `data.workspace` is returned.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/register` |
| **Auth** | None |

**Request body**

- `name`: string, 2–50 characters.
- `email`: valid email.
- `password`: string, minimum **8** characters.
- `otp`: **number** between `100000` and `999999` (JSON number, not a quoted string).
- `invitationToken` (optional): UUID from the workspace invitation link.

```json
{
  "name": "John Doe",
  "email": "user@example.com",
  "password": "yourSecurePassword",
  "otp": 308856,
  "invitationToken": "00000000-0000-4000-8000-000000000001"
}
```

**Response (201)** – `data`:

```json
{
  "accessToken": "eyJhbG...",
  "user": { "name": "John Doe", "email": "user@example.com" },
  "workspace": {
    "id": "uuid",
    "name": "My Team",
    "type": "TEAM",
    "ownerId": "uuid",
    "credits": 0,
    "owner": { "id": "...", "email": "...", "name": "..." },
    "createdAt": "ISO8601",
    "updatedAt": "ISO8601"
  }
}
```

`workspace` is present only when `invitationToken` was supplied and accepted. Other pending invitations for the same email still appear in the inbox after signup.

New users are created with `emailVerified: true` (OTP proves email ownership).

**Errors**

| Status | When |
|--------|------|
| **400** | Validation failure (name, email, password min 8, OTP format). |
| **400** | `Invitation was sent to a different email address` when `invitationToken` email does not match `email`. |
| **400** | Invalid or expired `invitationToken`. |
| **409** | `Email already registered` — redirect user to login, then `POST /api/workspaces/invitations/accept`. |
| **410** | OTP expired or not found. |
| **429** | Too many OTP verification attempts. |

---

## Login

### Login

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/login` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com",
  "password": "yourPassword"
}
```

**Response (200)** – `data`:

```json
{
  "accessToken": "eyJhbG...",
  "user": { "name": "John Doe", "email": "user@example.com" }
}
```

Refresh token is set in an HTTP-only cookie (`path: /`).

**Frontend:** On failure, always display `response.message` from the error envelope. The API does **not** return “user not registered” — unknown email and wrong password both return the same message (anti-enumeration).

**Errors**

| Status | When | `message` (typical) | Frontend action |
|--------|------|---------------------|-----------------|
| **401** | Invalid email/password, Google-only account, or permanently deleted account | `Invalid email or password` or `This account has been permanently deleted` | Show `response.message` |
| **429** | Login rate limit (per-email and per-IP buckets) | `Too many login attempts. Try again later.` | Show lockout message; read **`Retry-After`** response header (seconds) for countdown |

---

### Superadmin portal login (optional)

Only needed if you build a **separate admin login page**. If you use **one shared login page**, use normal [`POST /api/auth/login`](#login) plus [`GET /api/user/capabilities`](#get-capabilities) for the admin toggle instead.

Same credentials as normal login, but returns **403** if the user is not a platform superadmin (`User.isPlatformSuperadmin` or email in **`PLATFORM_SUPERADMIN_EMAILS`**).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/superadmin/login` |
| **Auth** | None |

**Request body** – same as login: `{ "email", "password" }`.

**Response (200)** – `data`:

```json
{
  "accessToken": "eyJhbG...",
  "user": { "name": "Admin", "email": "admin@company.com" },
  "isPlatformSuperadmin": true,
  "portal": "superadmin"
}
```

**403** – Valid credentials but not a platform superadmin (`Platform superadmin access required`).

Issues the **same** JWT and refresh cookie as normal login. Use **`GET /api/user/capabilities`** after main-platform login to decide whether to show the portal toggle.

---

## Token management

### Refresh access token

Cookie `refreshToken` must be sent.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/refresh` |
| **Auth** | Cookie: `refreshToken` |

**Response (201)** – `data`: `{ "accessToken": "eyJhbG..." }`. A new refresh token cookie is set.

---

## Logout

### Logout (current device)

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/logout` |
| **Auth** | Cookie: `refreshToken` |

Clears the refresh token cookie and invalidates the current session.

**Response (200)** – `data`: `{}`.

---

### Logout from all devices

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/logout-all` |
| **Auth** | `Authorization: Bearer <access_token>` |

Invalidates all refresh tokens for the user.

**Response (200)** – `data`: `{}`.

---

## Password reset

### Forget password

Sends a password reset link to the email. Response is the same whether or not the user exists (no email enumeration).

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/forget-password` |
| **Auth** | None |

**Request body**

```json
{
  "email": "user@example.com"
}
```

**Response (200)** – `data`: `{}`, `message`: `If the email exists, a password reset link has been sent`.

**Errors**

| Status | When |
|--------|------|
| **400** | Invalid email (validation). |
| **200** | Always returned for valid email format, including unknown addresses and SMTP failures (no email enumeration). |

Reset links expire after **15 minutes**. The email link format is `{FRONTEND_URL}/reset-password/{token}` (frontend reads `token` from the URL and sends it in the reset-password body).

---

### Reset password

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/reset-password` |
| **Auth** | None |

**Request body**

- `newPassword`: minimum **8** characters.

```json
{
  "token": "reset-token-from-email-link",
  "newPassword": "newSecurePassword"
}
```

**Response (200)** – `data`: `{}`, `message`: `Password reset successful. Please login again`.

**Errors**

| Status | When |
|--------|------|
| **400** | Validation failure (missing fields, `newPassword` shorter than 8 characters). |
| **400** | Invalid or expired reset token (`Invalid or expired password reset token`). |

On success, all refresh tokens and Redis sessions for the user are revoked; the client must log in again.

---

## Google OAuth

### Start Google sign-in

Redirect the browser to this URL. The user is sent to Google, then to the backend callback.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/auth/google` |
| **Auth** | None |

---

### Start Google sign-in (superadmin portal)

Same callback URL as main OAuth (`/api/auth/google/callback`). On success, redirects to **`SUPERADMIN_OAUTH_SUCCESS_PATH`** (default `/admin/auth/callback`) instead of the main app path. **403** if the Google account is not a platform superadmin.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/auth/superadmin/google` |
| **Auth** | None |

---

### Google OAuth callback

Google redirects here after consent. **Not called by your frontend directly**—configure this URL in the Google Cloud console as the authorized redirect URI.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/auth/google/callback` |
| **Auth** | None |

**Query**

- `code` (required)
- `state` (required)

On success, the backend redirects to:

- **Main portal:** `{FRONTEND_URL}{OAUTH_SUCCESS_PATH}#access_token=<access_token>` (default path `/auth/callback`)
- **Superadmin portal** (started via `/api/auth/superadmin/google`): `{FRONTEND_URL}{SUPERADMIN_OAUTH_SUCCESS_PATH}#access_token=<access_token>` (default path `/admin/auth/callback`)

(URL-encoded token in the hash.)

The frontend should read `access_token` from the hash and store it. A refresh token cookie is set on success (same pattern as email login when redirect URL is configured). If `FRONTEND_URL` is not set, the API may respond with `200` and JSON `data`: `{ "accessToken", "user" }` (superadmin flow also includes `isPlatformSuperadmin` and `portal`) instead of redirecting.

On error, the user is redirected to `{FRONTEND_URL}?error=...` with an error code in the query string.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

