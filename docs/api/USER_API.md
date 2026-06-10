# User API

Base path: **`/api/user`**

All routes below require **`Authorization: Bearer <access_token>`**.

---

## Get all users

Returns all user records from the database (intended for admin or internal use). **Responses currently include full user rows as stored** (e.g. may include `password` when the account has a password). Prefer a dedicated admin API with field selection for production exposure.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/getall` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "users": [ { "id": "...", "email": "...", "name": "...", "password": "...", ... } ],
  "count": 10
}
```

---

## Get profile

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/profile` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "profile": {
    "email": "user@example.com",
    "name": "John Doe",
    "profileImage": "https://...",
    "phoneNumber": "+1...",
    "createdAt": "ISO8601"
  }
}
```

---

## Get capabilities

Returns platform-level capabilities for the authenticated user. Call after main-platform login or token refresh to show/hide the **superadmin portal toggle**. Toggle navigation is client-side only (same Bearer token for both portals).

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/capabilities` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "isPlatformSuperadmin": true,
  "canAccessSuperadminPortal": true
}
```

Both fields are `false` for non-superadmin users. Superadmin credit APIs under `/api/superadmin/*` still enforce access on every request.

---

## Update profile

At least one of `name` or `phoneNumber` must be present. `phoneNumber` must match server validation (digits, `+`, `-`, `()`, optional single space; length 8–20).

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/profile` |
| **Auth** | Bearer |

**Request body** (partial)

```json
{
  "name": "Jane Doe",
  "phoneNumber": "+1(310) 1234567"
}
```

**Response (200)** – `data`: `{ "profile": { "email", "name", "phoneNumber", "createdAt" } }`.

---

## Upload profile image

`multipart/form-data` with a single file field **`profileImage`**.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/user/upload/profile-image` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "profile": { "id", "profileImage" } }`.

---

## Delete profile image

| | |
|---|---|
| **Method** | `DELETE` |
| **Path** | `/api/user/profile-image` |
| **Auth** | Bearer |

**Response (200)** – `data`: `{ "profile": { "id", "profileImage" } }` (`profileImage` cleared).

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

