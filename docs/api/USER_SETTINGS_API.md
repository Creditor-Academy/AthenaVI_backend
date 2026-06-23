# User settings API

Base path: **`/api/user/settings`**

All routes require **`Authorization: Bearer <access_token>`**. Settings are stored per authenticated user in `user_settings`. Additional tabs (security, billing) will be added under this base path later.

---

## Get appearance settings

Returns the user’s **Appearance** preferences (interface mode, theme palette, custom accent). If the user has never saved appearance settings, the API returns the same defaults the UI uses on first load.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/settings/appearance` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "appearance": {
    "interfaceMode": "light",
    "themePalette": "sapphire",
    "customAccentColor": "#2563EB"
  }
}
```

| Field | Type | Values |
|-------|------|--------|
| `interfaceMode` | string | `light`, `dark` |
| `themePalette` | string | `original`, `sapphire`, `ocean`, `forest`, `sunset`, `custom` |
| `customAccentColor` | string | 6-digit hex with leading `#` (e.g. `#2563EB`) |

---

## Update appearance settings

Partial update; send at least one field. Values are persisted for the current user (row created on first update).

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/settings/appearance` |
| **Auth** | Bearer |

**Request body** (partial)

```json
{
  "interfaceMode": "dark",
  "themePalette": "custom",
  "customAccentColor": "#7C3AED"
}
```

**Response (200)** – `data`: `{ "appearance": { "interfaceMode", "themePalette", "customAccentColor" } }` (full object after merge).

**400** – Validation error (invalid enum, malformed hex, or empty body).

---

## Get notification settings

Returns the user’s **Notifications** preferences (email and in-app toggles). If the user has never saved settings, the API returns the same defaults the UI uses on first load.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/settings/notifications` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "notifications": {
    "pushNotifications": true,
    "commentsAndMentions": true,
    "weeklyDigestEmail": false,
    "productEmails": false,
    "videoExportAlerts": true,
    "workspaceVideoExportAlerts": true,
    "creditsAlerts": true,
    "storageAlerts": true,
    "workspaceTeamAlerts": true,
    "platformAdminAlerts": true
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `pushNotifications` | boolean | Master switch for in-app notifications |
| `commentsAndMentions` | boolean | Teammate comments and @mentions |
| `weeklyDigestEmail` | boolean | Weekly usage and activity summary email |
| `productEmails` | boolean | Feature announcements and product updates |
| `videoExportAlerts` | boolean | Final Remotion export complete/fail (exporter) |
| `workspaceVideoExportAlerts` | boolean | Teammate final exports (OWNER/ADMIN) |
| `creditsAlerts` | boolean | Credit grants, revokes, low balance |
| `storageAlerts` | boolean | Storage quota warnings and upload blocked |
| `workspaceTeamAlerts` | boolean | Invitations, member joined/removed, role changes |
| `platformAdminAlerts` | boolean | Platform alerts (superadmin portal only) |

---

## Update notification settings

Partial update; send at least one boolean field. Persists for the current user (creates `user_settings` on first update if needed).

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/settings/notifications` |
| **Auth** | Bearer |

**Request body** (partial)

```json
{
  "pushNotifications": true,
  "commentsAndMentions": true,
  "weeklyDigestEmail": false,
  "productEmails": false,
  "videoExportAlerts": true,
  "workspaceVideoExportAlerts": true,
  "creditsAlerts": true,
  "storageAlerts": true,
  "workspaceTeamAlerts": true,
  "platformAdminAlerts": true
}
```

**Response (200)** – `data`: `{ "notifications": { ... } }` (full object after merge).

**400** – Validation error (non-boolean value or empty body).

---

## Get security settings

Returns password capability and account-deletion status for the **Security** tab.

| | |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/user/settings/security` |
| **Auth** | Bearer |

**Response (200)** – `data`:

```json
{
  "security": {
    "hasPassword": true,
    "canChangePassword": true,
    "accountDeletion": {
      "pending": false
    }
  }
}
```

When deletion is scheduled, `accountDeletion` includes:

```json
{
  "pending": true,
  "requestedAt": "ISO8601",
  "permanentDeletionAt": "ISO8601",
  "recoverableUntil": "ISO8601",
  "daysRemaining": 6,
  "gracePeriodDays": 7
}
```

---

## Change password

For email/password accounts only. OAuth-only accounts receive **400** (`PASSWORD_CHANGE_NOT_AVAILABLE`).

| | |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/user/settings/security/password` |
| **Auth** | Bearer |

**Request body**

```json
{
  "currentPassword": "old-password",
  "newPassword": "new-password"
}
```

`newPassword` must be at least **6** characters.

**Response (200)** – `data`: `{ "passwordChanged": true }`.

**400** – Wrong current password or account cannot change password locally.

---

## Delete account (scheduled)

Two-step confirmation: the client must send **`confirmation": "delete"`** (exact string, lowercase).

Schedules permanent deletion after **7 days** (override with env **`ACCOUNT_DELETION_GRACE_DAYS`**). All sessions are revoked immediately and the refresh cookie is cleared.

**Recovery:** If the user signs in again (email/password or Google) **before** `permanentDeletionAt`, the account and all data are restored automatically. Login/OAuth responses may include **`accountRecovered": true`** in `data`.

After the grace period, a background job permanently deletes the user, owned workspace data, and related S3 objects.

| | |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/user/settings/security/delete-account` |
| **Auth** | Bearer |

**Request body**

```json
{
  "confirmation": "delete"
}
```

**Response (200)** – `data`:

```json
{
  "accountDeletion": {
    "pending": true,
    "requestedAt": "ISO8601",
    "permanentDeletionAt": "ISO8601",
    "recoverableUntil": "ISO8601",
    "daysRemaining": 7,
    "gracePeriodDays": 7
  }
}
```

**400** – Confirmation text is not exactly `delete`.

**409** – Deletion is already scheduled.

**401** – After permanent deletion, login returns `ACCOUNT_PERMANENTLY_DELETED`.

---

---

**[← API index](README.md)** · [Project root README](../../README.md)

