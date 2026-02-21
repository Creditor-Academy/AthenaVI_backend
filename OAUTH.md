# Google OAuth – What You Need To Do

## 1. Google Cloud Console

1. Open [Google Cloud Console](https://console.cloud.google.com/) and select (or create) a project.
2. Go to **APIs & Services** → **Credentials**.
3. Click **Create Credentials** → **OAuth client ID**.
4. If prompted, configure the **OAuth consent screen** (External is fine for testing; add your app name and support email).
5. Choose **Web application** as the application type.
6. Set **Authorized redirect URIs** to **exactly**:
   - **Local:** `http://localhost:3000/api/auth/google/callback` (or your dev `PORT` and host).
   - **Production:** `https://<your-backend-host>/api/auth/google/callback`  
   Example: `https://api.yourdomain.com/api/auth/google/callback`.
7. Save and copy the **Client ID** and **Client secret**.

## 2. Environment Variables

Add these to `.env.development` and `.env.production` as needed:

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLIENT_ID` | Yes | OAuth client ID from Google. |
| `GOOGLE_CLIENT_SECRET` | Yes | OAuth client secret from Google. |
| `BACKEND_URL` | Yes for OAuth | Full base URL of this API (no trailing slash). e.g. `http://localhost:3000` or `https://api.yourdomain.com`. Used to build the redirect URI sent to Google. |
| `FRONTEND_URL` | No (recommended) | Where to redirect after successful login. e.g. `http://localhost:5173` or `https://app.yourdomain.com`. If missing, callback returns JSON instead of redirecting. |
| `OAUTH_SUCCESS_PATH` | No | Path on the frontend for the success redirect. Default: `/auth/callback`. Final redirect: `FRONTEND_URL + OAUTH_SUCCESS_PATH + #access_token=...` |

Example `.env.development`:

```env
PORT=3000
DATABASE_URL="postgresql://..."
REDIS_URL="redis://localhost:6379"
JWT_SECRET="your-secret"
SALT_ROUNDS=10

GOOGLE_CLIENT_ID=123456789-xxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxx
BACKEND_URL=http://localhost:3000
FRONTEND_URL=http://localhost:5173
```

## 3. Frontend

1. **Start the login flow**  
   Redirect the user to:
   ```text
   GET <BACKEND_URL>/api/auth/google
   ```
   Example: `window.location.href = 'http://localhost:3000/api/auth/google'`.

2. **Handle the callback**  
   After Google sign-in, the user is redirected to:
   ```text
   <FRONTEND_URL><OAUTH_SUCCESS_PATH>#access_token=<JWT>
   ```
   Example: `http://localhost:5173/auth/callback#access_token=eyJhbG...`

   On that page (e.g. `/auth/callback`):
   - Read `access_token` from the hash: `window.location.hash` or a small parser.
   - Store the token (e.g. in memory or secure storage) and use it in the `Authorization: Bearer <access_token>` header for API calls.
   - Remove the hash from the URL if you want a clean URL (e.g. `history.replaceState`).

3. **Refresh token**  
   The backend also sets an HTTP-only cookie for refresh. To get a new access token, call:
   ```text
   POST /api/auth/refresh
   ```
   with credentials (e.g. `fetch(..., { credentials: 'include' })`). The response body contains a new `accessToken`.

4. **Optional: error query params**  
   On failure, the user is redirected to:
   ```text
   <FRONTEND_URL>?error=<code>
   ```
   Possible `error` values: `missing_code`, `invalid_state`, `token_exchange_failed`, `no_id_token`, `invalid_id_token`, `no_email`. You can show a message and a “Try again” link to `/api/auth/google`.

## 4. Production Checklist

- [ ] Use HTTPS for both backend and frontend.
- [ ] Add the **exact** production callback URL to Google’s “Authorized redirect URIs” (e.g. `https://api.yourdomain.com/api/auth/google/callback`).
- [ ] Set `BACKEND_URL` and `FRONTEND_URL` to production URLs in `.env.production`.
- [ ] Keep `GOOGLE_CLIENT_SECRET` only on the server; never expose it in the frontend or in git.
- [ ] If frontend and API are on different domains, ensure CORS and cookie settings (`sameSite`, `secure`) allow your frontend to send the refresh cookie when calling `/api/auth/refresh` (e.g. `credentials: 'include'` and allowed origin).
