# Environment (for reference)

Frontend may need to know:

- **API base URL** – e.g. `process.env.REACT_APP_API_URL` or `NEXT_PUBLIC_API_URL` pointing to `https://your-backend.com/api`.
- **Google OAuth** – Register redirect URI `.../api/auth/google/callback`. After success, backend redirects to `FRONTEND_URL` + `OAUTH_SUCCESS_PATH` with `#access_token=...`. Superadmin portal OAuth uses the same callback; success redirect uses **`SUPERADMIN_OAUTH_SUCCESS_PATH`** (default `/admin/auth/callback`).
- **Invitations** – Email links use `{FRONTEND_URL}/invitations/accept/<token>`; your app should route the user to login if needed, then `POST /api/workspaces/invitations/accept` with `{ "token" }`.
- **Cookie** – Refresh token is HTTP-only; ensure credentials/cookies are sent when calling `/api/auth/refresh`, `/api/auth/logout`, etc. (`fetch`/`axios` with `credentials: 'include'` / `withCredentials: true`). The API must allow your frontend origin with credentials (not `Access-Control-Allow-Origin: *`); this server uses **`FRONTEND_URL`** or comma-separated **`CORS_ORIGINS`** for CORS.
- **HeyGen avatar videos** – Server **`HEYGEN_API_KEY`** (optional **`HEYGEN_BASE_URL`**), plus **AWS** (`AWS_S3_BUCKET`, `AWS_REGION`, credentials). Editor preview: see **HeyGen avatar videos → App developer checklist** (`/stream` vs `/download`, persisting **`heygenVideoId`**, CORS).
- **Large JSON** (e.g. voice clone **base64**) – Optional **`JSON_BODY_LIMIT`** (e.g. `32mb`). If unset, the server defaults to **15mb** for `express.json`.
- **Credits / billing** – `HEYGEN_BILLING_MODE` (`payg` \| `enterprise`, maps to HeyGen self-serve USD wallet vs enterprise credits), `ATHENA_MARGIN_PERCENT`, `ATHENA_AC_PER_USD`, `HEYGEN_ENTERPRISE_USD_PER_CREDIT`, `REMOTION_USD_PER_OUTPUT_SEC`, `CREDIT_ESTIMATE_WORDS_PER_MINUTE`, `PLATFORM_SUPERADMIN_EMAILS`. Scene video rates follow HeyGen official tables by `avatarType` (see `src/shared/config/creditPricing.js`).
- **Stock media (Pexels + Unsplash + Pixabay)** – `PEXELS_API_KEY`, `UNSPLASH_ACCESS_KEY`, `PIXABAY_API_KEY` (at least one required for `/api/stock/*`). Optional `STOCK_PHOTO_MAX_BYTES` (default 15 MB), `STOCK_VIDEO_MAX_BYTES` (default 100 MB). See [`STOCK_API.md`](STOCK_API.md).
- **Auth / rate limits** – `SALT_ROUNDS` (default **10**), `LOGIN_RATE_LIMIT_ACCOUNT` (default **10** failures per window), `LOGIN_RATE_LIMIT_IP` (default **30**), `LOGIN_RATE_LIMIT_WINDOW_SEC` (default **900** = 15 min), `TRUST_PROXY_HOPS` (set to proxy hop count in production; defaults to **1** when `NODE_ENV=production`).
- **Email normalization** – Before deploy, run `node scripts/normalize-user-emails.js` (with appropriate `.env`) if existing users may have mixed-case emails.

---

**End of API documentation**

---

**[← API index](README.md)** · [Project root README](../../README.md)

