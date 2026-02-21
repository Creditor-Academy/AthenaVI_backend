# Project Setup Guide

Follow these steps to set up the VI Backend project locally.

## Prerequisites
- **Node.js**: v18 or higher
- **PostgreSQL**: Local or remote instance
- **npm**: v9 or higher

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd VI_Backend
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

## Environment Configuration

The project uses separate environment files for development and production. `cross-env` is used to load the correct file based on the script you run.

1.  **Create your environment files:**
    Copy `.env.example` to create `.env.development` and `.env.production`.

    ```bash
    cp .env.example .env.development
    cp .env.example .env.production
    ```

2.  **Configure `.env.development`:**
    ```env
    PORT=3000
    DATABASE_URL="postgresql://user:password@localhost:5432/vi_backend_dev"
    ```

3.  **Configure `.env.production`:**
    ```env
    PORT=9000
    DATABASE_URL="postgresql://user:password@localhost:5432/vi_backend_prod"
    ```

4.  **For Google OAuth**, also set (see [Google OAuth Setup](#google-oauth-setup) below):
    ```env
    GOOGLE_CLIENT_ID=...
    GOOGLE_CLIENT_SECRET=...
    BACKEND_URL=http://localhost:3000
    FRONTEND_URL=http://localhost:5173
    ```

## Database Setup

1.  **Initialize the database (Development):**
    This command pushes the schema to the database defined in `.env.development`.

    ```bash
    npx prisma migrate dev --name init
    ```

2.  **Generate Prisma Client:**
    ```bash
    npx prisma generate
    ```

## Running the Application

### Development
Runs the server on `http://localhost:3000` with hot-reloading (nodemon). Uses `.env.development`.

```bash
npm run dev
```

### Production
Runs the server on `http://localhost:9000`. Uses `.env.production`.

```bash
npm start
```

## Project Structure

The project follows a **Modular MVC Architecture**:

```
src/
├── modules/            # Feature modules
│   └── health/         # Example feature
│       ├── health.controller.js
│       └── health.routes.js
├── routes/             # Main application router
├── middlewares/        # Global middlewares
├── utils/              # Global utilities (logger, etc.)
└── server.js           # Entry point
```

## Google OAuth Setup

1. **Google Cloud Console**
   - Go to [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials.
   - Create a **OAuth 2.0 Client ID** (Application type: **Web application**).
   - Under **Authorized redirect URIs** add exactly:
     - Development: `http://localhost:3000/api/auth/google/callback`
     - Production: `https://<your-api-domain>/api/auth/google/callback`
   - Copy the **Client ID** and **Client secret**.

2. **Environment variables**
   Add to `.env.development` / `.env.production`:
   - `GOOGLE_CLIENT_ID` – from the OAuth client.
   - `GOOGLE_CLIENT_SECRET` – from the OAuth client.
   - `BACKEND_URL` – base URL of this API (e.g. `http://localhost:3000` or `https://api.yourdomain.com`). Used to build the redirect URI for Google.
   - `FRONTEND_URL` – where to send the user after successful login (e.g. `http://localhost:5173` or `https://app.yourdomain.com`).
   - Optional: `OAUTH_SUCCESS_PATH` – path on frontend for the callback (default `/auth/callback`). User is redirected to `FRONTEND_URL + OAUTH_SUCCESS_PATH + #access_token=...`.

3. **Flow**
   - User visits `GET /api/auth/google` → redirected to Google → after consent, Google redirects to `GET /api/auth/google/callback?code=...&state=...`.
   - Backend exchanges `code` for tokens, verifies the id_token, creates or links the user, issues your app’s access token and refresh cookie, then redirects to the frontend with `access_token` in the URL hash.

## Commands Cheatsheet

| Command | Description |
| :--- | :--- |
| `npm run dev` | Start dev server (nodemon, .env.development) |
| `npm start` | Start production server (node, .env.production) |
| `npm run lint` | Run ESLint |
| `npm run format` | Format code with Prettier |
| `npx prisma studio` | Open database GUI |
