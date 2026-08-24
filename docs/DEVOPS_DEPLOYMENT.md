# Athena VI Backend — Production Deployment Guide

**Audience:** DevOps / platform engineering  
**Environment:** Production only  
**Last updated:** June 2025

This document describes how to deploy the **Athena VI** backend API on **AWS** using **ALB + EC2 + Nginx**, with DNS on **GoDaddy**.

For API contracts and frontend integration, see [docs/api/README.md](api/README.md). For a Render-based staging setup, see [DEPLOY_RENDER.md](DEPLOY_RENDER.md).

---

## 1. Summary

| Item | Value |
|------|-------|
| **Product** | Athena VI (Virtual Instructor) — backend API |
| **Repository** | `AthenaVI_backend` |
| **Runtime** | Node.js 20+ LTS, CommonJS |
| **Framework** | Express 5 |
| **Entry point** | `src/server.js` |
| **Start command** | `npm start` → `NODE_ENV=production node src/server.js` |
| **Internal app port** | `9000` |
| **API prefix** | `/api` |
| **Production API URL** | `https://vi.api.lmsathena.com` |
| **Production API base** | `https://vi.api.lmsathena.com/api` |
| **Domain registrar / DNS** | GoDaddy (`lmsathena.com`) |
| **TLS** | HTTPS required — use **GoDaddy SSL** (import to ALB) **or** free **AWS ACM** cert (see §5) |
| **Health check** | `GET /` → `Virtual Instructor Backend Running` |
| **S3** | Reuse existing `virtual-instructor` bucket (`us-east-1`) — no new bucket setup |

**Frontend URL (confirm with frontend team):** `https://vi.lmsathena.com` — used for `FRONTEND_URL`, CORS, OAuth redirects, and email links.

---

## 2. Architecture

```mermaid
flowchart TB
    subgraph Internet
        FE[Frontend<br/>vi.lmsathena.com]
        ADMIN[Superadmin portal<br/>same or separate origin]
    end

    subgraph GoDaddy
        DNS[DNS: vi.api CNAME → ALB]
    end

    subgraph AWS
        ALB[ALB :443<br/>TLS cert]
        EC2[EC2 private subnet<br/>Nginx :80]
        NODE[Node.js :9000<br/>localhost]
        RDS[(RDS PostgreSQL)]
        REDIS[(ElastiCache Redis)]
        S3[(S3 bucket)]
        NAT[NAT Gateway]
    end

    subgraph External
        SMTP[SMTP / SES]
        GOOGLE[Google OAuth]
        HEYGEN[HeyGen API]
        STOCK[Pexels / Unsplash / Pixabay]
    end

    FE --> DNS
    ADMIN --> DNS
    DNS --> ALB
    ALB --> EC2
    EC2 --> NODE
    NODE --> RDS
    NODE --> REDIS
    NODE --> S3
    NODE --> NAT
    NAT --> SMTP
    NAT --> GOOGLE
    NAT --> HEYGEN
    NAT --> STOCK
```

**Traffic path:** Browser → GoDaddy DNS → **ALB (HTTPS)** → **Nginx (HTTP :80)** → **Node.js (:9000)**.

TLS terminates at the ALB (recommended). Nginx on EC2 does not need a certificate in that setup.

**Startup dependencies:** PostgreSQL and Redis must be reachable at boot. The process exits if either connection fails.

---

## 3. TLS / SSL (GoDaddy vs ACM)

**Important:** GoDaddy **DNS** (pointing `vi.api` to AWS) is separate from GoDaddy **SSL**. Registering the domain in GoDaddy does **not** automatically encrypt traffic to your ALB or EC2. Something must present a certificate for `https://vi.api.lmsathena.com`.

Because you use an **ALB**, the public HTTPS listener on port **443** needs a certificate **on the ALB** (unless you switch to NLB TLS passthrough — not covered here).

### Option A — GoDaddy SSL you already own (typical if you bought SSL from GoDaddy)

1. In GoDaddy, download the certificate for `vi.api.lmsathena.com` (or a wildcard `*.lmsathena.com`):
   - Certificate (`.crt`)
   - Private key (`.key`)
   - Certificate chain / intermediate (`.ca-bundle` or similar)
2. In **AWS Certificate Manager (ACM)** → **Import certificate**:
   - Paste/upload the cert, private key, and chain
   - Region must match the ALB (e.g. `us-east-1`)
3. Attach the **imported** cert to the ALB HTTPS listener (`vi.api.lmsathena.com`).
4. ALB → EC2 Nginx on **HTTP port 80** (no cert needed on EC2).

You are **not** buying ACM — you are **hosting** your existing GoDaddy certificate inside AWS so the ALB can use it. Renew via GoDaddy before expiry and re-import.

### Option B — Free AWS ACM certificate (no GoDaddy SSL purchase)

1. Request a **public** cert in ACM for `vi.api.lmsathena.com`.
2. Validate via **DNS**: ACM gives a CNAME; add it in **GoDaddy DNS** (§5.2).
3. Attach to ALB HTTPS listener.
4. Auto-renews while DNS validation record stays in place.

Use this if you do **not** have a GoDaddy SSL product, or want free auto-renewal.

### Option C — GoDaddy SSL only on Nginx (no cert on ALB)

Only if DevOps explicitly chooses **not** to terminate TLS at the ALB:

- Use **NLB with TLS passthrough**, or
- ALB HTTPS listener still needs a cert on the ALB for clients — so this rarely avoids a cert on the load balancer.

**Default recommendation for this project:** **Option A** if GoDaddy SSL is already purchased; otherwise **Option B** (free ACM + DNS validation in GoDaddy).

Production auth cookies require **HTTPS** on the API URL (`secure: true` cookies).

---

## 4. Domains & URLs

| Purpose | URL |
|---------|-----|
| API (public) | `https://vi.api.lmsathena.com` |
| API routes | `https://vi.api.lmsathena.com/api` |
| Health check | `GET https://vi.api.lmsathena.com/` |
| Google OAuth callback | `https://vi.api.lmsathena.com/api/auth/google/callback` |
| OAuth success (main app) | `https://vi.lmsathena.com/auth/callback#access_token=...` |
| OAuth success (superadmin) | `https://vi.lmsathena.com/admin/auth/callback#access_token=...` |
| Password reset | `https://vi.lmsathena.com/reset-password/{token}` |
| Workspace invitations | `https://vi.lmsathena.com/invitations/accept/{token}` |

---

## 5. AWS resources to provision

| Resource | Purpose | Notes |
|----------|---------|-------|
| **VPC** | Network isolation | Minimum 2 availability zones |
| **Public subnets** | ALB | Internet-facing load balancer |
| **Private subnets** | EC2, RDS, Redis | No direct inbound from internet |
| **NAT Gateway** | EC2 outbound traffic | HeyGen, Google, SMTP, S3 API calls |
| **ALB** | HTTPS entry, health checks | TLS cert attached (GoDaddy import or ACM) |
| **EC2** | Application server | See sizing below |
| **RDS PostgreSQL** | Primary database | v14+; private subnet |
| **ElastiCache Redis** | Cache, rate limits | **Required** at startup |
| **S3** | Assets, videos, renders | **Reuse existing bucket** — no new bucket setup (see §13) |
| **IAM role** | EC2 → S3 access | Grant prod EC2 access to existing bucket (or reuse current IAM keys) |
| **ACM** | TLS certificate store | Import GoDaddy SSL **or** issue free ACM cert |
| **Secrets Manager / SSM** | Production secrets | Do not commit `.env.production` |
| **CloudWatch** | Logs and metrics | Recommended |
| **Jenkins** | CI/CD | Build, migrate, deploy to EC2 |

### EC2 sizing

| Profile | Instance type | vCPU | RAM | Disk |
|---------|---------------|------|-----|------|
| **Minimum** | `c6i.xlarge` | 4 | 8 GB | 100 GB gp3 |
| **Recommended (Remotion on same host)** | `c6i.2xlarge` | 8 | 16 GB | 100–200 GB gp3 |

Remotion server-side video rendering uses Chromium and FFmpeg and is CPU/RAM intensive. Monitor `/tmp` disk usage during renders.

**OS:** Ubuntu 22.04 LTS or Amazon Linux 2023.

---

## 6. GoDaddy DNS

Domain **lmsathena.com** is managed in GoDaddy. AWS hosts the application.

### 6.1 API record

| Type | Name | Value | TTL |
|------|------|-------|-----|
| **CNAME** | `vi.api` | `<alb-name>.<region>.elb.amazonaws.com` | 600 |

Example result: `vi.api.lmsathena.com` → ALB.

Do **not** point DNS directly at EC2. Only the ALB hostname is used.

### 6.2 ACM DNS validation (Option B only — free ACM cert)

If using a **new ACM-issued** certificate (not a GoDaddy import), add the validation CNAME in GoDaddy exactly as AWS provides:

| Type | Name | Value |
|------|------|-------|
| **CNAME** | `_xxxx.vi.api` | `_yyyy.acm-validations.aws.` |

Skip this step if you **import** a GoDaddy SSL certificate into ACM (Option A).

### 6.3 Frontend (separate from this doc)

Frontend hosting is outside this backend deployment. Confirm the production frontend hostname and set `FRONTEND_URL` / `CORS_ORIGINS` accordingly. Expected: `https://vi.lmsathena.com`.

---

## 7. Security groups

### ALB security group

| Direction | Port | Source / destination |
|-----------|------|----------------------|
| Inbound | 443 | `0.0.0.0/0` |
| Inbound | 80 | `0.0.0.0/0` (redirect to HTTPS) |
| Outbound | 80 | EC2 security group |

### EC2 security group

| Direction | Port | Source / destination |
|-----------|------|----------------------|
| Inbound | 80 | ALB security group only |
| Inbound | 22 | Jenkins / bastion IP only |
| Outbound | All | Via NAT (RDS, Redis, S3, external APIs) |

**Do not** expose port `9000` to the internet. Node is reached only via Nginx on localhost.

### RDS security group

| Direction | Port | Source |
|-----------|------|--------|
| Inbound | 5432 | EC2 security group |

### Redis security group

| Direction | Port | Source |
|-----------|------|--------|
| Inbound | 6379 | EC2 security group |

---

## 8. ALB configuration

| Setting | Value |
|---------|-------|
| Scheme | Internet-facing |
| Listener (HTTPS) | Port 443, TLS cert for `vi.api.lmsathena.com` (GoDaddy import or ACM) |
| Listener (HTTP) | Port 80 → redirect to HTTPS |
| Target group port | **80** (Nginx) |
| Target type | Instance (EC2) |
| Health check path | `/` |
| Health check port | Traffic port (80) |
| Success codes | `200` |
| Interval | 30s |
| Healthy / unhealthy threshold | 2 / 3 |
| **Idle timeout** | **600 seconds** |

Increase idle timeout for large uploads (HeyGen avatar twin up to ~900 MB) and long Remotion renders.

---

## 9. EC2 setup

### 9.1 System packages

```bash
# Node.js 20 LTS (via nvm, NodeSource, or official packages)
node -v   # >= 20

# Build tools (bcrypt native module)
sudo apt update
sudo apt install -y build-essential python3 git nginx

# Remotion / Chromium dependencies (Ubuntu)
sudo apt install -y \
  libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 \
  libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2 \
  libpango-1.0-0 libcairo2 libatspi2.0-0 ffmpeg
```

### 9.2 Application directory

```bash
sudo mkdir -p /opt/athena-vi
sudo chown $USER:$USER /opt/athena-vi
```

Place `.env.production` at `/opt/athena-vi/.env.production` (from Secrets Manager / SSM, not Git).

### 9.3 Nginx configuration

File: `/etc/nginx/sites-available/athena-vi`

```nginx
upstream athena_api {
    server 127.0.0.1:9000;
    keepalive 32;
}

server {
    listen 80;
    server_name vi.api.lmsathena.com;

    client_max_body_size 1024m;
    client_body_timeout 600s;
    proxy_read_timeout 600s;
    proxy_connect_timeout 60s;
    proxy_send_timeout 600s;

    location / {
        proxy_pass http://athena_api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
    }
}
```

Enable:

```bash
sudo ln -sf /etc/nginx/sites-available/athena-vi /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl reload nginx
```

No certificate on EC2 when TLS terminates at the ALB (Options A or B).

### 9.4 Process manager (PM2)

```bash
cd /opt/athena-vi
npm ci --omit=dev
npx prisma migrate deploy
pm2 start src/server.js --name athena-api
pm2 save
pm2 startup
```

**PM2 ecosystem** (`/opt/athena-vi/ecosystem.config.js`):

```javascript
module.exports = {
  apps: [{
    name: 'athena-api',
    script: 'src/server.js',
    cwd: '/opt/athena-vi',
    env: { NODE_ENV: 'production' },
    instances: 1,
    max_memory_restart: '2G',
    kill_timeout: 30000,
  }],
};
```

**Note:** Background jobs (account deletion purge, platform HeyGen wallet alerts) run inside the Node process. Use **one instance** unless you implement leader election.

---

## 10. Environment variables

The app loads `.env.production` when `NODE_ENV=production` (see `src/server.js`).

Store secrets in **AWS Secrets Manager** or **SSM Parameter Store**. Inject at deploy time; never commit production secrets to Git.

### 10.1 Required

| Variable | Production value / notes |
|----------|--------------------------|
| `NODE_ENV` | `production` |
| `PORT` | `9000` |
| `BACKEND_URL` | `https://vi.api.lmsathena.com` |
| `FRONTEND_URL` | `https://vi.lmsathena.com` *(confirm)* |
| `CORS_ORIGINS` | `https://vi.lmsathena.com` *(add superadmin origin if different)* |
| `TRUST_PROXY_HOPS` | `1` (ALB → Nginx → Node) |
| `DATABASE_URL` | RDS PostgreSQL connection string |
| `REDIS_URL` | ElastiCache Redis URL (`redis://` or `rediss://`) |
| `JWT_SECRET` | Long random string (64+ characters); **new for prod** |
| `AWS_REGION` | `us-east-1` (existing bucket region) |
| `AWS_S3_BUCKET` | `virtual-instructor` (existing shared bucket — same as dev/staging) |
| `AWS_ACCESS_KEY_ID` | Reuse existing IAM user/role with bucket access, or EC2 instance role |
| `AWS_SECRET_ACCESS_KEY` | Same credentials as today (omit if using EC2 instance role) |
| `SMTP_HOST` | e.g. AWS SES SMTP endpoint |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password |
| `SMTP_PORT` | `587` (default) or `465` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret |
| `GOOGLE_FONTS_API_KEY` | Optional Web Fonts Developer API key for live `/api/fonts` merge (snapshot works without it) |
| `HEYGEN_API_KEY` | HeyGen API key |
| `PLATFORM_SUPERADMIN_EMAILS` | Comma-separated platform admin emails |

### 10.2 Recommended

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_SUCCESS_PATH` | `/auth/callback` | Frontend path after Google login |
| `SUPERADMIN_OAUTH_SUCCESS_PATH` | `/admin/auth/callback` | Superadmin OAuth redirect |
| `SALT_ROUNDS` | `10` | bcrypt cost factor |
| `JSON_BODY_LIMIT` | `32mb` | Express JSON body limit |
| `HEYGEN_BILLING_MODE` | `payg` | `payg` or `enterprise` |
| `ATHENA_MARGIN_PERCENT` | `40` | Credit pricing margin |
| `ATHENA_AC_PER_USD` | `10000` | Athena credits per USD |
| `HEYGEN_ENTERPRISE_USD_PER_CREDIT` | `0.50` | Enterprise billing rate |
| `REMOTION_USD_PER_OUTPUT_SEC` | `0.01` | Remotion export pricing |
| `CREDIT_ESTIMATE_WORDS_PER_MINUTE` | `150` | Credit estimation |
| `DEFAULT_STORAGE_LIMIT_BYTES` | `1073741824` | Free tier storage (1 GB) |

### 10.3 Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `PEXELS_API_KEY` | — | Stock media (at least one key for `/api/stock/*`) |
| `UNSPLASH_ACCESS_KEY` | — | Stock media |
| `PIXABAY_API_KEY` | — | Stock media |
| `STOCK_PHOTO_MAX_BYTES` | 15 MB | Stock photo import limit |
| `STOCK_VIDEO_MAX_BYTES` | 100 MB | Stock video import limit |
| `LOGIN_RATE_LIMIT_ACCOUNT` | `10` | Failed logins per account per window |
| `LOGIN_RATE_LIMIT_IP` | `30` | Failed logins per IP per window |
| `LOGIN_RATE_LIMIT_WINDOW_SEC` | `900` | Rate limit window (15 min) |
| `ACCOUNT_DELETION_GRACE_DAYS` | `7` | Days before account purge |
| `ACCOUNT_DELETION_JOB_INTERVAL_MS` | `3600000` | Account purge job (1h) |
| `PLATFORM_ALERTS_JOB_INTERVAL_MS` | `3600000` | HeyGen wallet alert job (1h) |
| `CREDITS_LOW_THRESHOLD_AC` | `100` | Low-credit notification threshold |
| `PLATFORM_HEYGEN_WALLET_THRESHOLD_USD` | `50` | Platform wallet alert threshold |
| `PLATFORM_SUPERADMIN_NOTIFICATION_EMAIL` | superadmin emails | Storage upgrade request inbox |
| `STORAGE_UPGRADE_REQUEST_COOLDOWN_SEC` | `86400` | 24h cooldown per user |
| `REMOTION_DELAY_RENDER_TIMEOUT_MS` | `120000` | Remotion render timeout (2 min) |
| `REDIS_CONNECT_TIMEOUT` | `30000` | Redis connect timeout |
| `HEYGEN_BASE_URL` | HeyGen default | Override only if needed |

### 10.4 Example `.env.production` template

```env
NODE_ENV=production
PORT=9000

BACKEND_URL=https://vi.api.lmsathena.com
FRONTEND_URL=https://vi.lmsathena.com
CORS_ORIGINS=https://vi.lmsathena.com
TRUST_PROXY_HOPS=1

DATABASE_URL=postgres://USER:PASS@RDS_HOST:5432/athena?sslmode=require
REDIS_URL=redis://ELASTICACHE_HOST:6379

JWT_SECRET=<GENERATE_NEW_SECRET>
SALT_ROUNDS=10

AWS_REGION=us-east-1
AWS_S3_BUCKET=virtual-instructor
# Reuse existing IAM credentials (same as current environment), or EC2 instance role:
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

SMTP_HOST=<SMTP_HOST>
SMTP_PORT=587
SMTP_USER=<SMTP_USER>
SMTP_PASS=<SMTP_PASS>

GOOGLE_CLIENT_ID=<GOOGLE_CLIENT_ID>
GOOGLE_CLIENT_SECRET=<GOOGLE_CLIENT_SECRET>
# GOOGLE_FONTS_API_KEY=<optional Web Fonts Developer API key>

HEYGEN_API_KEY=<HEYGEN_API_KEY>
HEYGEN_BILLING_MODE=payg

ATHENA_MARGIN_PERCENT=40
ATHENA_AC_PER_USD=10000
HEYGEN_ENTERPRISE_USD_PER_CREDIT=0.50
REMOTION_USD_PER_OUTPUT_SEC=0.01
CREDIT_ESTIMATE_WORDS_PER_MINUTE=150

PLATFORM_SUPERADMIN_EMAILS=admin@lmsathena.com

JSON_BODY_LIMIT=32mb
```

---

## 11. PostgreSQL (RDS)

| Setting | Value |
|---------|-------|
| Engine | PostgreSQL 14+ |
| Network | Private subnet; SG allows EC2 only |
| SSL | Use `sslmode=require` in `DATABASE_URL` |
| Backups | Automated snapshots enabled |

### Migrations

Run on every deploy (after `npm ci`):

```bash
export NODE_ENV=production
cd /opt/athena-vi
npx prisma migrate deploy
```

Migrations live in `prisma/migrations/`. `npm ci` runs `prisma generate` via `postinstall`.

### One-time pre-deploy script (if migrating existing users)

```bash
node scripts/normalize-user-emails.js
```

---

## 12. Redis (ElastiCache)

| Setting | Value |
|---------|-------|
| Required | **Yes** — app exits on startup failure |
| URL | `redis://host:6379` or `rediss://...` for TLS |
| Use cases | Login rate limiting, caching |

---

## 13. S3 (existing bucket — no new setup)

Production uses the **same S3 bucket and region as the current environment**. No new bucket, CORS, or bucket policy work is required unless DevOps prefers to lock down prod EC2 with a dedicated IAM role.

| Setting | Value |
|---------|-------|
| **Bucket** | `virtual-instructor` |
| **Region** | `us-east-1` |
| **Env vars** | `AWS_S3_BUCKET`, `AWS_REGION`, plus existing `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (or EC2 IAM role with the same permissions) |

### DevOps action (minimal)

1. Set the env vars above in production `.env.production` (or Secrets Manager).
2. Ensure the **prod EC2 instance role** (or IAM user) has the same S3 permissions already used by dev — `PutObject`, `GetObject`, `DeleteObject`, `HeadObject`, `CopyObject` on `arn:aws:s3:::virtual-instructor/*`.
3. Confirm EC2 outbound HTTPS (443) to S3 via NAT or VPC endpoint.

**No action needed:** create bucket, bucket naming, public URL format, or key layout — unchanged from today.

Object keys remain application-managed (`users/...`, `workspace/...`). Public URLs: `https://virtual-instructor.s3.us-east-1.amazonaws.com/{key}`.

---

## 14. Google OAuth

Configure in [Google Cloud Console](https://console.cloud.google.com/):

| Setting | Value |
|---------|-------|
| Authorized redirect URI | `https://vi.api.lmsathena.com/api/auth/google/callback` |
| Authorized JavaScript origins | `https://vi.lmsathena.com` |

Add additional origins if the superadmin portal runs on a separate domain.

---

## 15. Authentication & CORS (DevOps-relevant)

| Item | Detail |
|------|--------|
| Access token | JWT Bearer; expires in **1 day** |
| Refresh token | HTTP-only cookie `refreshToken`; 7 days; `secure: true` in production |
| CORS | `credentials: true`; origins from `FRONTEND_URL` / `CORS_ORIGINS` — not `*` |
| Frontend | Must send `credentials: 'include'` on `/api/auth/refresh` and `/api/auth/logout` |

API (`vi.api.lmsathena.com`) and frontend (`vi.lmsathena.com`) are cross-origin. CORS must explicitly allow the frontend origin.

---

## 16. Upload & payload limits

Configure ALB idle timeout, Nginx, and env vars consistently.

| Layer / endpoint | Limit |
|------------------|-------|
| Profile image | 2 MB |
| Workspace asset upload | 50 MB |
| HeyGen voice clone (multipart) | 100 MB |
| HeyGen avatar twin (multipart) | 900 MB |
| Express JSON (`JSON_BODY_LIMIT`) | Default `32mb` |
| Nginx `client_max_body_size` | `1024m` |
| ALB idle timeout | `600s` |

---

## 17. Jenkins CI/CD

### Suggested pipeline stages

1. **Checkout** — clone repository  
2. **Install** — `npm ci` (runs `prisma generate`)  
3. **Lint** — `npm run lint` (optional gate)  
4. **Deploy** — rsync/SSH to EC2  
5. **Migrate** — `npx prisma migrate deploy` on EC2  
6. **Restart** — `pm2 reload athena-api`  
7. **Verify** — ALB target healthy; smoke test `GET /`

### Deploy commands (on EC2)

```bash
cd /opt/athena-vi
git pull origin main          # or rsync from Jenkins
npm ci --omit=dev
npx prisma migrate deploy
pm2 reload athena-api
```

### Example Jenkins pipeline (reference)

```groovy
pipeline {
    agent any
    environment {
        DEPLOY_DIR = '/opt/athena-vi'
        APP_HOST = '<ec2-private-ip-or-bastion-target>'
    }
    stages {
        stage('Checkout') {
            steps { checkout scm }
        }
        stage('Install & Lint') {
            steps {
                sh 'npm ci'
                sh 'npm run lint'
            }
        }
        stage('Deploy') {
            steps {
                sh '''
                    rsync -avz --delete \
                      --exclude node_modules \
                      --exclude .env* \
                      ./ deploy-user@${APP_HOST}:${DEPLOY_DIR}/
                '''
                sh '''
                    ssh deploy-user@${APP_HOST} "
                      cd ${DEPLOY_DIR} &&
                      npm ci --omit=dev &&
                      npx prisma migrate deploy &&
                      pm2 reload athena-api || pm2 start ecosystem.config.js
                    "
                '''
            }
        }
    }
}
```

---

## 18. API route prefixes (WAF / monitoring)

| Path prefix | Domain |
|-------------|--------|
| `/api/auth` | Authentication, OAuth |
| `/api/user` | Profile, inbox, settings, storage |
| `/api/workspaces` | Workspaces, folders, projects, renders, HeyGen videos |
| `/api/credits` | Workspace credits |
| `/api/assets` | Workspace file assets |
| `/api/heygen` | User-scoped HeyGen (avatars, voices) |
| `/api/stock` | Stock media search/import |
| `/api/superadmin` | Platform admin |

Full route table: [docs/api/QUICK_REFERENCE.md](api/QUICK_REFERENCE.md).

---

## 19. Background jobs

Started automatically when the server boots (`src/server.js`):

| Job | Default interval | Purpose |
|-----|------------------|---------|
| Account deletion purge | 1 hour | Permanently deletes accounts past grace period |
| Platform HeyGen wallet alert | 1 hour | Notifies superadmins when HeyGen wallet is low |

---

## 20. Post-deployment verification

| # | Check | Expected |
|---|-------|----------|
| 1 | `nslookup vi.api.lmsathena.com` | Resolves to ALB |
| 2 | `curl -s https://vi.api.lmsathena.com/` | `Virtual Instructor Backend Running` |
| 3 | ALB target group | Healthy |
| 4 | App logs | `Database connected and verified`, `Redis connected` |
| 5 | `POST /api/auth/otp/generate` | OTP email delivered |
| 6 | `GET /api/auth/google` | 302 redirect to Google |
| 7 | Google OAuth full flow | Redirect to frontend with `#access_token` |
| 8 | `POST /api/auth/refresh` with cookie | New access token |
| 9 | Asset upload | Object in S3 |
| 10 | CORS from frontend | Login and refresh work with credentials |

---

## 21. Monitoring & logging

| Item | Recommendation |
|------|----------------|
| App logs | Winston → stdout; ship to CloudWatch Logs agent |
| Process | PM2 or systemd with auto-restart |
| Metrics | CPU, RAM, disk (`/tmp` for Remotion), RDS connections, Redis memory |
| Alerts | App down, unhealthy ALB targets, RDS storage, Redis OOM |

---

## 22. Secrets handoff checklist

Provide DevOps / store in Secrets Manager:

- [ ] `DATABASE_URL` (RDS endpoint + credentials)
- [ ] `REDIS_URL` (ElastiCache endpoint)
- [ ] `JWT_SECRET` (new production secret, not dev value)
- [ ] `AWS_S3_BUCKET=virtual-instructor`, `AWS_REGION=us-east-1` (existing bucket — reuse current IAM access)
- [ ] `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_PORT`
- [ ] `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- [ ] Optional `GOOGLE_FONTS_API_KEY` for live font catalog merge
- [ ] `HEYGEN_API_KEY`
- [ ] `PLATFORM_SUPERADMIN_EMAILS`
- [ ] Stock API keys (if stock feature enabled)
- [ ] GoDaddy: CNAME `vi.api` → ALB
- [ ] TLS cert on ALB (GoDaddy import into ACM, or free ACM + DNS validation CNAME)
- [ ] Google OAuth redirect URI registered
- [ ] Frontend `FRONTEND_URL` confirmed

---

## 23. Outbound connectivity (EC2 via NAT)

EC2 must reach:

| Destination | Port | Purpose |
|-------------|------|---------|
| RDS | 5432 | PostgreSQL |
| ElastiCache | 6379 | Redis |
| S3 | 443 | Object storage |
| SMTP / SES | 587 or 465 | Email (OTP, invites, resets) |
| `accounts.google.com`, `oauth2.googleapis.com` | 443 | Google OAuth |
| `api.heygen.com` | 443 | HeyGen avatars/videos |
| `api.pexels.com`, `api.unsplash.com`, `pixabay.com` | 443 | Stock media (optional) |

---

## 24. Related documentation

| Document | Purpose |
|----------|---------|
| [docs/api/README.md](api/README.md) | API index |
| [docs/api/OVERVIEW.md](api/OVERVIEW.md) | Auth, response format |
| [docs/api/ENVIRONMENT.md](api/ENVIRONMENT.md) | Env vars (frontend-focused) |
| [docs/api/QUICK_REFERENCE.md](api/QUICK_REFERENCE.md) | All HTTP routes |
| [AGENTS.md](../AGENTS.md) | Codebase patterns for developers |
| [DEPLOY_RENDER.md](DEPLOY_RENDER.md) | Render staging (non-AWS) |

---

## 25. Quick reference card

```
Product:     Athena VI Backend
API URL:     https://vi.api.lmsathena.com/api
Health:      GET https://vi.api.lmsathena.com/
DNS:         GoDaddy CNAME vi.api → ALB
TLS:         GoDaddy SSL imported to ACM on ALB (or free ACM cert)
Path:        ALB:443 → EC2 Nginx:80 → Node:9000
Deploy dir:  /opt/athena-vi
Start:       npm start (NODE_ENV=production)
Migrate:     npx prisma migrate deploy
OAuth:       https://vi.api.lmsathena.com/api/auth/google/callback
```
