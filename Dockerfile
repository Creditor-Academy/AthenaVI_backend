# Node 22: Puppeteer 25 (PDF / image export) requires Node >= 22.12.
FROM node:22-bookworm-slim AS builder

WORKDIR /app

# Puppeteer downloads its browser during `npm ci`. Keep it inside /app so the runtime stage
# (which only copies /app) has it, and only fetch chrome-headless-shell (exports run headless).
ENV PUPPETEER_CACHE_DIR=/app/.cache/puppeteer \
    PUPPETEER_CHROME_SKIP_DOWNLOAD=true

COPY package*.json ./

# Copy Prisma schema BEFORE npm ci
COPY prisma ./prisma
COPY prisma.config.ts ./

RUN npm ci

# Make sure the export browser is there even if the postinstall step was skipped.
RUN npx puppeteer browsers install chrome-headless-shell

# Copy the remaining application files
COPY . .

RUN npx prisma generate

FROM node:22-bookworm-slim

WORKDIR /app

ENV PUPPETEER_CACHE_DIR=/app/.cache/puppeteer \
    PUPPETEER_CHROME_SKIP_DOWNLOAD=true

# Install required system libraries (headless Chrome) and fonts for PDF / image export:
# Liberation (Arial / Times / Courier metrics), Noto (most scripts), CJK and colour emoji.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libdbus-1-3 \
    libatk1.0-0 \
    libgbm-dev \
    libasound2 \
    libxrandr2 \
    libxkbcommon-dev \
    libxfixes3 \
    libxcomposite1 \
    libxdamage1 \
    libatk-bridge2.0-0 \
    libpango-1.0-0 \
    libcairo2 \
    libcups2 \
    fontconfig \
    fonts-liberation \
    fonts-noto-core \
    fonts-noto-cjk \
    fonts-noto-color-emoji \
    ffmpeg \
 && fc-cache -f \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app .

# Remove development dependencies and keep Prisma CLI
RUN npm prune --omit=dev \
 && npm install --no-save prisma@^7.2.0

# Pre-install Chrome Headless Shell at build time (avoid runtime download on first render)
RUN node scripts/ensure-remotion-browser.js

# Fail the build if PDF / image export can't start its browser (instead of failing in production).
RUN node scripts/check-export-browser.js

ENV NODE_ENV=production

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
CMD node -e "require('http').get('http://127.0.0.1:9000/',(r)=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "src/server.js"]
