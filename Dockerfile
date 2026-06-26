FROM node:20-bookworm-slim AS builder

WORKDIR /app

COPY package*.json ./

# Copy Prisma schema BEFORE npm ci
COPY prisma ./prisma

COPY prisma.config.ts ./

RUN npm ci

# Copy the remaining application files
COPY . .

RUN npx prisma generate

FROM node:20-bookworm-slim

WORKDIR /app

# Remotion / Chromium system libraries (see https://www.remotion.dev/docs/docker)
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
    ffmpeg \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app .

RUN npm prune --omit=dev \
  && npm install --no-save prisma@^7.2.0 \
  && npx remotion browser ensure

ENV NODE_ENV=production

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:9000/',(r)=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "src/server.js"]
