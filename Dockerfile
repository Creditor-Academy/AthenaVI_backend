FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./

# Copy Prisma schema BEFORE npm ci
COPY prisma ./prisma

COPY prisma.config.ts ./

RUN npm ci

# Copy the remaining application files
COPY . .

RUN npx prisma generate

FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app .

ENV NODE_ENV=production

EXPOSE 9000

CMD ["npm", "start"]
