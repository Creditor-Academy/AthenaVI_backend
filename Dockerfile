# Stage 1 - Build
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./

RUN npm ci

COPY . .

RUN npx prisma generate

# Stage 2 - Production
FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app ./

ENV NODE_ENV=production

EXPOSE 9000

CMD ["npm", "start"]
