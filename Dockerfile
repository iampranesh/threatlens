# Multi-stage Dockerfile for ThreatLens Platform
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json tsconfig*.json vite.config.ts ./
RUN npm ci

COPY . .
RUN npm run build

# Production Runner
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/data ./data
COPY --from=builder /app/results ./results
COPY --from=builder /app/server.ts ./
COPY --from=builder /app/src/server ./src/server

# Install python3 for background evaluation scripts
RUN apk add --no-cache python3 py3-pip && npm ci --omit=dev

EXPOSE 3000

CMD ["node", "--loader", "tsx", "server.ts"]
