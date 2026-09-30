FROM node:22-alpine AS build
WORKDIR /app

COPY package*.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run lint
RUN npm run build
RUN node --check dist/server.cjs

FROM node:22-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=build --chown=appuser:appgroup /app/dist ./dist
COPY --from=build --chown=appuser:appgroup /app/config.json ./config.json
COPY --from=build --chown=appuser:appgroup /app/package.json ./package.json

USER appuser
EXPOSE 3000
CMD ["node", "dist/server.cjs"]
