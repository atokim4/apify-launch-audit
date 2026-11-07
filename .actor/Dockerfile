# Build stage: compile TypeScript
FROM apify/actor-node:22 AS builder
COPY --chown=myuser package*.json ./
RUN npm ci --include=dev --audit=false --fund=false
COPY --chown=myuser . ./
RUN npm run build

# Runtime stage: production dependencies + compiled JS only
FROM apify/actor-node:22
COPY --chown=myuser package*.json ./
RUN npm ci --omit=dev --omit=optional --audit=false --fund=false \
    && echo "Node.js $(node --version), npm $(npm --version)"
COPY --from=builder --chown=myuser /usr/src/app/dist ./dist
COPY --chown=myuser .actor ./.actor
CMD ["npm", "run", "start", "--silent"]
