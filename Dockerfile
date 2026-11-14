FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY public ./public
COPY sql ./sql
COPY assets ./assets
COPY branding ./branding
EXPOSE 10000
CMD ["node", "server.js"]
