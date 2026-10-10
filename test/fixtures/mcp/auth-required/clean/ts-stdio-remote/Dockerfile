FROM node:24-slim
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
CMD ["node", "dist/server.js"]
