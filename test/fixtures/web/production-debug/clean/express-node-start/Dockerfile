FROM node:20 AS dev
CMD ["npm", "run", "dev"]

FROM node:20-alpine
WORKDIR /app
COPY . .
CMD ["npm", "start"]
