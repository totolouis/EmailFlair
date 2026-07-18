FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist
COPY src/dashboard ./dist/dashboard
RUN mkdir -p /app/data/quarantine /app/data/acme

EXPOSE 2525 3000

CMD ["node", "dist/index.js"]
