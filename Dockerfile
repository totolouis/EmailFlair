FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

RUN mkdir -p /app/data/quarantine

EXPOSE 2525 3000

CMD ["node", "src/index.js"]
