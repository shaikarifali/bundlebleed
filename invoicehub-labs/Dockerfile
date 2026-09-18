FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

ENV PORT=4000
EXPOSE 4000

CMD ["node", "server.js"]
