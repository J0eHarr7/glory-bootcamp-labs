FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-fund --no-audit
COPY bot.js .
CMD ["node", "bot.js"]
