# Backend image (Node 24 LTS). Build context: this Backend folder.
FROM node:24-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
USER node
EXPOSE 8080
# HOST defaults to 0.0.0.0 in server.js so the published port works
CMD ["node", "server.js"]
