FROM node:20-bullseye-slim
WORKDIR /usr/src/app
# deps baked in at build time (NOT on the peer) -> no peer-side npm install
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm install --no-audit --no-fund typescript@5 @types/node && npx tsc && npm prune --omit=dev
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
EXPOSE 9999
CMD ["node", "build/server.js"]
