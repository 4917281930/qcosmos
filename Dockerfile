FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY bin ./bin
COPY src ./src
COPY docs ./docs
COPY proto ./proto
COPY LICENSE README.md SECURITY.md ./

ENTRYPOINT ["node", "bin/qcosmos.js"]
