FROM oven/bun:1.2.21-alpine

WORKDIR /app

COPY package.json tsconfig.json ./

RUN bun install --production

COPY . .

EXPOSE 3000

CMD ["bun" "start"]