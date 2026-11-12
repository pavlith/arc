FROM node:26-alpine AS builder
WORKDIR /app
ARG SECURITY_REFRESH=initial
RUN npm install --global npm@11.20.0
COPY client/package.json client/package-lock.json ./client/
COPY client/web/package.json ./client/web/package.json
COPY client/ts/package.json ./client/ts/package.json
WORKDIR /app/client
RUN npm ci
WORKDIR /app
COPY client/web ./client/web
COPY client/ts ./client/ts
COPY services/task/api/v1/contract ./services/task/api/v1/contract
COPY services/notify/api/v1/contract ./services/notify/api/v1/contract
COPY services/files/api/v1/contract ./services/files/api/v1/contract
COPY services/pages/api/v1/contract ./services/pages/api/v1/contract
ARG PUBLIC_DEMO_MODE=false
ARG PUBLIC_DEMO_USERS
ENV PUBLIC_DEMO_MODE=$PUBLIC_DEMO_MODE
ENV PUBLIC_DEMO_USERS=$PUBLIC_DEMO_USERS
ARG NODE_OPTIONS=--max-old-space-size=8192
RUN npm --prefix client run check --workspace @arc/client
RUN npm --prefix client run build --workspace ui

FROM golang:1.26.10-alpine AS caddy-builder
ARG SECURITY_REFRESH=initial
RUN apk add --no-cache git
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.6
RUN xcaddy build v2.11.4 \
    --with google.golang.org/grpc@v1.83.2 \
    --replace github.com/klauspost/compress=github.com/klauspost/compress@v1.18.7 \
    --replace golang.org/x/text=golang.org/x/text@v0.43.0 \
    --replace golang.org/x/net=golang.org/x/net@v0.62.0 \
    --replace golang.org/x/crypto=golang.org/x/crypto@v0.58.0 \
    --replace github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@v4.1.6

FROM alpine:3.23
ARG SECURITY_REFRESH=initial
RUN apk update && apk upgrade --no-cache
COPY --from=caddy-builder /go/caddy /usr/bin/caddy
COPY --from=builder /app/client/web/build /srv
COPY client/web/Caddyfile /etc/caddy/Caddyfile
EXPOSE 3000
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
