FROM golang:latest AS build-base

WORKDIR /app

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && \
    go install github.com/air-verse/air@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest

FROM build-base AS dev

COPY . .

CMD ["air", "-c", ".air.toml"]
