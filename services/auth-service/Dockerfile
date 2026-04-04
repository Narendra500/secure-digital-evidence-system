FROM golang:1.25.5-bookworm AS build-base

WORKDIR /app

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

FROM build-base AS dev

RUN go install github.com/air-verse/air@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest

COPY . .

CMD ["air", "-c", ".air.toml"]

# FROM build-base AS build-production
#
# RUN useradd -u 1001 nonroot
#
# COPY . .
#
# RUN go build \
#     -ldflags="-linkmode external -extldflags -static" \
#     -tags netgo \
#     -o auth-service-go ./cmd/main.go
#
# CMD ["./auth-service-go"]

