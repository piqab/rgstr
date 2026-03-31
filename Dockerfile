# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /rgstr .

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Use alpine (not scratch) so the health check can use wget.
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata wget

COPY --from=builder /rgstr /rgstr

# Storage volume mount point.
VOLUME ["/data"]

EXPOSE 5000

ENTRYPOINT ["/rgstr"]
