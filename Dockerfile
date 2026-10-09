# ── Build stage ───────────────────────────────────────────────────────────────
# Builder runs natively on the build host and cross-compiles for TARGETARCH,
# so multi-arch images build fast without QEMU emulating the Go compiler.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
# Without --build-arg VERSION (local builds) take it from the VERSION file.
RUN V="$VERSION"; if [ "$V" = dev ] && [ -f VERSION ]; then V="v$(cat VERSION)"; fi; \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=$V" -o /rgstr . && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /mkpasswd ./cmd/mkpasswd

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Use alpine (not scratch) so the health check can use wget.
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata wget

COPY --from=builder /rgstr /rgstr
# Password hash generator: docker run --rm --entrypoint /mkpasswd <image> alice secret
COPY --from=builder /mkpasswd /mkpasswd

ENV RGSTR_STORAGE=/data

# Storage volume mount point.
VOLUME ["/data"]

EXPOSE 5000

ENTRYPOINT ["/rgstr"]
