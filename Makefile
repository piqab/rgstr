BINARY  = rgstr
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -trimpath -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: all build build-linux build-windows run run-auth docker docker-push \
        tidy test passwd clean

all: build

## Download dependencies and update go.sum
tidy:
	go mod tidy

## Build for the current OS/arch
build: tidy
	go build $(LDFLAGS) -o $(BINARY)$(if $(filter windows,$(shell go env GOOS)),.exe,) .

## Cross-compile for Linux amd64 (from any OS)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

## Cross-compile for Linux arm64 (e.g. Raspberry Pi / AWS Graviton)
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	go build $(LDFLAGS) -o $(BINARY)-linux-arm64 .

## Cross-compile for Windows amd64
build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
	go build $(LDFLAGS) -o $(BINARY)-windows-amd64.exe .

## Build all platforms at once
release: build-linux build-linux-arm64 build-windows

## Run locally with no auth
run: build
	RGSTR_STORAGE=./data ./$(BINARY)$(if $(filter windows,$(shell go env GOOS)),.exe,)

## Run locally with auth enabled
## Usage: make run-auth USERS="alice:$$2a$$10$$..."
run-auth: build
	RGSTR_AUTH_ENABLED=true \
	RGSTR_AUTH_SECRET=supersecret \
	RGSTR_USERS="$(USERS)" \
	RGSTR_STORAGE=./data \
	./$(BINARY)$(if $(filter windows,$(shell go env GOOS)),.exe,)

## Build Docker image
docker:
	docker build -t rgstr:$(VERSION) -t rgstr:latest .

## Push Docker image  (set REGISTRY env var, e.g. ghcr.io/yourname)
docker-push: docker
	docker tag rgstr:$(VERSION) $(REGISTRY)/rgstr:$(VERSION)
	docker tag rgstr:latest     $(REGISTRY)/rgstr:latest
	docker push $(REGISTRY)/rgstr:$(VERSION)
	docker push $(REGISTRY)/rgstr:latest

## Generate a bcrypt password hash for RGSTR_USERS
## Usage: make passwd USER=alice PASS=secret
passwd:
	go run ./cmd/mkpasswd $(USER) $(PASS)

## Run all tests (unit + integration)
test: tidy
	go test -v -race -count=1 ./...

## Run tests with coverage report
cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-linux-* $(BINARY)-windows-*
	rm -f coverage.out coverage.html
	rm -rf data/
