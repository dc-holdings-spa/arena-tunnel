.PHONY: help build build-all clean fmt lint test release tag verify

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -s -w -X main.version=$(VERSION)
GOFLAGS   := -trimpath
DIST       := dist
PLATFORMS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "}; /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## build server + client for the current host
	@mkdir -p $(DIST)
	cd server && CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ../$(DIST)/arena-tunnel-server ./...
	cd client && CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ../$(DIST)/arena-tunnel-client ./...
	@ls -lh $(DIST)/

build-all: ## cross-compile all 5 target platforms
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	    os=$${p%-*}; arch=$${p#*-}; ext=""; \
	    if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
	    echo ">>> $$os/$$arch"; \
	    (cd server && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ../$(DIST)/arena-tunnel-server-$$os-$$arch$$ext ./...); \
	    (cd client && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ../$(DIST)/arena-tunnel-client-$$os-$$arch$$ext ./...); \
	done
	@ls -lh $(DIST)/

fmt: ## gofmt -s -w
	gofmt -s -w server client

lint: ## golangci-lint (run via go run to avoid global install)
	cd server && go vet ./...
	cd client && go vet ./...

test: ## go test in both modules (no tests yet — placeholder)
	cd server && go test ./...
	cd client && go test ./...

verify: build-all ## smoke-verify each cross-compiled binary
	@for p in $(PLATFORMS); do \
	    os=$${p%-*}; arch=$${p#*-}; ext=""; \
	    if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
	    f=$(DIST)/arena-tunnel-client-$$os-$$arch$$ext; \
	    sz=$$(stat --format=%s "$$f" 2>/dev/null || stat -f%z "$$f" 2>/dev/null); \
	    if [ "$$sz" -lt 1000000 ]; then echo "ERROR: $$f suspiciously small ($$sz bytes)"; exit 1; fi; \
	    echo "OK $$f $$sz bytes"; \
	done

clean: ## remove build artifacts
	rm -rf $(DIST)

tag: ## create an annotated git tag from VERSION
	@if [ "$(VERSION)" = "dev" ]; then echo "set VERSION=vX.Y.Z"; exit 1; fi
	git tag -a $(VERSION) -m "Release $(VERSION)"
	@echo "Tag $(VERSION) created locally. Push with: make release"

release: ## push the tag → triggers CI release workflow
	@if [ "$(VERSION)" = "dev" ]; then echo "set VERSION=vX.Y.Z"; exit 1; fi
	git push origin $(VERSION)
	@echo "Tag $(VERSION) pushed. Watch CI for the release."
