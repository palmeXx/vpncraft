# vpncraft – Warcraft III LAN sniffer & relay for VPNs

APP       := vpncraft
PKG       := github.com/palmeXx/vpncraft
MAIN      := ./cmd/$(APP)
BIN_DIR   := bin
DIST_DIR  := dist

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
# Pinned so local runs and CI use the same scanner.
GOVULNCHECK_VERSION ?= v1.9.0
GOWINRES_VERSION    ?= v0.3.3

# Windows icon: go-winres turns the logo into resource objects that the Go
# linker picks up automatically for windows/<arch> builds of the main package.
WINRES_ICON  := docs/vpn_craft_logo_v3.png
WINRES_DIR   := cmd/$(APP)
WINRES_AMD64 := $(WINRES_DIR)/rsrc_windows_amd64.syso
WINRES_ARM64 := $(WINRES_DIR)/rsrc_windows_arm64.syso
GOWINRES     := $(BIN_DIR)/go-winres-$(GOWINRES_VERSION)

# Build metadata, injected via -ldflags -X and printed at startup.
# The version comes from version.json, the single source of truth for releases.
VERSION ?= $(shell sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' version.json)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)

# Release targets (os/arch). All builds are pure Go (CGO_ENABLED=0).
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64
LINT_OS   := linux darwin windows

export CGO_ENABLED := 0

# build_platform(os, arch): cross-compile into $(DIST_DIR)/$(APP)_<os>_<arch>[.exe]
define build_platform
	@echo "[*] Building $(1)/$(2)"
	@GOOS=$(1) GOARCH=$(2) $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST_DIR)/$(APP)_$(1)_$(2)$(if $(filter windows,$(1)),.exe) $(MAIN)

endef

.DEFAULT_GOAL := help
.PHONY: help all check fmt fmt-check vet lint vuln test test-race cover test-integration \
	test-integration-privileged fuzz build build-all build-linux build-windows build-darwin \
	checksums manifest release-check release-notes winres run tidy clean

help: ## Show this help
	@echo "$(APP) $(VERSION) (commit $(COMMIT))"
	@echo
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: check build-all ## Lint, test and build all release binaries

check: fmt-check vet lint test ## Run all static checks and unit tests

## ---- Code quality ----------------------------------------------------------

fmt: ## Format code (gofmt + goimports via golangci-lint)
	@$(GOLANGCI_LINT) fmt ./...

fmt-check: ## Fail if code is not formatted
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "[!] Unformatted files:"; echo "$$out"; exit 1; fi

vet: ## Run go vet (incl. tests) for every release platform; catches missing per-OS implementations
	@for p in $(PLATFORMS); do echo "[*] go vet ($$p)"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} $(GO) vet -tags integration ./... || exit 1; done

lint: ## Run golangci-lint for every target OS (build-tagged files included)
	@command -v $(GOLANGCI_LINT) >/dev/null || { echo "[!] golangci-lint not found: https://golangci-lint.run/welcome/install/"; exit 1; }
	@for os in $(LINT_OS); do echo "[*] golangci-lint ($$os)"; GOOS=$$os $(GOLANGCI_LINT) run ./... || exit 1; done

# Installed for the host into bin/ (not via `go run`, which would honour GOOS).
$(BIN_DIR)/govulncheck-$(GOVULNCHECK_VERSION):
	@mkdir -p $(BIN_DIR)
	@GOBIN=$(abspath $(BIN_DIR)) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@mv $(BIN_DIR)/govulncheck$(shell $(GO) env GOEXE) $@

# Installed for the host into bin/, version pinned like govulncheck.
$(GOWINRES):
	@mkdir -p $(BIN_DIR)
	@GOBIN=$(abspath $(BIN_DIR)) $(GO) install github.com/tc-hib/go-winres@$(GOWINRES_VERSION)
	@mv $(BIN_DIR)/go-winres$(shell $(GO) env GOEXE) $@

# One run writes both architectures; regenerated when the logo changes.
$(WINRES_AMD64): $(WINRES_ICON) | $(GOWINRES)
	@echo "[*] Generating Windows icon resources from $(WINRES_ICON)"
	@$(GOWINRES) simply --arch amd64,arm64 --manifest none --icon $(WINRES_ICON) --out $(WINRES_DIR)/rsrc
$(WINRES_ARM64): $(WINRES_AMD64)

winres: $(WINRES_AMD64) $(WINRES_ARM64) ## Generate Windows icon resources (.syso) from the logo

vuln: $(BIN_DIR)/govulncheck-$(GOVULNCHECK_VERSION) ## Check dependencies and code for known vulnerabilities (govulncheck, every target OS)
	@for os in $(LINT_OS); do echo "[*] govulncheck ($$os)"; \
		GOOS=$$os $(BIN_DIR)/govulncheck-$(GOVULNCHECK_VERSION) ./... || exit 1; done

## ---- Tests -----------------------------------------------------------------

test: ## Run unit tests
	@$(GO) test -count=1 ./...

test-race: ## Run unit tests with the race detector (needs cgo)
	@CGO_ENABLED=1 $(GO) test -race -count=1 ./...

cover: ## Run unit tests with coverage report (coverage.html)
	@$(GO) test -count=1 -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -1
	@$(GO) tool cover -html=coverage.out -o coverage.html

test-integration: ## Run integration tests (raw-socket tests skip without root)
	@$(GO) test -count=1 -tags integration -v ./test/integration/...

test-integration-privileged: ## Run raw-socket integration tests and privileged capture unit tests via sudo
	@mkdir -p $(BIN_DIR)
	@$(GO) test -c -tags integration -o $(BIN_DIR)/integration.test ./test/integration
	@$(GO) test -c -o $(BIN_DIR)/capture.test ./internal/capture
	@$(GO) test -c -o $(BIN_DIR)/relay.test ./internal/relay
	@cd test/integration && sudo ../../$(BIN_DIR)/integration.test -test.v -test.count=1 \
		-test.run 'TestCaptureLoopback|TestRawForwarderSourcePort|TestSweepLoopback'
	@cd internal/capture && sudo ../../$(BIN_DIR)/capture.test -test.v -test.count=1 -test.run 'TestOpen'
	@cd internal/relay && sudo ../../$(BIN_DIR)/relay.test -test.v -test.count=1 -test.run 'TestOpenRawConn'

FUZZTIME ?= 30s
fuzz: ## Fuzz packet parsers (FUZZTIME=30s)
	@$(GO) test -run '^$$' -fuzz FuzzDescribe -fuzztime $(FUZZTIME) ./internal/wc3
	@$(GO) test -run '^$$' -fuzz FuzzDecodeIPv4UDP -fuzztime $(FUZZTIME) ./internal/capture

## ---- Build -----------------------------------------------------------------

build: ## Build for the host platform into bin/
	@mkdir -p $(BIN_DIR)
	@$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP)$(shell $(GO) env GOEXE) $(MAIN)
	@echo "[+] $(BIN_DIR)/$(APP)$(shell $(GO) env GOEXE) (commit $(COMMIT))"

build-all: $(foreach p,$(PLATFORMS),build-$(subst /,-,$(p))) ## Build all release binaries into dist/
	@echo "[+] Binaries in $(DIST_DIR)/"

build-linux: build-linux-amd64 build-linux-arm64 ## Build Linux amd64 + arm64
build-windows: build-windows-amd64 build-windows-arm64 ## Build Windows amd64 + arm64 (with icon)
build-darwin: build-darwin-amd64 build-darwin-arm64 ## Build macOS amd64 + arm64

# Windows binaries embed the icon; the recipe comes from the build-% pattern rule.
build-windows-amd64: $(WINRES_AMD64)
build-windows-arm64: $(WINRES_ARM64)

build-%:
	@mkdir -p $(DIST_DIR)
	$(call build_platform,$(word 1,$(subst -, ,$*)),$(word 2,$(subst -, ,$*)))

checksums: build-all ## Write SHA-256 checksums for dist/
	@cd $(DIST_DIR) && shasum -a 256 $(APP)_* > SHA256SUMS && cat SHA256SUMS

manifest: checksums ## Release assets: binaries, SHA256SUMS and manifest.json in dist/
	@$(RELEASE) manifest --dist $(DIST_DIR) --commit $(COMMIT) --date $(DATE) --output $(DIST_DIR)/manifest.json
	@echo "[+] $(DIST_DIR)/manifest.json ($(VERSION))"

## ---- Release -------------------------------------------------------------

RELEASE := $(GO) run ./tools/release
# Same check as on pull requests; BASE=main compares with the local branch.
BASE ?= origin/main

release-check: ## Check version.json and CHANGELOG.md as next release (BASE=origin/main)
	@$(RELEASE) check --base $(BASE)

release-notes: ## Preview the release notes (REF=v0.1.0 for an existing release)
	@$(RELEASE) notes $(if $(REF),--ref $(REF))

run: build ## Build and run (ARGS="-m relay"); raw sockets need sudo
	@$(BIN_DIR)/$(APP) $(ARGS)

## ---- Housekeeping ----------------------------------------------------------

tidy: ## go mod tidy
	@$(GO) mod tidy

# Leftovers of the former Python/PyInstaller build (branch first-try-with-python).
LEGACY_ARTIFACTS := build $(APP).spec __pycache__

clean: ## Remove build artifacts, incl. legacy PyInstaller build/ and dist/
	@rm -rf $(BIN_DIR) $(DIST_DIR) $(LEGACY_ARTIFACTS) coverage.out coverage.html $(WINRES_DIR)/*.syso
	@echo "[+] Cleaned $(BIN_DIR)/ $(DIST_DIR)/ $(LEGACY_ARTIFACTS) coverage.* $(WINRES_DIR)/*.syso"
