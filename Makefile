BIN     := leakpatrol
PKG     := github.com/optimuslabs-io/leakpatrol/internal/buildinfo
MAIN    := ./cmd/$(BIN)
DIST    := dist

# Falls back to the version baked into internal/buildinfo when no git tag exists,
# so a build from a fresh clone is still stamped with a real number.
BASE_VERSION := 0.1.0
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo $(BASE_VERSION))
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# SOURCE_DATE_EPOCH makes the stamp reproducible; the fallback covers BSD and GNU date.
DATE    ?= $(shell date -u -d "@$${SOURCE_DATE_EPOCH:-$$(date +%s)}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$${SOURCE_DATE_EPOCH:-$$(date +%s)}" +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X $(PKG).Version=$(VERSION) \
  -X $(PKG).Commit=$(COMMIT) \
  -X $(PKG).Date=$(DATE)

# -trimpath        strips local filesystem paths: reproducible, and no path leakage
# -buildvcs=false  identical output whether the tree is dirty or clean
# CGO_ENABLED=0    static, no libc, cross-compiles cleanly, runs in alpine/scratch
GOFLAGS := -trimpath -buildvcs=false -mod=readonly
GOBUILD := CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)'

# windows/amd64 is deliberate: the advisory publishes a harvester build for the
# windows-rdp module, and Coder provisioners run on Windows.
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64

# Where `make demo` builds its synthetic compromised provisioner.
FIXTURE ?= /tmp/leakpatrol-fixture

.DEFAULT_GOAL := help

## help: list the available targets
.PHONY: help
help:
	@echo "leakpatrol $(VERSION)"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F': ' '{printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}' | sed 's/^  //'

# --- build -------------------------------------------------------------------

## build: build ./dist/leakpatrol for this machine
.PHONY: build
build:
	@mkdir -p $(DIST)
	$(GOBUILD) -o $(DIST)/$(BIN) $(MAIN)
	@echo "built $(DIST)/$(BIN)"

## install: install leakpatrol into $GOPATH/bin
.PHONY: install
install:
	CGO_ENABLED=0 go install $(GOFLAGS) -ldflags '$(LDFLAGS)' $(MAIN)

## run: build, then run (ARGS="all --json" to pass a command and flags)
.PHONY: run
run: build
	@$(DIST)/$(BIN) $(ARGS)

## release: cross-compile all five platforms into ./dist with SHA256SUMS
.PHONY: release
release: clean-dist verify-deps
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	  out="$(DIST)/$(BIN)_$(VERSION)_$${os}_$${arch}$${ext}"; \
	  echo "  -> $$out"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	    go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "$$out" $(MAIN) || exit 1; \
	done
	@cd $(DIST) && (shasum -a 256 $(BIN)_* 2>/dev/null || sha256sum $(BIN)_*) > SHA256SUMS
	@echo && cat $(DIST)/SHA256SUMS

# --- verification ------------------------------------------------------------

# This target IS the trust guarantee. Two properties of the LINKER, not promises
# in a README:
#   1. go.sum is empty: no third-party code is in the binary.
#   2. net/http and crypto/tls are reachable ONLY through internal/detect/deploy,
#      the one package allowed to talk to the operator's own Coder server. Every
#      other package -- the ones that run on a suspect provisioner host -- links no
#      network code at all.
## verify-deps: prove the binary is stdlib-only and that only the deploy tier links networking
.PHONY: verify-deps
verify-deps:
	@test ! -s go.sum || { echo "FAIL: go.sum is non-empty - a third-party dependency crept in"; exit 1; }
	@if go list -deps ./... | grep -v '^github.com/optimuslabs-io/leakpatrol' | grep -qE '^[a-z0-9.-]+\.[a-z]+/'; then \
	  echo "FAIL: a non-stdlib package is linked:"; \
	  go list -deps ./... | grep -v '^github.com/optimuslabs-io/leakpatrol' | grep -E '^[a-z0-9.-]+\.[a-z]+/'; \
	  exit 1; \
	fi
	@bad=0; for p in $$(go list ./internal/... | grep -v '/internal/detect/deploy$$'); do \
	  if go list -deps $$p | grep -qxE 'net/http|crypto/tls'; then \
	    echo "FAIL: $$p links network code (only internal/detect/deploy may):"; \
	    go list -deps $$p | grep -xE 'net/http|crypto/tls'; bad=1; \
	  fi; \
	done; test $$bad -eq 0
	@echo "OK: stdlib-only; networking linked only via internal/detect/deploy; CGO_ENABLED=0 (archive/tar's os/user is the pure-Go build)"

## test: run the test suite with the race detector
.PHONY: test
test:
	go test -race ./...

## fmt: gofmt the tree in place
.PHONY: fmt
fmt:
	gofmt -w .

## vet: run go vet
.PHONY: vet
vet:
	go vet ./...

## check: everything CI runs -- deps, fmt, vet, race tests, cross-compile smoke
.PHONY: check
check: verify-deps
	@gofmt -l . | (! grep .) || { echo "FAIL: run 'make fmt'"; exit 1; }
	go vet ./...
	go test -race ./...
	@echo "cross-compile smoke (catches //go:build mistakes before release, not during):"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./... & p1=$$!; \
	 GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./... & p2=$$!; \
	 GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./... & p3=$$!; \
	 wait $$p1 && wait $$p2 && wait $$p3
	@echo "OK: check passed"

# --- demo --------------------------------------------------------------------

# There is no real poisoned provisioner to test against, so the compromised case
# is constructed: a synthetic provisioner work dir with the telemetry block, a
# shell history with the exfil call, an egress log with the rogue IP, and an image
# tar carrying the tampered module. Scanned offline, so the deploy tier is skipped
# and the verdict is judged on the tiers that ran.
# Both demos ASSERT their verdict: a demo that cannot fail is a demo that proves
# nothing. Progress goes to stderr, so the report on stdout greps cleanly.
## demo: build a synthetic compromised provisioner and scan it (FAILS unless VERDICT: COMPROMISED)
.PHONY: demo
demo: build
	@./testdata/make_fixture.sh $(FIXTURE) >/dev/null
	@echo "synthetic compromised provisioner: $(FIXTURE)"
	@echo
	@$(DIST)/$(BIN) all --offline --no-animation --color never \
	    --home $(FIXTURE)/home \
	    --roots $(FIXTURE)/provisioner --roots $(FIXTURE)/home \
	    --logs $(FIXTURE)/logs/fw.log.gz --image $(FIXTURE)/image.tar \
	    > $(FIXTURE)/report.txt
	@cat $(FIXTURE)/report.txt
	@grep -q '^VERDICT: COMPROMISED' $(FIXTURE)/report.txt \
	  || { echo; echo "FAIL: the compromised fixture did not produce VERDICT: COMPROMISED"; exit 1; }
	@echo "OK: demo produced VERDICT: COMPROMISED"

## demo-clean: fs alone over an empty fixture (FAILS unless VERDICT: CLEAN)
.PHONY: demo-clean
demo-clean: build
	@rm -rf $(FIXTURE)-clean && mkdir -p $(FIXTURE)-clean/home $(FIXTURE)-clean/provisioner
	@$(DIST)/$(BIN) fs --no-animation --color never --home $(FIXTURE)-clean/home \
	    $(FIXTURE)-clean/provisioner $(FIXTURE)-clean/home \
	    > $(FIXTURE)-clean/report.txt
	@cat $(FIXTURE)-clean/report.txt
	@grep -q '^VERDICT: CLEAN' $(FIXTURE)-clean/report.txt \
	  || { echo; echo "FAIL: an empty fixture did not produce VERDICT: CLEAN"; exit 1; }
	@echo "OK: demo-clean produced VERDICT: CLEAN"

# --- lab: live end-to-end against a real, contained, hijacked coderd ---------
# See lab/README.md. `lab-up` needs the internet ONCE (to mirror Terraform
# providers); everything after runs on an egress-less internal Docker network.

## lab-up: stand up the hijacked-registry lab and assert leakpatrol reaches COMPROMISED
.PHONY: lab-up
lab-up:
	@bash lab/run.sh

## lab-down: tear the lab down and delete its generated secrets (TLS, mirror, out)
.PHONY: lab-down
lab-down:
	@cd lab && docker compose down -v --remove-orphans 2>/dev/null || true
	@rm -rf lab/tls lab/out
	@echo "lab down; generated TLS and reports removed (lab/mirror kept -- rm -rf lab/mirror to drop the provider cache)"

# --- cleanup -----------------------------------------------------------------

.PHONY: clean-dist
clean-dist:
	@rm -f $(DIST)/$(BIN)_* $(DIST)/SHA256SUMS

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(DIST)

## distclean: remove build output, the Go caches, and the demo fixtures
.PHONY: distclean
distclean: clean
	rm -rf $(FIXTURE) $(FIXTURE)-clean
	go clean -cache -testcache
