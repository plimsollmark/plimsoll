# plimsoll — the gate. `make audit` is the single reproducible check that runs
# everything a hostile-code TCB should pass before a commit, and CI
# (.github/workflows/audit.yml, gvisor.yml) runs these same targets on a hosted
# runner so what a check claims and what this file does cannot drift. Each target
# is runnable on its own.
#
# "Reproducible" is a claim this file has to earn. buf, golangci-lint and
# govulncheck live outside the module, so they are pinned in gate-tools.versions,
# installed by `make tools`, and checked by `make tools-check` before the gate runs.
# Without that check, a lint clean run means "clean under whichever golangci-lint
# happened to be on PATH", which is not a gate.

# The docker/e2b suites need real infrastructure, so they are opt-in even inside
# `make audit`: set DOCKER=1 (local daemon, images from `make docker-images`) and/or
# E2B=1 (E2B_API_KEY in the environment) to include them. DOCKER=1 is a request for
# proof: docker-suite runs in required mode, where a missing daemon, a missing image
# or any skipped test fails the target instead of passing quietly.
SECCOMP := $(CURDIR)/docker/seccomp.json

GATE_TOOLS := gate-tools.versions

.PHONY: audit build vet test race lint buf vuln docker-images docker-suite e2b-suite e2b-guard-live modproxy tools tools-check help

## audit: the full local gate — pinned-tool check, build, vet, race tests, lint, buf, govulncheck (+ opt-in docker/e2b)
audit: tools-check build vet race lint buf vuln
	@if [ "$(DOCKER)" = "1" ]; then $(MAKE) docker-suite; else echo "skip docker-suite (set DOCKER=1 with a local daemon + images from 'make docker-images')"; fi
	@if [ "$(E2B)" = "1" ]; then $(MAKE) e2b-suite; else echo "skip e2b-suite (set E2B=1 with E2B_API_KEY)"; fi
	@echo "audit: OK"

## build: compile every package
build:
	go build ./...

## vet: go vet
vet:
	go vet ./...

## test: unit tests (includes fuzz corpora as regressions)
test:
	go test ./... -count=1

## race: unit tests under the race detector
race:
	go test -race ./... -count=1

## lint: golangci-lint (must be on PATH)
lint:
	golangci-lint run ./...

## buf: proto lint + verify generated code is in sync (fails if `buf generate` would change anything)
buf:
	buf lint
	buf generate
	git diff --exit-code -- gen/ || (echo "generated code is stale: run 'buf generate' and commit" >&2; exit 1)

## vuln: govulncheck against the pinned toolchain
vuln:
	govulncheck ./...

## docker-images: pull the snippet image and build the project images the docker suite runs against
docker-images:
	docker pull node:22-alpine
	docker build -t plimsoll/sandbox:latest docker/
	docker build -t plimsoll/sandbox-python:latest -f docker/python.Dockerfile docker/
	docker build -t plimsoll/sandbox-sim:latest -f docker/sim.Dockerfile docker/

# Required mode, twice over. SANDBOX_TEST_REQUIRE_DOCKER=1 makes the test helpers
# fail instead of skip when the daemon or an image is missing; the scan afterwards
# fails the target on ANY skipped test in the selection, so a future bare t.Skip
# cannot turn requested coverage into a quiet pass either. -skip Live excludes the
# live E2B tests, which match the selection by name and skip without a key; they
# belong to e2b-suite, and here a skip must mean docker. The status file, rather
# than a pipe, keeps the go test exit code under POSIX sh.
## docker-suite: the real docker/seccomp/broker/smoke tests; a missing daemon, image or skipped test FAILS
docker-suite:
	@mkdir -p tmp
	@[ -w tmp ] || { echo "docker-suite: tmp/ is not writable (created by root during a sudo install?); chown it to your user" >&2; exit 1; }
	@{ SANDBOX_TEST_REQUIRE_DOCKER=1 SANDBOX_DOCKER_SECCOMP="$(SECCOMP)" \
	     go test ./sandbox -run 'Docker|RunProject|Broker|Smoke' -skip 'Live' -count=1 -v; \
	   echo $$? > tmp/docker-suite.status; } 2>&1 | tee tmp/docker-suite.log
	@if grep -qE '^ *--- SKIP' tmp/docker-suite.log; then \
	   echo "docker-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/docker-suite.log >&2; exit 1; fi
	@exit "$$(cat tmp/docker-suite.status)"

## e2b-suite: the live E2B tests (needs E2B_API_KEY)
e2b-suite:
	go test ./sandbox -run 'Live' -count=1 -v

# The guarded-egress path is the one claim `make audit E2B=1` cannot make: its live
# test skips unless three deployment-specific variables are set, and a skip inside a
# green suite reads exactly like a pass. This target is the deliberate run, and it
# fails rather than skips when its configuration is missing.
#
#   E2B_API_KEY                 the account key
#   E2B_GUARD_URL               the externally reachable HTTPS guard route
#   E2B_LIVE_GRANT_BASE_URL     origin of a real HTTPS API to prove against
#   E2B_LIVE_GUARD_LISTEN       optional: local addr that self-serves the handler
#
## e2b-guard-live: prove the guarded E2B egress path (FAILS if it is not configured)
e2b-guard-live:
	E2B_GUARD_LIVE_REQUIRED=1 go test ./sandbox -run 'TestE2BGuardLive' -count=1 -v

# The website targets that used to sit here drove the commercial site's local stack
# through scripts/ , which is private and does not ship. In a public clone they were
# advertised by `make help` and failed with "No such file or directory". The scripts
# are documented directly in the private docs/website-runbook.md; a Makefile is the
# wrong place for a target only half the tree can run.

# Before public tags exist, consumers can resolve tagged versions from a local
# file-based GOPROXY that this target publishes from the tag itself, not the
# working tree. Siblings use go.work for day-to-day development; the proxy also
# supports `go mod tidy`, `go mod vendor`, and Docker builds without a sibling
# checkout or public repository.
MODPATH := github.com/plimsollmark/plimsoll
GOPROXY_DIR ?= $(HOME)/projects/.goproxy
MODVERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null)

## modproxy: publish the latest tag into the local file-based Go module proxy
modproxy:
	@test -n "$(MODVERSION)" || { echo "modproxy: no tag found (tag first, e.g. git tag v0.1.0)" >&2; exit 1; }
	@mkdir -p "$(GOPROXY_DIR)/$(MODPATH)/@v"
	git archive --format=zip --prefix="$(MODPATH)@$(MODVERSION)/" "$(MODVERSION)" \
		-o "$(GOPROXY_DIR)/$(MODPATH)/@v/$(MODVERSION).zip"
	git show "$(MODVERSION):go.mod" > "$(GOPROXY_DIR)/$(MODPATH)/@v/$(MODVERSION).mod"
	printf '{"Version":"%s"}\n' "$(MODVERSION)" > "$(GOPROXY_DIR)/$(MODPATH)/@v/$(MODVERSION).info"
	@cd "$(GOPROXY_DIR)/$(MODPATH)/@v" && ls *.info | sed 's/\.info$$//' > list
	@echo "modproxy: published $(MODPATH)@$(MODVERSION) to $(GOPROXY_DIR)"

## tools: install the exact out-of-module gate tools named in gate-tools.versions
tools:
	go install github.com/bufbuild/buf/cmd/buf@v$$(sed -n 's/^buf=//p' $(GATE_TOOLS))
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$$(sed -n 's/^golangci-lint=//p' $(GATE_TOOLS))
	go install golang.org/x/vuln/cmd/govulncheck@$$(sed -n 's/^govulncheck=//p' $(GATE_TOOLS))
	@echo "codegen plugins are pinned separately, by go.mod tool directives"

## tools-check: fail unless the installed gate tools are the pinned versions
tools-check:
	@fail=0; \
	want="$$(sed -n 's/^buf=//p' $(GATE_TOOLS))"; \
	got="$$(buf --version 2>/dev/null)"; \
	[ "$$got" = "$$want" ] || { echo "buf: have '$$got', pinned $$want" >&2; fail=1; }; \
	want="$$(sed -n 's/^golangci-lint=//p' $(GATE_TOOLS))"; \
	got="$$(golangci-lint --version 2>/dev/null | sed -n 's/.*has version \([^ ]*\).*/\1/p')"; \
	[ "$$got" = "$$want" ] || { echo "golangci-lint: have '$$got', pinned $$want" >&2; fail=1; }; \
	want="$$(sed -n 's/^govulncheck=//p' $(GATE_TOOLS))"; \
	got="$$(govulncheck -version 2>/dev/null | sed -n 's/^Scanner: govulncheck@//p')"; \
	[ "$$got" = "$$want" ] || { echo "govulncheck: have '$$got', pinned $$want" >&2; fail=1; }; \
	[ $$fail -eq 0 ] || { echo "gate tools do not match $(GATE_TOOLS); run 'make tools'" >&2; exit 1; }; \
	echo "gate tools match $(GATE_TOOLS)"

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
