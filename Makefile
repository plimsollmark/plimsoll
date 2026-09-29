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

# The docker/e2b/dockercloud/openshell suites need real infrastructure, so they are
# opt-in even inside `make audit`: set DOCKER=1 (local daemon, images from `make
# docker-images`), E2B=1 (E2B_API_KEY in the environment), DOCKERCLOUD=1
# (DOCKER_SBX_TOKEN, DOCKER_SBX_USERNAME, SANDBOX_DOCKERCLOUD_API_URL and
# SANDBOX_DOCKERCLOUD_IMAGE) and/or OPENSHELL=1 (an OpenShell gateway and the
# SANDBOX_OPENSHELL_* files) to include them. DOCKER=1, DOCKERCLOUD=1 and OPENSHELL=1
# are requests for proof: those suites run in required mode, where missing
# infrastructure or configuration fails the target instead of passing quietly. E2B and
# dockercloud spend money; no CI job runs them, nor openshell, which needs a gateway.
SECCOMP := $(CURDIR)/docker/seccomp.json

GATE_TOOLS := gate-tools.versions

.PHONY: audit build vet test race lint generate buf vuln docker-images docker-suite e2b-suite e2b-guard-live dockercloud-suite openshell-suite modproxy tools tools-check help

## audit: the full local gate (pinned-tool check, build, vet, race tests, lint, buf, govulncheck, plus the opt-in docker, e2b, dockercloud and openshell suites)
## audit prerequisites: node and cc on PATH, and a non-root user; runnerwire's
##   TestProjectRunnerAlwaysEmitsCompleteBoundedJSON and TestProjectRunnerReportsTruncationFlags
##   skip without node or as root (root defeats the runner guard they test)
audit: tools-check build vet race lint buf vuln
	@if [ "$(DOCKER)" = "1" ]; then $(MAKE) docker-suite; else echo "skip docker-suite (set DOCKER=1 with a local daemon + images from 'make docker-images')"; fi
	@if [ "$(E2B)" = "1" ]; then $(MAKE) e2b-suite; else echo "skip e2b-suite (set E2B=1 with E2B_API_KEY)"; fi
	@if [ "$(DOCKERCLOUD)" = "1" ]; then $(MAKE) dockercloud-suite; else echo "skip dockercloud-suite (set DOCKERCLOUD=1 with DOCKER_SBX_TOKEN, DOCKER_SBX_USERNAME, SANDBOX_DOCKERCLOUD_API_URL, SANDBOX_DOCKERCLOUD_IMAGE)"; fi
	@if [ "$(OPENSHELL)" = "1" ]; then $(MAKE) openshell-suite; else echo "skip openshell-suite (set OPENSHELL=1 with a gateway and SANDBOX_OPENSHELL_GATEWAY_URL, _CA_FILE, _CERT_FILE, _KEY_FILE, _IMAGE)"; fi
	@echo "audit: OK"

## build: compile every package
build:
	go build ./...

## vet: go vet
vet:
	go vet ./...

# The live E2B and dockercloud tests skip only when their credentials are absent, and
# `./...` selects them, so a key left in the shell (a secrets-manager wrapper, an
# earlier E2B=1 or DOCKERCLOUD=1 session) would make the ordinary gate create billable
# microVMs. These targets strip both credentials; only e2b-suite, e2b-guard-live and
# dockercloud-suite, the deliberate paid runs, see one, and each sees only its own.
NO_PAID_KEYS := env -u E2B_API_KEY -u DOCKER_SBX_TOKEN

## test: unit tests (includes fuzz corpora as regressions); never sees E2B_API_KEY or DOCKER_SBX_TOKEN
test:
	$(NO_PAID_KEYS) go test ./... -count=1

## race: unit tests under the race detector; never sees E2B_API_KEY or DOCKER_SBX_TOKEN
race:
	$(NO_PAID_KEYS) go test -race ./... -count=1

## lint: golangci-lint (must be on PATH)
lint:
	golangci-lint run ./...

## generate: regenerate gen/ from proto/ and from every vendored third_party/*/buf.gen.yaml
# The root template runs first: its `clean: true` empties gen/go, and each vendored
# template then writes its own subdirectory. Vendored protos are a separate buf
# workspace, so the root `buf lint` never lints upstream files we do not own.
generate:
	buf generate
	@for t in third_party/*/buf.gen.yaml; do \
		[ -f "$$t" ] || continue; \
		echo "buf generate $$(dirname "$$t")"; \
		buf generate "$$(dirname "$$t")" --template "$$t" || exit 1; \
	done

## buf: proto lint + verify generated code is in sync (fails if `make generate` would change or add anything)
buf: generate
	buf lint
	@git diff --exit-code --stat -- gen/ && [ -z "$$(git ls-files --others --exclude-standard -- gen/)" ] || { git ls-files --others --exclude-standard -- gen/ >&2; echo "generated code is stale or untracked: run 'make generate' and commit (or stage) gen/" >&2; exit 1; }

## vuln: govulncheck against the pinned toolchain
vuln:
	govulncheck ./...

## docker-images: pull the snippet image and build the project images the docker suite runs against
docker-images:
	docker pull node:22-alpine
	docker build -t plimsoll/sandbox:latest docker/
	docker build -t plimsoll/sandbox-python:latest -f docker/python.Dockerfile docker/
	docker build -t plimsoll/sandbox-sim:latest -f docker/sim.Dockerfile docker/
	docker build -t plimsoll/sandbox-wasm-cc:latest -f docker/wasm-cc.Dockerfile docker/

# Required mode, twice over. SANDBOX_TEST_REQUIRE_DOCKER=1 makes the test helpers
# fail instead of skip when the daemon or an image is missing; the scan afterwards
# fails the target on ANY skipped test in the selection, so a future bare t.Skip
# cannot turn requested coverage into a quiet pass either. -skip Live excludes the
# live E2B and dockercloud tests, which can match the selection by name and skip
# without a key; they belong to their own suites, and here a skip must mean docker.
# The dockercloud unit tests (a fake Connect server, and the exec wrapper under the
# toolchain image's busybox) match 'Docker' and run here. The status file, rather
# than a pipe, keeps the go test exit code under POSIX sh. OracleAttack is the oracle's
# anti-forgery set, which needs the sim image and matches none of the other names; the
# ./docker package holds the gVisor installer's offline-bundle check, which skips
# without zstd and so ran in no required suite before.
## docker-suite: the real docker/seccomp/broker/smoke tests, the oracle anti-forgery tests and the gVisor installer check; a missing daemon, image, tool or skipped test FAILS
docker-suite:
	@mkdir -p tmp
	@[ -w tmp ] || { echo "docker-suite: tmp/ is not writable (created by root during a sudo install?); chown it to your user" >&2; exit 1; }
	@{ SANDBOX_TEST_REQUIRE_DOCKER=1 SANDBOX_DOCKER_SECCOMP="$(SECCOMP)" \
	     $(NO_PAID_KEYS) go test ./sandbox ./docker -run 'Docker|RunProject|Broker|Smoke|OracleAttack|Installer' -skip 'Live' -count=1 -v; \
	   echo $$? > tmp/docker-suite.status; } 2>&1 | tee tmp/docker-suite.log
	@if grep -qE '^ *--- SKIP' tmp/docker-suite.log; then \
	   echo "docker-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/docker-suite.log >&2; exit 1; fi
	@exit "$$(cat tmp/docker-suite.status)"

## e2b-suite: the live E2B tests (needs E2B_API_KEY)
e2b-suite:
	env -u DOCKER_SBX_TOKEN go test ./sandbox -run 'E2B.*Live' -count=1 -v

# The live Docker Cloud Sandboxes suite. DOCKERCLOUD_LIVE_REQUIRED=1 makes missing
# configuration fail instead of skip, so a green run means the live service was
# exercised. The provider is written against Docker's published contract; this
# target is how it gets verified against the real service.
#
#   DOCKER_SBX_TOKEN              a Docker personal access token for automation
#   SANDBOX_DOCKERCLOUD_API_URL   the management endpoint (no default)
#   SANDBOX_DOCKERCLOUD_IMAGE     the toolchain image, pullable by the service
#
## dockercloud-suite: the live Docker Cloud Sandboxes tests (FAILS if not configured; spends)
dockercloud-suite:
	DOCKERCLOUD_LIVE_REQUIRED=1 env -u E2B_API_KEY go test ./sandbox -run 'DockerCloud.*Live' -count=1 -v

# The live OpenShell suite: the provider's tests and a daemon test against a real
# gateway (sandbox/openshell/live_test.go, cmd/plimsolld/openshell_live_test.go). It
# is free, a local gateway on local docker, but needs a gateway, so it is opt-in and
# a request for proof: OPENSHELL_LIVE=1 makes missing configuration fail, and a
# skipped test fails the target. -p 1 runs the packages one after the other, because
# the daemon test requires the gateway to hold no new plimsoll sandbox after the
# daemon exits, and the provider tests would add some if they ran at the same time.
#
#   SANDBOX_OPENSHELL_GATEWAY_URL   e.g. https://127.0.0.1:17670
#   SANDBOX_OPENSHELL_CA_FILE       the gateway CA (PEM)
#   SANDBOX_OPENSHELL_CERT_FILE     the client certificate (PEM)
#   SANDBOX_OPENSHELL_KEY_FILE      the client key (PEM)
#   SANDBOX_OPENSHELL_IMAGE         e.g. plimsoll/sandbox:latest
#
## openshell-suite: the live OpenShell provider and daemon tests; a missing gateway or a skipped test FAILS
openshell-suite:
	@mkdir -p tmp
	@{ OPENSHELL_LIVE=1 $(NO_PAID_KEYS) go test -p 1 ./sandbox/openshell ./cmd/plimsolld -run 'Live' -count=1 -v; \
	   echo $$? > tmp/openshell-suite.status; } 2>&1 | tee tmp/openshell-suite.log
	@if grep -qE '^ *--- SKIP' tmp/openshell-suite.log; then \
	   echo "openshell-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/openshell-suite.log >&2; exit 1; fi
	@exit "$$(cat tmp/openshell-suite.status)"

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
	E2B_GUARD_LIVE_REQUIRED=1 env -u DOCKER_SBX_TOKEN go test ./sandbox -run 'TestE2BGuardLive' -count=1 -v

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
	@$(MAKE) --no-print-directory tools-check

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
	bin="$$(go env GOBIN 2>/dev/null)"; gopath="$$(go env GOPATH 2>/dev/null)"; \
	[ -n "$$bin" ] || bin="$${gopath:+$$gopath/bin}"; [ -n "$$bin" ] || bin='$$(go env GOPATH)/bin'; \
	[ $$fail -eq 0 ] || { echo "gate tools do not match $(GATE_TOOLS). 'make tools' installs the pinned versions into $$bin, which must come first on PATH (export PATH=\"$$bin:\$$PATH\"); a copy found earlier on PATH wins" >&2; exit 1; }; \
	echo "gate tools match $(GATE_TOOLS)"

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
