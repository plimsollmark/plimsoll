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
# (DOCKER_SBX_TOKEN, DOCKER_SBX_USERNAME, SANDBOX_DOCKERCLOUD_IMAGE or _STORE_IMAGE, and unless
# SANDBOX_DOCKERCLOUD_API=rest SANDBOX_DOCKERCLOUD_API_URL) and/or OPENSHELL=1 (an OpenShell gateway and the
# SANDBOX_OPENSHELL_* files) and/or AGENTSANDBOX=1 (an agent-sandbox cluster and the
# SANDBOX_AGENTSANDBOX_* settings) to include them. DOCKER=1, DOCKERCLOUD=1, OPENSHELL=1 and AGENTSANDBOX=1
# are requests for proof: those suites run in required mode, where missing
# infrastructure or configuration fails the target instead of passing quietly. E2B and
# dockercloud spend money; no CI job runs them, nor openshell, which needs a gateway, nor
# agentsandbox, which needs a cluster.
SECCOMP := $(CURDIR)/docker/seccomp.json

# The docker suite's tests in ./sandbox and ./docker, by top-level name. Only
# docker-suite runs a docker container: the race and test passes run with -short, which
# the docker test helpers (requireDocker, sessionDocker) read as "skip", so a box with
# docker and the images no longer runs the docker tests a second time, outside required
# mode, in every plain `make audit` (418 s of a 7-minute gate on 2026-10-04). Tests in
# this selection that need no docker run in both passes.
DOCKER_TESTS := Docker|RunProject|Broker|Smoke|OracleAttack|Installer

GATE_TOOLS := gate-tools.versions

.PHONY: nemotron-verifier audit build vet modules test race lint generate buf vuln docker-images docker-suite py-frameworks py-frameworks-lock clients-suite mcp-suite e2b-suite e2b-guard-live e2b-session-live dockercloud-guard-live dockercloud-suite openshell-suite agentsandbox-suite modproxy tools tools-check help

## audit: the full local gate (pinned-tool check, build, vet, race tests, lint, buf, govulncheck, plus the opt-in docker, e2b, dockercloud and openshell suites)
## audit prerequisites: node and cc on PATH, and a non-root user; runnerwire's
##   TestProjectRunnerAlwaysEmitsCompleteBoundedJSON and TestProjectRunnerReportsTruncationFlags
##   skip without node or as root (root defeats the runner guard they test)
audit: tools-check build vet modules race lint buf vuln
	@if [ "$(DOCKER)" = "1" ]; then $(MAKE) docker-suite; else echo "skip docker-suite (set DOCKER=1 with a local daemon + images from 'make docker-images')"; fi
	@if [ "$(E2B)" = "1" ]; then $(MAKE) e2b-suite; else echo "skip e2b-suite (set E2B=1 with E2B_API_KEY)"; fi
	@if [ "$(DOCKERCLOUD)" = "1" ]; then $(MAKE) dockercloud-suite; else echo "skip dockercloud-suite (set DOCKERCLOUD=1 with DOCKER_SBX_TOKEN, DOCKER_SBX_USERNAME, SANDBOX_DOCKERCLOUD_IMAGE or _STORE_IMAGE, and unless SANDBOX_DOCKERCLOUD_API=rest SANDBOX_DOCKERCLOUD_API_URL)"; fi
	@if [ "$(OPENSHELL)" = "1" ]; then $(MAKE) openshell-suite; else echo "skip openshell-suite (set OPENSHELL=1 with a gateway and SANDBOX_OPENSHELL_GATEWAY_URL, _CA_FILE, _CERT_FILE, _KEY_FILE, _IMAGE)"; fi
	@if [ "$(AGENTSANDBOX)" = "1" ]; then $(MAKE) agentsandbox-suite; else echo "skip agentsandbox-suite (set AGENTSANDBOX=1 with a cluster, AGENTSANDBOX_TIER and the SANDBOX_AGENTSANDBOX_* settings)"; fi
	@echo "audit: OK"

# A working copy may add steps of its own to the gate: local.mk, if present, appends
# them to EXTRA_AUDIT. It is optional and never part of the published tree. Included
# after the rule above, so a bare `make` still means audit.
-include local.mk
audit: $(EXTRA_AUDIT)

## build: compile every package, and the browser verifier for WebAssembly (nemotron-verifier builds the shipped file)
build:
	go build ./...
	GOOS=js GOARCH=wasm go build -o /dev/null ./examples/nemotron-agent/verifier

## nemotron-verifier: build the browser verifier (plimsoll's bundle verification compiled to WebAssembly) into docs/examples/nemotron-agent, gzip-compressed, with the Go toolchain's wasm_exec.js beside it
nemotron-verifier:
	@mkdir -p docs/examples/nemotron-agent
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o tmp/verify.wasm ./examples/nemotron-agent/verifier
	gzip -9 -n -c tmp/verify.wasm > docs/examples/nemotron-agent/verify.wasm.gz
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" docs/examples/nemotron-agent/wasm_exec.js
	@rm -f tmp/verify.wasm
	@ls -la docs/examples/nemotron-agent/verify.wasm.gz

## vet: go vet
vet:
	go vet ./...

# The nested modules replace the root module with ../, so a breaking change to the root
# (routine under the no-backward-compatibility rule) breaks them with no error from
# build or vet above. Their own suites test them; this builds and vets them on every gate.
# A module whose go.mod asks for a newer Go than this one (examples/capsule) is built here
# only where go may switch to that toolchain (GOTOOLCHAIN auto or ending +auto): under
# GOTOOLCHAIN=local, which actions/setup-go sets in CI, or a fixed version, go refuses it,
# so it is skipped with a line saying so, and its own suite (CI's capsule job) builds it
# with the compiler it names.
NESTED_MODULES := clients/mcp examples/sbom examples/capsule

## modules: build and vet each nested module (clients/mcp, examples/sbom, examples/capsule) against this tree; one needing a newer Go is skipped, said so, where GOTOOLCHAIN forbids switching
modules:
	@have=$$(go env GOVERSION); have=$${have#go}; tc=$$(go env GOTOOLCHAIN); \
	 for m in $(NESTED_MODULES); do \
	   need=$$(awk '$$1 == "go" { print $$2; exit }' $$m/go.mod); \
	   case $$tc in auto|*+auto) newer= ;; *) newer=$$(printf '%s\n%s\n' "$$need" "$$have" | sort -V | tail -n 1) ;; esac; \
	   if [ -n "$$newer" ] && [ "$$newer" != "$$have" ]; then \
	     echo "skip $$m: its go.mod needs go $$need, this is go $$have with GOTOOLCHAIN=$$tc (its own suite builds it)"; continue; \
	   fi; \
	   echo "build and vet $$m"; (cd $$m && go build ./... && go vet ./...) || exit 1; \
	 done

# The live E2B and dockercloud tests skip only when their credentials are absent, and
# `./...` selects them, so a key left in the shell (a secrets-manager wrapper, an
# earlier E2B=1 or DOCKERCLOUD=1 session) would make the ordinary gate create billable
# microVMs. These targets strip both credentials; only e2b-suite, e2b-guard-live and
# dockercloud-suite, the deliberate paid runs, see one, and each sees only its own.
NO_PAID_KEYS := env -u E2B_API_KEY -u DOCKER_SBX_TOKEN

## test: unit tests (includes fuzz corpora as regressions); -short skips every docker test; never sees E2B_API_KEY or DOCKER_SBX_TOKEN
test:
	$(NO_PAID_KEYS) go test -short ./... -count=1

## race: unit tests under the race detector; -short skips every docker test (docker-suite runs them); never sees E2B_API_KEY or DOCKER_SBX_TOKEN
race:
	$(NO_PAID_KEYS) go test -race -short ./... -count=1

## lint: golangci-lint (must be on PATH)
lint:
	golangci-lint run ./...

## generate: regenerate gen/ from proto/ and from every vendored third_party/*/buf.gen.yaml, then the Python and TypeScript client tables (internal/wiretables)
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
	go run ./internal/wiretables

## buf: proto lint + verify generated code is in sync, the client tables included (fails if `make generate` would change or add anything)
buf: generate
	buf lint
	@git diff --exit-code --stat -- gen/ $(WIRE_TABLES) && [ -z "$$(git ls-files --others --exclude-standard -- gen/ $(WIRE_TABLES))" ] || { git ls-files --others --exclude-standard -- gen/ $(WIRE_TABLES) >&2; echo "generated code is stale or untracked: run 'make generate' and commit (or stage) gen/ and the client tables" >&2; exit 1; }

# The Python and TypeScript clients' copies of the protocol's enums, the isolation tiers
# and the cell languages, written by internal/wiretables in make generate.
WIRE_TABLES := clients/python/src/plimsoll_client/_tables.py clients/typescript/src/tables.gen.ts

## vuln: govulncheck against the pinned toolchain
vuln:
	govulncheck ./...

## docker-images: pull the snippet image and build the project images the docker suite runs against
docker-images:
	@set -e; img=node:22-alpine; \
	if [ -n "$(DOCKER_HUB_MIRROR)" ] && docker pull "$(DOCKER_HUB_MIRROR)/library/$$img"; then \
	  docker tag "$(DOCKER_HUB_MIRROR)/library/$$img" "$$img"; \
	else \
	  docker pull "$$img"; \
	fi
	@h="$$($(DOCKER_INPUTS_HASH))"; set -ex; \
	docker build $(DOCKER_BASE_ARGS) --label $(DOCKER_INPUTS_LABEL)=$$h -t plimsoll/sandbox:latest docker/; \
	docker build --label $(DOCKER_INPUTS_LABEL)=$$h -t plimsoll/sandbox-python:latest -f docker/python.Dockerfile docker/; \
	docker build $(DOCKER_BASE_ARGS) --label $(DOCKER_INPUTS_LABEL)=$$h -t plimsoll/sandbox-sim:latest -f docker/sim.Dockerfile docker/; \
	docker build --label $(DOCKER_INPUTS_LABEL)=$$h -t plimsoll/sandbox-wasm-cc:latest -f docker/wasm-cc.Dockerfile docker/

# DOCKER_HUB_MIRROR, unset by default, names a registry serving Docker Hub's official
# images under library/ (CI sets mirror.gcr.io). The snippet image node:22-alpine, which
# runs as it is, is pulled from it and tagged with its Docker Hub name; the Dockerfiles'
# bases, each an ARG BASE_* pinned by digest, are built from the same digest on the
# mirror (DOCKER_BASE_ARGS), so the bytes do not change with the registry. Hosted runners
# share Docker Hub's anonymous limit of 100 pulls per 6 hours per address, and a mirror
# set in the runner's daemon.json does not help: the daemon sends the runner's Docker Hub
# login to the mirror, which refuses any credentials, and falls back to Docker Hub.
DOCKER_BASE_ARGS = $(if $(DOCKER_HUB_MIRROR),$(shell sed -n 's|^ARG \(BASE_[A-Z_]*\)=\([a-z0-9._-]*\):[^@]*@\(sha256:[0-9a-f]*\)$$|--build-arg \1=$(DOCKER_HUB_MIRROR)/library/\2@\3|p' docker/Dockerfile docker/*.Dockerfile | LC_ALL=C sort -u))

# The images the suite builds from docker/, and the label each carries: a hash of the
# build context (every file under docker/ by path and content, minus the literal paths
# in docker/.dockerignore). docker-suite refuses an image whose label is not the current
# hash, so a change under docker/ cannot pass the suite on images built before it. The
# base images the Dockerfiles name (node:22-alpine and the others) are outside it.
DOCKER_BUILT_IMAGES = plimsoll/sandbox:latest plimsoll/sandbox-python:latest plimsoll/sandbox-sim:latest plimsoll/sandbox-wasm-cc:latest
DOCKER_INPUTS_LABEL = io.plimsoll.inputs
DOCKER_INPUTS_HASH = cd docker && find . -type f | sed 's|^\./||' | LC_ALL=C sort | grep -vxF -f .dockerignore \
	| while IFS= read -r f; do printf '%s\0' "$$f"; cat -- "$$f"; done | sha256sum | cut -c1-64

# Required mode, twice over. SANDBOX_TEST_REQUIRE_DOCKER=1 makes the test helpers
# fail instead of skip when the daemon or an image is missing; the scan afterwards
# fails the target on ANY skipped test in the selection, so a future bare t.Skip
# cannot turn requested coverage into a quiet pass either. -skip 'Live$' excludes the
# live E2B and dockercloud tests, which can match the selection by name and skip
# without a key; they belong to their own suites, and here a skip must mean docker.
# Anchored, because an unanchored Live also matched TestDockerSessionGrantLivesForItsCall,
# which no required run covered until 2026-10-03.
# The dockercloud unit tests (a fake Connect server, and the exec wrapper under the
# toolchain image's busybox) match 'Docker' and run here. The status file, rather
# than a pipe, keeps the go test exit code under POSIX sh. OracleAttack is the oracle's
# anti-forgery set, which needs the sim image and matches none of the other names; the
# ./docker package holds the gVisor installer's offline-bundle check, which skips
# without zstd and so ran in no required suite before.
## docker-suite: the real docker/seccomp/broker/smoke tests, the oracle anti-forgery tests and the gVisor installer check, under the race detector; a missing daemon, image, tool or skipped test FAILS
# DOCKER_PARALLEL caps how many docker-suite tests run at once. Only the tests that
# call t.Parallel take part; the rest (those that change the environment, list every
# session container on the host, or retag a shared image) run first, alone.
DOCKER_PARALLEL ?= 4
docker-suite:
	@h="$$($(DOCKER_INPUTS_HASH))"; for img in $(DOCKER_BUILT_IMAGES); do \
	   got="$$(docker image inspect -f '{{index .Config.Labels "$(DOCKER_INPUTS_LABEL)"}}' $$img 2>/dev/null)"; \
	   [ "$$got" = "$$h" ] || { echo "docker-suite: $$img was not built from the current docker/ (label '$$got', inputs now $$h); run make docker-images" >&2; exit 1; }; \
	 done
	@mkdir -p tmp
	@[ -w tmp ] || { echo "docker-suite: tmp/ is not writable (created by root during a sudo install?); chown it to your user" >&2; exit 1; }
	@{ SANDBOX_TEST_REQUIRE_DOCKER=1 SANDBOX_DOCKER_SECCOMP="$(SECCOMP)" \
	     $(NO_PAID_KEYS) go test -race ./sandbox ./sandbox/openshell ./sandbox/agentsandbox ./docker -run '$(DOCKER_TESTS)' -skip 'Live$$' -count=1 -parallel $(DOCKER_PARALLEL) -timeout 30m -v; \
	   echo $$? > tmp/docker-suite.status; } 2>&1 | tee tmp/docker-suite.log
	@{ $(MAKE) --no-print-directory py-frameworks PY_FRAMEWORKS=verifiers && \
	   SANDBOX_TEST_REQUIRE_DOCKER=1 SANDBOX_DOCKER_SECCOMP="$(SECCOMP)" \
	     $(NO_PAID_KEYS) go test ./clients/python -run '^(TestPythonWorkspaceDocker|TestVerifiersRuntimeDocker)$$' -count=1 -v; \
	   echo $$? > tmp/docker-suite-python.status; } 2>&1 | tee -a tmp/docker-suite.log
	@if grep -qE '^ *--- SKIP' tmp/docker-suite.log; then \
	   echo "docker-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/docker-suite.log >&2; exit 1; fi
	@s="$$(cat tmp/docker-suite.status)"; [ "$$s" = 0 ] || exit "$$s"; exit "$$(cat tmp/docker-suite-python.status)"

# One virtual environment per Python framework adapter, installed from its directory's lock:
# requirements.in names the framework version, requirements.txt is every package it pulls in,
# pinned with hashes (make py-frameworks-lock writes it), installed with --require-hashes
# --no-deps so nothing is resolved at install time and local and CI runs test the same set. The
# locks are compiled for PY_FRAMEWORKS_PYTHON (CI's python3); another version fails here rather
# than quietly installing a different set. A stamp of the lock decides whether an environment is
# current; any change rebuilds it from scratch.
PY_FRAMEWORKS_PYTHON := 3.12
# PY_FRAMEWORKS names the environments to build, every lock by default; docker-suite builds
# only verifiers, the one its Python checks need.
PY_FRAMEWORKS ?= $(patsubst clients/python/frameworks/%/requirements.txt,%,$(wildcard clients/python/frameworks/*/requirements.txt))
## py-frameworks: build tmp/py-frameworks/<name> from each clients/python/frameworks/<name>/requirements.txt lock, or only those PY_FRAMEWORKS names (needs the network the first time)
py-frameworks:
	@python3 -c 'import sys; v = "%d.%d" % sys.version_info[:2]; sys.exit(0 if v == "$(PY_FRAMEWORKS_PYTHON)" else "py-frameworks: the locks are for Python $(PY_FRAMEWORKS_PYTHON), python3 is " + v + "; run make py-frameworks-lock under it, or use $(PY_FRAMEWORKS_PYTHON)")'
	@mkdir -p tmp/py-frameworks
	@for name in $(PY_FRAMEWORKS); do \
	   req=clients/python/frameworks/$$name/requirements.txt; venv=tmp/py-frameworks/$$name; \
	   [ -f $$req ] || { echo "py-frameworks: no lock at $$req" >&2; exit 1; }; \
	   stamp=$$(sha256sum $$req | cut -c1-64); \
	   if [ "$$(cat $$venv/.requirements 2>/dev/null)" != "$$stamp" ]; then \
	     echo "py-frameworks: building $$venv"; \
	     rm -rf $$venv && python3 -m venv $$venv && \
	     $(NO_PAID_KEYS) $$venv/bin/pip install --quiet --disable-pip-version-check --require-hashes --no-deps -r $$req && \
	     echo $$stamp > $$venv/.requirements || exit 1; \
	   fi; \
	 done

## py-frameworks-lock: recompile each framework's requirements.txt from its requirements.in, every package pinned with hashes (pip-tools in tmp/piptools; needs the network)
py-frameworks-lock:
	@[ -x tmp/piptools/bin/pip-compile ] || { python3 -m venv tmp/piptools && tmp/piptools/bin/pip install --quiet --disable-pip-version-check pip-tools; }
	@for src in clients/python/frameworks/*/requirements.in; do \
	   dir=$$(dirname $$src); echo "py-frameworks-lock: $$dir"; \
	   (cd $$dir && ../../../../tmp/piptools/bin/pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url -o requirements.txt requirements.in) || exit 1; \
	 done

# Install both lockfiles and the Python framework environments, then require the
# Python, Python framework adapter, TypeScript client, add-on and Trigger.dev suites.
# Keep the go test exit status despite tee, and fail on any Go test skip in case a
# future test bypasses PLIMSOLL_REQUIRE_CLIENTS.
# npm ci runs with --ignore-scripts: the trigger example's lockfile holds three packages
# with install scripts (@depot/cli's downloads a binary at install), and its tests need
# none of them (esbuild's binary comes as an optional dependency). Checked 2026-10-24.
# That also skips the client's own prepare script, which compiles clients/typescript/dist
# (gitignored), and the Trigger.dev example imports the client through dist, so the
# client is built here, from the source under test: a fresh checkout has no dist, and a
# stale one would test old code (found in review, 2026-10-28).
## clients-suite: install both npm dependency sets, build the TypeScript client's dist, install the Python framework environments, then run the Python, framework adapter, TypeScript, add-on and Trigger.dev suites; missing prerequisites or a skipped Go test FAILS (TestPythonWorkspaceDocker and TestVerifiersRuntimeDocker need the docker images and are docker-suite's, so they are excluded here rather than skipped)
clients-suite:
	@mkdir -p tmp
	@[ -w tmp ] || { echo "clients-suite: tmp/ is not writable" >&2; exit 1; }
	@{ (cd clients/typescript && $(NO_PAID_KEYS) npm ci --ignore-scripts --userconfig=/dev/null && \
	    rm -rf dist && $(NO_PAID_KEYS) npm run build --userconfig=/dev/null) && \
	   (cd examples/trigger-chat && $(NO_PAID_KEYS) npm ci --ignore-scripts --userconfig=/dev/null) && \
	   $(MAKE) --no-print-directory py-frameworks && \
	   PLIMSOLL_REQUIRE_CLIENTS=1 $(NO_PAID_KEYS) go test ./clients/python/ ./clients/typescript/ -skip '^(TestPythonWorkspaceDocker|TestVerifiersRuntimeDocker)$$' -count=1 -v; \
	   echo $$? > tmp/clients-suite.status; } 2>&1 | tee tmp/clients-suite.log
	@if grep -qE '^ *--- SKIP' tmp/clients-suite.log; then \
	   echo "clients-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/clients-suite.log >&2; exit 1; fi
	@exit "$$(cat tmp/clients-suite.status)"

# The capsule example is its own Go module (Go 1.27 and the capsule emitter's COSE
# and CBOR dependencies), outside `go build ./...` at the root, so nothing else
# builds or tests it. Its tests need the capsule project's Python reference
# verifier, pinned by hash in examples/capsule/requirements.txt as the framework
# environments are, installed into tmp/capsule-verifier and rebuilt when the
# lockfile changes. The module needs Go 1.27: with Go's default GOTOOLCHAIN=auto the
# go command fetches the module's own toolchain line (1.27.2); under
# GOTOOLCHAIN=local, as in CI, the go on PATH must already be 1.27 or later.
## capsule-suite: vet and race-test examples/capsule (its own Go module) with the Python reference verifier installed from its hash-pinned lockfile; a missing verifier or a skipped test FAILS
capsule-suite:
	@mkdir -p tmp
	@[ -w tmp ] || { echo "capsule-suite: tmp/ is not writable" >&2; exit 1; }
	@req=examples/capsule/requirements.txt; venv=tmp/capsule-verifier; stamp=$$(sha256sum $$req | cut -d' ' -f1); \
	 if [ "$$(cat $$venv/.requirements 2>/dev/null)" != "$$stamp" ]; then \
	   echo "capsule-suite: building $$venv"; \
	   rm -rf $$venv && python3 -m venv $$venv && \
	   $(NO_PAID_KEYS) $$venv/bin/pip install --quiet --disable-pip-version-check --require-hashes --no-deps -r $$req && \
	   echo $$stamp > $$venv/.requirements || exit 1; \
	 fi
	@{ (cd examples/capsule && $(NO_PAID_KEYS) go vet ./... && \
	   AAC_VERIFIER="$(CURDIR)/tmp/capsule-verifier/bin/agent-action-capsule" $(NO_PAID_KEYS) go test -race -count=1 -v ./...); \
	   echo $$? > tmp/capsule-suite.status; } 2>&1 | tee tmp/capsule-suite.log
	@if grep -qE '^ *--- SKIP' tmp/capsule-suite.log; then \
	   echo "capsule-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/capsule-suite.log >&2; exit 1; fi
	@exit "$$(cat tmp/capsule-suite.status)"

## capsule-lock: recompile examples/capsule/requirements.txt from its requirements.in, every package pinned with hashes (pip-tools in tmp/piptools; needs the network)
capsule-lock:
	@[ -x tmp/piptools/bin/pip-compile ] || { python3 -m venv tmp/piptools && tmp/piptools/bin/pip install --quiet --disable-pip-version-check pip-tools; }
	tmp/piptools/bin/pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url -o examples/capsule/requirements.txt examples/capsule/requirements.in

.PHONY: receipt-suite
## receipt-suite: run examples/pr-receipt/receipt.sh end to end (docker, runsc, the containerd image store); a skipped test FAILS
receipt-suite:
	@mkdir -p tmp
	@{ RECEIPT_SUITE=1 $(NO_PAID_KEYS) go test ./examples/pr-receipt -run TestReceiptScriptEndToEnd -count=1 -v; \
	   echo $$? > tmp/receipt-suite.status; } 2>&1 | tee tmp/receipt-suite.log
	@if grep -qE '^ *--- SKIP' tmp/receipt-suite.log; then \
	   echo "receipt-suite: required coverage was skipped" >&2; exit 1; fi
	@status="$$(cat tmp/receipt-suite.status)"; [ "$$status" = 0 ] || exit "$$status"; echo "receipt-suite: OK"

.PHONY: policy-suite
## policy-suite: the receipt verifier's policy gate on the Open Policy Agent release pinned in examples/pr-receipt/policy/opa.version (downloaded into tmp/tools once, its SHA-256 checked before it runs): the example policy's own tests and every refusal; a skipped test FAILS
policy-suite:
	@mkdir -p tmp
	@opa="$$(sh examples/pr-receipt/policy/opa.sh "$$PWD/tmp/tools")" || exit 1; \
	  PLIMSOLL_OPA="$$opa" go test ./examples/pr-receipt -run ReceiptPolicyGate -count=1 -v > tmp/policy-suite.log 2>&1; status=$$?; \
	  cat tmp/policy-suite.log; \
	  if grep -qE '^ *--- SKIP' tmp/policy-suite.log; then echo "policy-suite: required coverage was skipped" >&2; exit 1; fi; \
	  [ "$$status" = 0 ] || exit "$$status"; echo "policy-suite: OK"

# This nested module uses its embedded schemas and published signed bundle only.
# No sandbox is created and no hosted service or credential is used.
.PHONY: sbom-suite
## sbom-suite: vet and race-test examples/sbom offline; a skipped test FAILS
sbom-suite:
	@mkdir -p tmp
	@[ -w tmp ] || { echo "sbom-suite: tmp/ is not writable" >&2; exit 1; }
	@{ (cd examples/sbom && $(NO_PAID_KEYS) go vet ./... && \
	   $(NO_PAID_KEYS) go test -race -count=1 -v ./...); \
	   echo $$? > tmp/sbom-suite.status; } 2>&1 | tee tmp/sbom-suite.log
	@if grep -qE '^ *--- SKIP' tmp/sbom-suite.log; then \
	   echo "sbom-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/sbom-suite.log >&2; exit 1; fi
	@status="$$(cat tmp/sbom-suite.status)"; [ "$$status" = 0 ] || exit "$$status"; echo "sbom-suite: OK"

## mcp-suite: the MCP server's own module (clients/mcp): vet, lint, race tests (the real RPC handler over fake providers, the built binary over stdio) and govulncheck, since it ships as a binary; any skipped test FAILS
mcp-suite:
	@mkdir -p tmp
	@[ -w tmp ] || { echo "mcp-suite: tmp/ is not writable" >&2; exit 1; }
	@{ (cd clients/mcp && $(NO_PAID_KEYS) go vet ./... && golangci-lint run ./... && \
	   $(NO_PAID_KEYS) go test -race -count=1 -v ./... && govulncheck ./...); \
	   echo $$? > tmp/mcp-suite.status; } 2>&1 | tee tmp/mcp-suite.log
	@if grep -qE '^ *--- SKIP' tmp/mcp-suite.log; then \
	   echo "mcp-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/mcp-suite.log >&2; exit 1; fi
	@status="$$(cat tmp/mcp-suite.status)"; [ "$$status" = 0 ] || exit "$$status"; echo "mcp-suite: OK"

## e2b-suite: the live E2B tests (needs E2B_API_KEY)
e2b-suite:
	E2B_LIVE=1 env -u DOCKER_SBX_TOKEN go test ./sandbox -run 'E2B.*Live' -count=1 -v

# The live Docker Cloud Sandboxes suite. DOCKERCLOUD_LIVE_REQUIRED=1 makes missing
# configuration fail instead of skip, so a green run means the live service was
# exercised. The provider is written against Docker's published contract; this
# target is how it gets verified against the real service.
#
#   DOCKER_SBX_TOKEN              a Docker personal access token for automation
#   DOCKER_SBX_USERNAME           the account it belongs to
#   SANDBOX_DOCKERCLOUD_API       connect (default) or rest; run the suite once per API
#   SANDBOX_DOCKERCLOUD_API_URL   the management endpoint: required unless the API is rest
#   SANDBOX_DOCKERCLOUD_IMAGE     the toolchain image, pullable by the service, or
#   SANDBOX_DOCKERCLOUD_STORE_IMAGE  one in the account's image store (<id>@sha256:<digest>; connect)
#
## dockercloud-suite: the live Docker Cloud Sandboxes tests (FAILS if not configured; spends)
dockercloud-suite:
	DOCKERCLOUD_LIVE_REQUIRED=1 env -u E2B_API_KEY go test ./sandbox -run 'DockerCloud.*Live' -count=1 -v

# The live OpenShell suite: the provider's tests and a daemon test against a real
# gateway (sandbox/openshell/live_test.go, cmd/plimsolld/openshell_live_test.go). It
# is free, a local gateway on local docker, but needs a gateway, so it is opt-in and
# a request for proof: OPENSHELL_LIVE=1 makes missing configuration fail, and a
# skipped test fails the target. The packages run one after the other, because
# the daemon test requires the gateway to hold no new plimsoll sandbox after the
# daemon exits, and the provider tests would add some if they ran at the same time
# (the two run one after the other).
# The daemon package runs only its OpenShell tests, since its other live tests need other
# infrastructure and would skip here.
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
	@{ OPENSHELL_LIVE=1 $(NO_PAID_KEYS) go test ./sandbox/openshell -run 'Live' -count=1 -v && \
	   OPENSHELL_LIVE=1 $(NO_PAID_KEYS) go test ./cmd/plimsolld -run 'OpenShell.*Live' -count=1 -v; \
	   echo $$? > tmp/openshell-suite.status; } 2>&1 | tee tmp/openshell-suite.log
	@if grep -qE '^ *--- SKIP' tmp/openshell-suite.log; then \
	   echo "openshell-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/openshell-suite.log >&2; exit 1; fi
	@exit "$$(cat tmp/openshell-suite.status)"

# The live agent-sandbox suite: the provider's tests and a daemon test against a cluster
# (sandbox/agentsandbox/live_test.go, cmd/plimsolld/agentsandbox_live_test.go), the
# provider's first, since the daemon test requires the cluster to hold no new claim of
# plimsoll's after the daemon exits. Free, but it needs a cluster, so it is opt-in and a
# request for proof: missing configuration or a skipped test fails the target. The
# settings are plimsolld's own (`plimsolld -h`) plus AGENTSANDBOX_TIER, the tier the
# cluster was set up for (kernel, container or vm), stated outside the provider.
#
# The tests reach each pod at its address, so they run where the pod network is
# routable. Inside the cluster that is anywhere; for a kind cluster on this host's docker,
# set AGENTSANDBOX_NETWORK to kind's docker network and AGENTSANDBOX_POD_ROUTE to the pod
# range through the node (for example '10.244.0.0/16 via 172.24.0.2'), and the suite
# runs in a container on that network with that route, every file setting mounted
# read-only at its own path.
AGENTSANDBOX_SETTINGS := AGENTSANDBOX_TIER SANDBOX_AGENTSANDBOX_API_SERVER SANDBOX_AGENTSANDBOX_CA_FILE \
	SANDBOX_AGENTSANDBOX_TOKEN_FILE SANDBOX_AGENTSANDBOX_NAMESPACE SANDBOX_AGENTSANDBOX_WARM_POOL \
	SANDBOX_AGENTSANDBOX_RUNTIME_CLASS SANDBOX_AGENTSANDBOX_IMAGE SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE \
	SANDBOX_MEMORY_MB SANDBOX_CPUS SANDBOX_DISK_MB SANDBOX_REQUIRE_PINNED_IMAGES
AGENTSANDBOX_FILES := SANDBOX_AGENTSANDBOX_CA_FILE SANDBOX_AGENTSANDBOX_TOKEN_FILE SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE
## agentsandbox-suite: the live agent-sandbox provider and daemon tests; a missing cluster or a skipped test FAILS
agentsandbox-suite:
	@mkdir -p tmp/agentsandbox-suite
	@CGO_ENABLED=0 go test -c -o tmp/agentsandbox-suite/provider.test ./sandbox/agentsandbox
	@CGO_ENABLED=0 go test -c -o tmp/agentsandbox-suite/daemon.test ./cmd/plimsolld
	@{ if [ -n "$(AGENTSANDBOX_NETWORK)" ]; then \
	     set --; \
	     for v in $(AGENTSANDBOX_SETTINGS); do [ -n "$$(printenv $$v)" ] && set -- "$$@" -e "$$v"; done; \
	     for v in $(AGENTSANDBOX_FILES); do f="$$(printenv $$v)"; [ -n "$$f" ] && set -- "$$@" -v "$$f:$$f:ro"; done; \
	     docker run --rm --network "$(AGENTSANDBOX_NETWORK)" --cap-add NET_ADMIN -e AGENTSANDBOX_LIVE=1 "$$@" \
	       -v "$(CURDIR)/tmp/agentsandbox-suite:/suite:ro" alpine:3 sh -c \
	       "ip route add $(AGENTSANDBOX_POD_ROUTE) && /suite/provider.test -test.run Live -test.count=1 -test.v && /suite/daemon.test -test.run 'AgentSandbox.*Live' -test.count=1 -test.v"; \
	   else \
	     AGENTSANDBOX_LIVE=1 $(NO_PAID_KEYS) tmp/agentsandbox-suite/provider.test -test.run Live -test.count=1 -test.v && \
	     AGENTSANDBOX_LIVE=1 $(NO_PAID_KEYS) tmp/agentsandbox-suite/daemon.test -test.run 'AgentSandbox.*Live' -test.count=1 -test.v; \
	   fi; echo $$? > tmp/agentsandbox-suite.status; } 2>&1 | tee tmp/agentsandbox-suite.log
	@if grep -qE '^ *--- SKIP' tmp/agentsandbox-suite.log; then \
	   echo "agentsandbox-suite: required coverage was skipped:" >&2; \
	   grep -E '^ *--- SKIP' tmp/agentsandbox-suite.log >&2; exit 1; fi
	@exit "$$(cat tmp/agentsandbox-suite.status)"

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
	E2B_GUARD_LIVE_REQUIRED=1 env -u DOCKER_SBX_TOKEN go test ./sandbox -run 'TestE2BGuardLive|TestE2BSessionGuardLive' -count=1 -v

# The live E2B session suite: the startup and session smoke tests, the session
# conformance suite and the guest's privileges, against the real service. It spends
# (a microVM per case, about 2 cents a pass at the template's size), so it runs only
# here, never in e2b-suite or the gate. E2B_TEMPLATE picks the template (default base).
## e2b-session-live: prove E2B sessions against the live service, the daemon's unclaimed close included (paid; needs E2B_API_KEY)
e2b-session-live:
	E2B_SESSION_LIVE=1 env -u DOCKER_SBX_TOKEN go test ./sandbox -run 'TestLiveE2BSessions|TestLiveE2BDaemonClosesAnUnclaimedSession' -count=1 -v -timeout 40m

## dockercloud-guard-live: prove a Docker Cloud host-API grant end to end on the Connect API (paid, well under a cent; needs a public guard route to this process, see TestDockerCloudGuardLive)
dockercloud-guard-live:
	DOCKERCLOUD_GUARD_LIVE_REQUIRED=1 DOCKERCLOUD_LIVE_REQUIRED=1 env -u E2B_API_KEY go test ./sandbox -run 'TestDockerCloudGuardLive' -count=1 -v -timeout 10m


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
