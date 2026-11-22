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
# SANDBOX_AGENTSANDBOX_* settings) to include them. Each is a request for proof: those
# suites run in required mode (SUITE_BEGIN and SUITE_END below), where missing
# infrastructure or configuration, or any skipped test, fails the target instead of
# passing quietly. E2B and
# dockercloud spend money; no CI job runs them, nor openshell, which needs a gateway, nor
# agentsandbox, which needs a cluster.
SECCOMP := $(CURDIR)/docker/seccomp.json

# The docker suite's tests in ./sandbox and ./docker, by top-level name. Only
# docker-suite runs a docker container: the race and test passes run with -short, which
# the docker test helpers (requireDocker, sessionDocker) read as "skip", so a box with
# docker and the images no longer runs the docker tests a second time, outside required
# mode, in every plain `make audit` (418 s of a 7-minute gate on 2026-10-04). Tests in
# this selection that need no docker run in both passes. TestSessionInit is the session
# init's tests (sandbox/docker_session_helpers_test.go), whose names hold none of the
# other words.
DOCKER_TESTS := Docker|RunProject|Broker|Smoke|OracleAttack|Installer|TestSessionInit

# The Python client's checks on real docker sessions, in ./clients/python, by top-level
# name, and the framework environments (make py-frameworks) they run in. docker-suite runs
# them in required mode; clients-suite excludes them by these names, since CI's clients
# job builds no images and a check there would skip, which fails that suite. One list for
# both targets, so each of these checks runs in exactly one of them.
DOCKER_PY_TESTS := TestPythonWorkspaceDocker|TestPythonReattachDocker|TestVerifiersRuntimeDocker|TestDeepAgentsDocker|TestAgentFrameworkDocker|TestSmolagentsDocker|TestPydanticAIDocker|TestPydanticAICrashDocker|TestADKEnvironmentDocker|TestPythonExamplesDocker
# The ADK environment's check runs in the adk environment; the example programs run in the agno,
# crewai, adk, openai_agents, agent_framework, smolagents and pydantic_ai environments, and the
# LangChain one in deepagents (clients/python/examples_docker_test.go).
DOCKER_PY_FRAMEWORKS := verifiers deepagents agent_framework smolagents pydantic_ai agno crewai adk openai_agents

# The tests in dockercloud-suite's selection, by top-level name, that skip on purpose there
# for want of settings of their own and belong to another target: the guarded-egress test,
# dockercloud-guard-live's. That suite leaves them out, so any skip it does see fails it.
DOCKERCLOUD_SUITE_SKIP := TestDockerCloudGuardLive

GATE_TOOLS := gate-tools.versions

.PHONY: nemotron-verifier audit build vet modules test race lint generate buf vuln docker-images docker-suite docker-go-suite docker-py-suite docker-faults docker-suite-parts py-frameworks py-frameworks-key py-frameworks-python py-frameworks-lock clients-suite mcp-suite e2b-suite e2b-guard-live e2b-session-live dockercloud-guard-live dockercloud-suite openshell-suite agentsandbox-suite wslc-suite wslc-gvisor-suite wslc-docker-check tools tools-check help

## audit: the full local gate (pinned-tool check, build, vet, race tests, lint, buf, govulncheck, plus the opt-in docker, e2b, dockercloud and openshell suites)
## audit prerequisites: node and cc on PATH, and a non-root user; runnerwire's
##   TestProjectRunnerAlwaysEmitsCompleteBoundedJSON and TestProjectRunnerReportsTruncationFlags
##   skip without node or as root (root defeats the runner guard they test)
audit: tools-check build vet modules race lint buf vuln
	@if [ "$(DOCKER)" = "1" ]; then $(MAKE) docker-suite; else echo "skip docker-suite (set DOCKER=1 with a local daemon + images from 'make docker-images')"; fi
	@if [ "$(DOCKER)" = "1" ]; then $(MAKE) wslc-docker-check; else echo "skip wslc-docker-check (set DOCKER=1)"; fi
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

# GO_TEST_TIMEOUT is each test binary's limit in test, race, the docker suite's parts and
# clients-suite: 30 minutes by default, since on a loaded machine the clients/python package
# (the Python client's suite and the framework suites) took 562 to 589 s under make audit on
# 2026-11-17, at the edge of go test's default 10-minute package timeout, and went past it twice
# that day. Nearly all of that was a working copy's own test modules, which TestPython has run
# apart since 2026-11-18 (PLIMSOLL_PY_ELSEWHERE, clients/python/client_test.go); its own tests
# took 13 s. CI sets 15 minutes, under its jobs' 30-minute limits: there a test that hangs hits
# go test's limit first, which prints every goroutine's stack, instead of the job's, which kills
# the runner with no trace, and a package three times slower than its slowest CI run (./sandbox
# under runsc, 330 s on 2026-11-17) fails instead of passing.
GO_TEST_TIMEOUT ?= 30m

## test: unit tests (includes fuzz corpora as regressions); -short skips every docker test; never sees E2B_API_KEY or DOCKER_SBX_TOKEN
test:
	$(NO_PAID_KEYS) go test -short ./... -count=1 -timeout $(GO_TEST_TIMEOUT)

# A test that skips in the short pass runs only where a suite selects it, and the docker
# suite selects by name and by package (DOCKER_TESTS, in the packages its line names). So
# the pass ends with a check of its own structured results: every test that skipped must be
# selected by the go test of some target that runs through SUITE_BEGIN, read from make's own
# dry run of each (internal/suiterun's unselected). A test that needs docker under a name
# or in a package no suite reaches then fails this pass, in every gate, without docker:
# nine such tests had run in no target and no CI job until 2026-11-20. A test that is run by
# hand on purpose (it needs a flag of its own and something no suite sets up) is listed in
# BY_HAND_TESTS with the reason, one line each; a listed test that did not skip fails the
# pass too, so the list cannot outlive what it describes. (+=: local.mk, read above, may have
# named a list of its own already.)
BY_HAND_TESTS += internal/suiterun/by-hand-tests.txt
## race: unit tests under the race detector; -short skips every docker test (docker-suite runs them), and a test that skips here and that no suite selects fails the pass; never sees E2B_API_KEY or DOCKER_SBX_TOKEN
race:
	@mkdir -p tmp; rm -f tmp/race$(SUITE_TAG).results; go build -o tmp/race$(SUITE_TAG).reader ./internal/suiterun
	SUITE_RESULTS=$(CURDIR)/tmp/race$(SUITE_TAG).results $(NO_PAID_KEYS) tmp/race$(SUITE_TAG).reader test -quiet -race -short ./... -count=1 -timeout $(GO_TEST_TIMEOUT)
	tmp/race$(SUITE_TAG).reader unselected tmp/race$(SUITE_TAG).results $(BY_HAND_TESTS)

## lint: golangci-lint (must be on PATH)
lint:
	golangci-lint run ./...

## generate: regenerate gen/ from proto/ and from every vendored third_party/*/buf.gen.yaml, then the Python and TypeScript client tables (internal/wiretables) and the guest guard's filter (sandbox/internal/guestguard/gen)
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
	go run ./sandbox/internal/guestguard/gen

## buf: proto lint + verify generated code is in sync, the client tables included (fails if `make generate` would change or add anything)
buf: generate
	buf lint
	@git diff --exit-code --stat -- gen/ $(WIRE_TABLES) && [ -z "$$(git ls-files --others --exclude-standard -- gen/ $(WIRE_TABLES))" ] || { git ls-files --others --exclude-standard -- gen/ $(WIRE_TABLES) >&2; echo "generated code is stale or untracked: run 'make generate' and commit (or stage) gen/ and the client tables" >&2; exit 1; }

# The Python and TypeScript clients' and the receipt checker's copies of the protocol's enums and
# the wire rules (limits, grammars, record layouts), written by internal/wiretables in make generate.
WIRE_TABLES := clients/python/src/plimsoll_client/_tables.py clients/typescript/src/tables.gen.ts examples/sbom/tables.gen.js clients/python/src/plimsoll_client/_granted.py clients/typescript/src/granted.gen.ts

## publish-workflows: write the Python packages' publish workflows (.github/workflows/publish-<name>.yml) from internal/publishflows' table, one row per PyPI project; its test fails when a file is not what this writes
.PHONY: publish-workflows
publish-workflows:
	go run ./internal/publishflows

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
	docker build $(DOCKER_BASE_ARGS) $(NATIVE_HELPER_CONTEXT) --label $(DOCKER_INPUTS_LABEL)=$$h -t plimsoll/sandbox:latest docker/; \
	docker build --label $(DOCKER_INPUTS_LABEL)=$$h -t plimsoll/sandbox-python:latest -f docker/python.Dockerfile docker/; \
	docker build $(DOCKER_BASE_ARGS) $(NATIVE_HELPER_CONTEXT) --label $(DOCKER_INPUTS_LABEL)=$$h -t plimsoll/sandbox-sim:latest -f docker/sim.Dockerfile docker/; \
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
# in docker/.dockerignore, then the native helper's two files, below). docker-suite refuses an image whose label is not the current
# hash, so a change under docker/ cannot pass the suite on images built before it. The
# base images the Dockerfiles name (node:22-alpine and the others) are outside it.
# The project runner in those images, the native helper, is not under docker/: the images
# that carry it (docker/Dockerfile, docker/sim.Dockerfile) take it from the named build
# context nativehelper, its committed build at its pin (NATIVE_HELPER_DIR), and the hash
# covers the two files they read from there, named nativehelper/<file>, after docker/'s.
DOCKER_BUILT_IMAGES = plimsoll/sandbox:latest plimsoll/sandbox-python:latest plimsoll/sandbox-sim:latest plimsoll/sandbox-wasm-cc:latest
DOCKER_INPUTS_LABEL = io.plimsoll.inputs
NATIVE_HELPER_DIR = sandbox/internal/nativehelper/program
NATIVE_HELPER_FILES = plimsoll-helper.sha256 plimsoll-helper_amd64
NATIVE_HELPER_CONTEXT = --build-context nativehelper=$(NATIVE_HELPER_DIR)
DOCKER_INPUTS_HASH = { (cd docker && find . -type f | sed 's|^\./||' | LC_ALL=C sort | grep -vxF -f .dockerignore \
	| while IFS= read -r f; do printf '%s\0' "$$f"; cat -- "$$f"; done) && \
	(cd $(NATIVE_HELPER_DIR) && for f in $(NATIVE_HELPER_FILES); do printf 'nativehelper/%s\0' "$$f"; cat -- "$$f" || exit 1; done); } \
	| sha256sum | cut -c1-64

# Required mode, written once. A suite that is a request for proof (its help line says a
# skipped test FAILS it) wraps its commands, on one recipe line, as
#
#	@$(SUITE_BEGIN) <commands>; $(SUITE_END)
#
# SUITE_BEGIN makes tmp/ and fails when it is not writable; the commands' output goes to
# the terminal and to tmp/<target>.log; SUITE_END fails the target on ANY skipped Go test
# in the suite's structured results, listing each, so a future bare t.Skip cannot turn
# requested coverage into a quiet pass, and otherwise exits with the commands' own status. A status file, rather
# than the pipe, carries that status past tee under POSIX sh, and a command that ends the
# shell before it is written fails the target. A suite that builds something with $(MAKE)
# does it on a line of its own first: make runs a line holding $(MAKE) even under -n. Until
# 2026-11-18 each suite carried its own copy of this, and the copies had drifted: one
# listed no skipped test, one did not tee, and two had no scan at all
# (internal/maketest holds every FAILS target to it now).
# Whether a test skipped is read from go test's structured results (go test -json), never
# from the words it prints: every go test of a suite runs as $(SUITE_TEST), which is
# internal/suiterun's reader, built by SUITE_BEGIN into tmp/<target>.reader. It runs go test
# -json with the same arguments, prints what -v would, and appends each test's result to
# tmp/<target>.results; SUITE_END's check reads that file and fails the target on a skipped
# test, naming each, and on no result at all, so a go test written here without the reader
# fails its suite. Until 2026-11-20 SUITE_END searched the log for go test's "--- SKIP",
# which go test prints only under -v, a flag nothing required.
# SUITE_TAG (empty unless set) is added to each of a suite's file names in tmp/, so two runs of
# one suite at the same moment in one checkout (the docker Go suite under runc and under
# gVisor, side by side) each write files of their own: make docker-go-suite SUITE_TAG=.runsc
# writes tmp/docker-go-suite.runsc.log, .status, .results and .reader.
MAKEFILE_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
SUITE_TAG ?=
SUITE_FILE = tmp/$@$(SUITE_TAG)
SUITE_READER = $(CURDIR)/$(SUITE_FILE).reader
SUITE_TEST = $(SUITE_READER) test
SUITE_BEGIN = mkdir -p tmp; [ -w tmp ] || { echo "$@: tmp/ is not writable (created by root during a sudo install?); chown it to your user" >&2; exit 1; }; rm -f $(SUITE_FILE).status $(SUITE_FILE).results; \
	go build -C $(MAKEFILE_DIR) -o $(SUITE_READER) ./internal/suiterun || exit 1; export SUITE_RESULTS=$(CURDIR)/$(SUITE_FILE).results; \
	$(if $(SUITE_DOCKER_RUN),suite_run="$$(mktemp -d -t pXXX)" || exit 1; export TMPDIR="$$suite_run";) {
SUITE_END = echo $$? > $(SUITE_FILE).status; } 2>&1 | tee $(SUITE_FILE).log; \
	$(if $(SUITE_DOCKER_RUN),$(SUITE_READER) leftovers "$$suite_run"; left=$$?; rm -rf "$$suite_run"; [ "$$left" = 0 ] || exit 1;) \
	$(SUITE_READER) check $(SUITE_FILE).results || { echo "$@: its results did not pass the reader's check (above)" >&2; exit 1; }; \
	s="$$(cat $(SUITE_FILE).status 2>/dev/null)"; [ "$$s" = 0 ] || exit "$${s:-1}"; echo "$@: OK"
# A docker suite (SUITE_DOCKER_RUN set for its target, below) runs its tests with TMPDIR a
# directory made for the run, where the docker provider keeps the files it bind-mounts into
# every container it starts, and ends by failing on any container still on the docker host
# with a mount from there, which it names and removes (suiterun leftovers): a container this
# run started that no test closed, told apart by its mounts from another suite's on the same
# host at the same moment. The docker Python suite left a paused session container and the
# docker exec attached to it on every run until 2026-11-20, and the exec kept the gate's
# scope alive after the gate ended. The directory's name is short (/tmp/pXXX, 5 characters
# more than /tmp itself) because a unix socket's path holds at most 107 bytes and the
# longest a docker test makes under TMPDIR is 100 under /tmp (the E2B stand-in's envd.sock
# under t.TempDir); with /tmp/plimsoll-suite.XXXXXXXX ten of them could not listen.

# The docker suite is in parts, each a required suite of its own: docker-go-suite, the Go
# tests in ./sandbox, ./sandbox/openshell, ./sandbox/agentsandbox and ./docker, and
# docker-py-suite, the Python client's checks on real docker sessions. make docker-suite runs
# them in turn; CI runs each as a job of its own at the same time, under runc (audit.yml) and
# under runsc (gvisor.yml), through .github/workflows/docker-suite.yml, which reads this list
# from make docker-suite-parts. In one job the two took 232 s and then 128 s under runc, and
# 330 s and then 243 s under runsc (CI 2026-11-17 and the rehearsal of 2026-11-18), on the
# same four CPUs; as two jobs they overlap. A new part is a new target here, named in this
# list with the framework environments it builds (<part>_FRAMEWORKS, empty for none).
DOCKER_SUITE_PARTS := docker-go-suite docker-py-suite
$(DOCKER_SUITE_PARTS): SUITE_DOCKER_RUN = 1
docker-py-suite_FRAMEWORKS = $(DOCKER_PY_FRAMEWORKS)
# A part whose tests run node names the node CI installs for it (<part>_NODE, empty for none):
# docker-py-suite's example programs include the TypeScript client's granted example
# (clients/typescript/examples/granted.ts), which node runs from source, and TypeScript without a
# build needs node 22.18 or later. NODE_VERSION is that node, the one the clients job pins too
# (internal/maketest's TestDockerSuiteParts holds the two equal); here a part runs the node on PATH.
NODE_VERSION := 22.18.0
docker-py-suite_NODE = $(NODE_VERSION)

## docker-suite: both parts of the docker suite in turn (docker-go-suite, then docker-py-suite, each in required mode); it fails when either part does, after running both
# make runs a line holding $(MAKE) even under -n, and passes -n on, so make -n docker-suite
# prints each part's commands and runs none.
docker-suite:
	@status=0; for part in $(DOCKER_SUITE_PARTS); do $(MAKE) --no-print-directory $$part || status=1; done; exit $$status

comma := ,
## docker-suite-parts: print the docker suite's parts as JSON, for CI's matrix: each part's target, the framework environments it builds, the Python they are locked for, and the node its tests run (empty for none)
docker-suite-parts:
	@echo '[$(subst } {,}$(comma){,$(foreach p,$(DOCKER_SUITE_PARTS),{"part":"$(p)"$(comma)"frameworks":"$(strip $($(p)_FRAMEWORKS))"$(comma)"python":"$(PY_FRAMEWORKS_PYTHON)"$(comma)"node":"$(strip $($(p)_NODE))"}))]'

# Each part first refuses an image whose inputs label is not the current hash of docker/.
DOCKER_IMAGES_CURRENT = h="$$($(DOCKER_INPUTS_HASH))"; for img in $(DOCKER_BUILT_IMAGES); do \
	   got="$$(docker image inspect -f '{{index .Config.Labels "$(DOCKER_INPUTS_LABEL)"}}' $$img 2>/dev/null)"; \
	   [ "$$got" = "$$h" ] || { echo "$@: $$img was not built from the current docker/ (label '$$got', inputs now $$h); run make docker-images" >&2; exit 1; }; \
	 done

# The parts are required mode twice over. SANDBOX_TEST_REQUIRE_DOCKER=1 makes the test
# helpers fail instead of skip when the daemon or an image is missing, and the runner fails
# the target on any skipped test in the selection. -skip 'Live$' excludes the
# live E2B and dockercloud tests, which can match the selection by name and skip
# without a key; they belong to their own suites, and here a skip must mean docker.
# Anchored, because an unanchored Live also matched TestDockerSessionGrantLivesForItsCall,
# which no required run covered until 2026-10-03.
# The dockercloud unit tests (a fake Connect server, and the exec wrapper under the
# toolchain image's busybox) match 'Docker' and run here. OracleAttack is the oracle's
# anti-forgery set, which needs the sim image and matches none of the other names; the
# ./docker package holds the gVisor installer's offline-bundle check, which skips
# without zstd and so ran in no required suite before.
# docker-py-suite is the Python client's checks on real docker sessions (DOCKER_PY_TESTS),
# without the race detector, the framework ones each in its framework environment
# (DOCKER_PY_FRAMEWORKS, built first, on a line of its own). Under
# SANDBOX_DOCKER_RUNTIME=runsc, as the gvisor workflow runs both parts, their sessions run
# on gVisor, and the verifiers, framework and example checks set the kernel tier as their
# isolation floor.
# make runs a recipe line that holds $(MAKE) even under -n (GNU make's rule for recursive
# make), so each suite builds its framework environments on a line of its own and no line that
# runs a test holds $(MAKE): make -n docker-py-suite and make -n clients-suite run no test
# (review finding release-36; internal/maketest's TestSuiteDryRunsRunNoTest holds it).
# DOCKER_PARALLEL caps how many docker tests run at once. Only the tests that
# call t.Parallel take part; the rest (those that change the environment or retag a
# shared image) run first, alone.
DOCKER_PARALLEL ?= 4
# DOCKER_RUNTIME_BLIND names the tests of docker-go-suite's selection whose containers never
# run under SANDBOX_DOCKER_RUNTIME: the stand-in for E2B's service starts its own with a
# docker run that names no runtime (sandbox/e2b_session_docker_test.go), and the E2B
# provider they test never names one. Under another runtime they repeat the default
# runtime's run word for word (198 to 300 s of test time in the gVisor pass, 2026-11-20), so
# a pass under a named runtime other than runc leaves them out, and the default pass, which
# make audit DOCKER=1 and CI's runc job run, is where they are proven. Run with
# SANDBOX_DOCKER_RUNTIME naming a runtime docker does not have, all of them pass: none asks
# docker for it. internal/maketest's TestRuntimeBlindTests holds the pattern to the code:
# every test it selects is in a file that never reads the runtime, and it selects nothing
# outside the stand-in's two files.
DOCKER_RUNTIME_BLIND := ^TestE2B(Session)?Docker
DOCKER_GO_SKIP = Live$$$(if $(filter-out runc,$(SANDBOX_DOCKER_RUNTIME)),|$(DOCKER_RUNTIME_BLIND))
## docker-go-suite: the real docker/seccomp/broker/smoke tests, the oracle anti-forgery tests and the gVisor installer check, under the race detector; a missing daemon, image, tool or skipped test FAILS; under a SANDBOX_DOCKER_RUNTIME other than runc, without the tests whose containers never run under it (DOCKER_RUNTIME_BLIND)
docker-go-suite:
	@$(DOCKER_IMAGES_CURRENT)
	@$(SUITE_BEGIN) SANDBOX_TEST_REQUIRE_DOCKER=1 SANDBOX_DOCKER_SECCOMP="$(SECCOMP)" \
	     $(NO_PAID_KEYS) $(SUITE_TEST) -race ./sandbox ./sandbox/openshell ./sandbox/agentsandbox ./docker -run '$(DOCKER_TESTS)' -skip '$(DOCKER_GO_SKIP)' -count=1 -parallel $(DOCKER_PARALLEL) -timeout $(GO_TEST_TIMEOUT); $(SUITE_END)
## docker-py-suite: the Python client's checks on real docker sessions (the agent workspace, the verifiers runtime, the Deep Agents, Agent Framework, smolagents, PydanticAI and Google ADK environment adapters, and the example programs), each in the framework environment its lock pins; a missing daemon, image, framework environment or skipped test FAILS
docker-py-suite:
	@$(DOCKER_IMAGES_CURRENT)
	@$(MAKE) --no-print-directory py-frameworks PY_FRAMEWORKS="$(DOCKER_PY_FRAMEWORKS)"
	@$(SUITE_BEGIN) SANDBOX_TEST_REQUIRE_DOCKER=1 SANDBOX_DOCKER_SECCOMP="$(SECCOMP)" \
	     $(NO_PAID_KEYS) $(SUITE_TEST) ./clients/python -run '^($(DOCKER_PY_TESTS))$$' -count=1 -parallel $(DOCKER_PARALLEL) -timeout $(GO_TEST_TIMEOUT); $(SUITE_END)

# docker-faults runs the docker provider against a docker CLI that fails on purpose
# (sandbox/faultrounds_test.go): ROUNDS rounds, each one scenario (a snippet, a session's
# open, cells, suspend, resume, close or lifetime end, a pool claim, the orphan pass) with
# one docker command refused, hung, slowed, or run and then reported failed or hung, and
# after each the checks of what it left behind. The rounds that once found a defect run
# first. SEED=<seed>[,<seed>...] replays those rounds alone; START=<seed> repeats a whole
# run. Under SANDBOX_DOCKER_RUNTIME=runsc the rounds run on gVisor. It is not part of
# make audit: 150 rounds take tens of minutes.
ROUNDS ?= 150
SEED ?=
START ?=
docker-faults: SUITE_DOCKER_RUN = 1
## docker-faults: the docker provider's cleanup under docker commands that fail, hang or lie on purpose (ROUNDS=150, SEED= to replay, START= to repeat a run); a missing daemon, image or skipped test FAILS
docker-faults:
	@$(DOCKER_IMAGES_CURRENT)
	@$(SUITE_BEGIN) SANDBOX_TEST_REQUIRE_DOCKER=1 SANDBOX_DOCKER_SECCOMP="$(SECCOMP)" PLIMSOLL_FAULT_ROUNDS="$(ROUNDS)" PLIMSOLL_FAULT_SEED="$(SEED)" PLIMSOLL_FAULT_START="$(START)" \
	     $(NO_PAID_KEYS) $(SUITE_TEST) -race ./sandbox -run '^TestFaultRounds$$' -count=1 -timeout 4h; $(SUITE_END)

# One virtual environment per Python framework adapter, installed from its directory's lock:
# requirements.in names the framework version, requirements.txt is every package it pulls in,
# pinned with hashes (make py-frameworks-lock writes it), installed with --require-hashes
# --no-deps so nothing is resolved at install time and local and CI runs test the same set. The
# locks are compiled for PY_FRAMEWORKS_PYTHON (CI's jobs install it with setup-python); another version fails here rather
# than quietly installing a different set. A stamp of the lock decides whether an environment is
# current; any change rebuilds it from scratch.
PY_FRAMEWORKS_PYTHON := 3.12
# PY_FRAMEWORKS names the environments to build, every lock by default; docker-suite builds
# only DOCKER_PY_FRAMEWORKS, the ones its Python checks need.
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

## py-frameworks-python: print the Python the framework locks are compiled for (PY_FRAMEWORKS_PYTHON), which CI's jobs install; internal/maketest checks every lock's header names it
py-frameworks-python:
	@echo "$(PY_FRAMEWORKS_PYTHON)"

## py-frameworks-key: print a digest of what decides the content of the PY_FRAMEWORKS environments (each name and its lock, the Python the locks are for, and the py-frameworks recipe), the key CI caches tmp/py-frameworks under
# CI restores the environments from GitHub's cache under this key and the runner's exact
# Python, so a change to a lock, the list, the Python or the way an environment is built makes
# a new key, and make py-frameworks then builds what the restored stamps do not match.
py-frameworks-key:
	@for name in $(PY_FRAMEWORKS); do [ -f clients/python/frameworks/$$name/requirements.txt ] || { echo "$@: no lock for $$name" >&2; exit 1; }; done; \
	 recipe="$$(sed -n '/^py-frameworks:$$/,/^$$/p' $(firstword $(MAKEFILE_LIST)))"; \
	 [ -n "$$recipe" ] || { echo "$@: no py-frameworks recipe in $(firstword $(MAKEFILE_LIST))" >&2; exit 1; }; \
	 { printf '%s\n' "$$recipe" "$(PY_FRAMEWORKS_PYTHON)"; \
	   for name in $(PY_FRAMEWORKS); do printf '%s\0' "$$name"; cat clients/python/frameworks/$$name/requirements.txt; done; } | sha256sum | cut -c1-64

## py-frameworks-lock: recompile each framework's requirements.txt from its requirements.in, every package pinned with hashes (pip-tools in tmp/piptools; needs the network)
py-frameworks-lock:
	@[ -x tmp/piptools/bin/pip-compile ] || { python3 -m venv tmp/piptools && tmp/piptools/bin/pip install --quiet --disable-pip-version-check pip-tools; }
	@for src in clients/python/frameworks/*/requirements.in; do \
	   dir=$$(dirname $$src); echo "py-frameworks-lock: $$dir"; \
	   (cd $$dir && ../../../../tmp/piptools/bin/pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url -o requirements.txt requirements.in) || exit 1; \
	 done

# Install both lockfiles and the Python framework environments, then require the
# Python, Python framework adapter, TypeScript client, add-on and Trigger.dev suites.
# The runner fails on any Go test skip in case a future test bypasses
# PLIMSOLL_REQUIRE_CLIENTS.
# npm ci runs with --ignore-scripts: the trigger example's lockfile holds three packages
# with install scripts (@depot/cli's downloads a binary at install), and its tests need
# none of them (esbuild's binary comes as an optional dependency). Checked 2026-10-24.
# That also skips the client's own prepare script, which compiles clients/typescript/dist
# (gitignored), and the Trigger.dev example imports the client through dist, so the
# client is built here, from the source under test: a fresh checkout has no dist, and a
# stale one would test old code (found in review, 2026-10-28).
# The Python package took 9 to 11 minutes (TestPython about 500 s and TestDeepAgentsDocker about
# 130 s on 2026-11-17), past go test's default 10-minute package timeout, so the suite sets
# GO_TEST_TIMEOUT (see above). The checks on real docker sessions (the framework ones, the example
# programs) have since moved to docker-suite, and TestPython's growth was a working copy's own
# test modules, which it has run apart since 2026-11-18.
## clients-suite: install both npm dependency sets, build the TypeScript client's dist, install the Python framework environments, then run the Python, framework adapter, TypeScript, add-on and Trigger.dev suites; missing prerequisites or a skipped Go test FAILS (the Python client's checks on real docker sessions, DOCKER_PY_TESTS, are docker-suite's, so they are excluded here rather than skipped)
clients-suite:
	@$(MAKE) --no-print-directory py-frameworks
	@$(SUITE_BEGIN) (cd clients/typescript && $(NO_PAID_KEYS) npm ci --ignore-scripts --userconfig=/dev/null && \
	    rm -rf dist && $(NO_PAID_KEYS) npm run build --userconfig=/dev/null) && \
	   (cd examples/trigger-chat && $(NO_PAID_KEYS) npm ci --ignore-scripts --userconfig=/dev/null) && \
	   PLIMSOLL_REQUIRE_CLIENTS=1 $(NO_PAID_KEYS) $(SUITE_TEST) ./clients/python/ ./clients/typescript/ -skip '^($(DOCKER_PY_TESTS))$$' -count=1 -timeout $(GO_TEST_TIMEOUT); $(SUITE_END)

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
	@req=examples/capsule/requirements.txt; venv=tmp/capsule-verifier; stamp=$$(sha256sum $$req | cut -d' ' -f1); \
	 if [ "$$(cat $$venv/.requirements 2>/dev/null)" != "$$stamp" ]; then \
	   echo "capsule-suite: building $$venv"; \
	   rm -rf $$venv && python3 -m venv $$venv && \
	   $(NO_PAID_KEYS) $$venv/bin/pip install --quiet --disable-pip-version-check --require-hashes --no-deps -r $$req && \
	   echo $$stamp > $$venv/.requirements || exit 1; \
	 fi
	@$(SUITE_BEGIN) (cd examples/capsule && $(NO_PAID_KEYS) go vet ./... && \
	   AAC_VERIFIER="$(CURDIR)/tmp/capsule-verifier/bin/agent-action-capsule" $(NO_PAID_KEYS) $(SUITE_TEST) -race -count=1 ./...); $(SUITE_END)

## capsule-lock: recompile examples/capsule/requirements.txt from its requirements.in, every package pinned with hashes (pip-tools in tmp/piptools; needs the network)
capsule-lock:
	@[ -x tmp/piptools/bin/pip-compile ] || { python3 -m venv tmp/piptools && tmp/piptools/bin/pip install --quiet --disable-pip-version-check pip-tools; }
	tmp/piptools/bin/pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url -o examples/capsule/requirements.txt examples/capsule/requirements.in

.PHONY: receipt-suite
## receipt-suite: run examples/pr-receipt/receipt.sh end to end (docker, runsc, the containerd image store); a skipped test FAILS
receipt-suite:
	@$(SUITE_BEGIN) RECEIPT_SUITE=1 $(NO_PAID_KEYS) $(SUITE_TEST) ./examples/pr-receipt -run TestReceiptScriptEndToEnd -count=1; $(SUITE_END)

.PHONY: policy-suite
## policy-suite: the receipt verifier's policy gate on the Open Policy Agent release pinned in examples/pr-receipt/policy/opa.version (downloaded into tmp/tools once, its SHA-256 checked before it runs): the example policy's own tests and every refusal; a skipped test FAILS
policy-suite:
	@$(SUITE_BEGIN) opa="$$(sh examples/pr-receipt/policy/opa.sh "$$PWD/tmp/tools")" && \
	  PLIMSOLL_OPA="$$opa" $(SUITE_TEST) ./examples/pr-receipt -run ReceiptPolicyGate -count=1; $(SUITE_END)

# This nested module uses its embedded schemas and published signed bundle only.
# No sandbox is created and no hosted service or credential is used.
.PHONY: sbom-suite
## sbom-suite: vet and race-test examples/sbom offline; a skipped test FAILS
sbom-suite:
	@$(SUITE_BEGIN) (cd examples/sbom && $(NO_PAID_KEYS) go vet ./... && \
	   $(NO_PAID_KEYS) $(SUITE_TEST) -race -count=1 ./...); $(SUITE_END)

## mcp-suite: the MCP server's own module (clients/mcp): vet, lint, race tests (the real RPC handler over fake providers, the built binary over stdio) and govulncheck, since it ships as a binary; any skipped test FAILS
mcp-suite:
	@$(SUITE_BEGIN) (cd clients/mcp && $(NO_PAID_KEYS) go vet ./... && golangci-lint run ./... && \
	   $(NO_PAID_KEYS) $(SUITE_TEST) -race -count=1 ./... && govulncheck ./...); $(SUITE_END)

# The live E2B suite. E2B_LIVE_REQUIRED=1 is the opt-in to spend, which only this target
# sets, and under it a missing E2B_API_KEY fails instead of skipping, so a green run means
# the live service was exercised, as dockercloud-suite's DOCKERCLOUD_LIVE_REQUIRED does.
# The two guarded-egress tests match the selection by name and skip on purpose without
# their deployment's settings; they are e2b-guard-live's, so they are left out here by
# name, and any skip left is missing coverage, which fails the target.
## e2b-suite: the live E2B tests, the guarded-egress ones aside (e2b-guard-live runs those); a missing E2B_API_KEY or a skipped test FAILS (spends)
e2b-suite:
	@$(SUITE_BEGIN) E2B_LIVE_REQUIRED=1 env -u DOCKER_SBX_TOKEN $(SUITE_TEST) ./sandbox -run 'E2B.*Live' -skip '^TestE2B(Session)?GuardLive$$' -count=1; $(SUITE_END)

# The live Docker Cloud Sandboxes suite. DOCKERCLOUD_LIVE_REQUIRED=1 makes missing
# configuration fail instead of skip, so a green run means the live service was
# exercised. The provider is written against Docker's published contract; this
# target is how it gets verified against the real service. The tests in its selection
# that skip on purpose without settings of their own are left out by name
# (DOCKERCLOUD_SUITE_SKIP, above), so any skip left is missing coverage, which fails the
# target.
#
#   DOCKER_SBX_TOKEN              a Docker personal access token for automation
#   DOCKER_SBX_USERNAME           the account it belongs to
#   SANDBOX_DOCKERCLOUD_API       connect (default) or rest; run the suite once per API
#   SANDBOX_DOCKERCLOUD_API_URL   the management endpoint: required unless the API is rest
#   SANDBOX_DOCKERCLOUD_IMAGE     the toolchain image, pullable by the service, or
#   SANDBOX_DOCKERCLOUD_STORE_IMAGE  one in the account's image store (<id>@sha256:<digest>; connect)
#
## dockercloud-suite: the live Docker Cloud Sandboxes tests, the guarded-egress one aside (dockercloud-guard-live runs it); missing configuration or a skipped test FAILS (spends)
dockercloud-suite:
	@$(SUITE_BEGIN) DOCKERCLOUD_LIVE_REQUIRED=1 env -u E2B_API_KEY $(SUITE_TEST) ./sandbox -run 'DockerCloud.*Live' -skip '^($(DOCKERCLOUD_SUITE_SKIP))$$' -count=1; $(SUITE_END)

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
	@$(SUITE_BEGIN) OPENSHELL_LIVE=1 $(NO_PAID_KEYS) $(SUITE_TEST) ./sandbox/openshell -run 'Live' -count=1 && \
	   OPENSHELL_LIVE=1 $(NO_PAID_KEYS) $(SUITE_TEST) ./cmd/plimsolld -run 'OpenShell.*Live' -count=1; $(SUITE_END)

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
	SANDBOX_AGENTSANDBOX_SANDBOXD_CA_FILE SANDBOX_AGENTSANDBOX_SANDBOXD_SERVER_NAME \
	SANDBOX_MEMORY_MB SANDBOX_CPUS SANDBOX_DISK_MB SANDBOX_REQUIRE_PINNED_IMAGES
AGENTSANDBOX_FILES := SANDBOX_AGENTSANDBOX_CA_FILE SANDBOX_AGENTSANDBOX_TOKEN_FILE SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE \
	SANDBOX_AGENTSANDBOX_SANDBOXD_CA_FILE
# This suite runs its two compiled test programs itself, inside the cluster's network where one
# is given, so their output (-test.v=test2json) goes to the reader's stream mode, whose arguments
# repeat what each program was asked to run. A program that fails leaves a failed test in the
# results, and one that never started leaves none; either fails the suite.
## agentsandbox-suite: the live agent-sandbox provider and daemon tests; a missing cluster or a skipped test FAILS
agentsandbox-suite:
	@mkdir -p tmp/agentsandbox-suite
	@CGO_ENABLED=0 go test -c -o tmp/agentsandbox-suite/provider.test ./sandbox/agentsandbox
	@CGO_ENABLED=0 go test -c -o tmp/agentsandbox-suite/daemon.test ./cmd/plimsolld
	@$(SUITE_BEGIN) if [ -n "$(AGENTSANDBOX_NETWORK)" ]; then \
	     set --; \
	     for v in $(AGENTSANDBOX_SETTINGS); do [ -n "$$(printenv $$v)" ] && set -- "$$@" -e "$$v"; done; \
	     for v in $(AGENTSANDBOX_FILES); do f="$$(printenv $$v)"; [ -n "$$f" ] && set -- "$$@" -v "$$f:$$f:ro"; done; \
	     docker run --rm --network "$(AGENTSANDBOX_NETWORK)" --cap-add NET_ADMIN -e AGENTSANDBOX_LIVE=1 "$$@" \
	       -v "$(CURDIR)/tmp/agentsandbox-suite:/suite:ro" alpine:3 sh -c \
	       "ip route add $(AGENTSANDBOX_POD_ROUTE) && /suite/provider.test -test.run Live -test.count=1 -test.v=test2json && /suite/daemon.test -test.run 'AgentSandbox.*Live' -test.count=1 -test.v=test2json"; \
	   else \
	     AGENTSANDBOX_LIVE=1 $(NO_PAID_KEYS) tmp/agentsandbox-suite/provider.test -test.run Live -test.count=1 -test.v=test2json && \
	     AGENTSANDBOX_LIVE=1 $(NO_PAID_KEYS) tmp/agentsandbox-suite/daemon.test -test.run 'AgentSandbox.*Live' -test.count=1 -test.v=test2json; \
	   fi | $(SUITE_READER) stream ./sandbox/agentsandbox -run Live + ./cmd/plimsolld -run 'AgentSandbox.*Live'; $(SUITE_END)

# The WSL containers provider's live suites run on a Windows machine with WSL 3.0.5 or later,
# from a WSL distribution, by hand: CI's hosted Linux runners have no WSL, so no CI job runs
# them. They spend nothing (WSL containers run on the machine itself), and a missing
# configuration or a skipped test fails them. wslc-docker-check is the part any machine with
# docker can run: the shared mode's run path, plimsoll's runner and the smoke test's
# boundary test against a real container, through a stand-in for wslc.exe that answers with
# the local docker (sandbox/wslc/testdata/docker-standin.sh). It checks plimsoll's side of
# the path and is never evidence about WSL containers; make audit runs it with DOCKER=1. It
# leaves out the per-run tests, which need real Hyper-V sessions, and the environment canary,
# whose control starts a Windows program through interop.
#
#   SANDBOX_WSLC_IMAGE          the sandbox image, loaded into the WSL containers session
#   SANDBOX_WSLC_PATH           wslc.exe, when it is not at the default path
#   SANDBOX_WSLC_RUNSC_PATH, SANDBOX_WSLC_RUNSC_SHA512, SANDBOX_WSLC_RUNSC_HELPERS
#                               wslc-gvisor-suite only: the operator's runsc (docs/wslc.md)
#
## wslc-suite: the live WSL containers provider suite, by hand on a Windows machine from a WSL distribution; a missing configuration or a skipped test FAILS
wslc-suite:
	@$(SUITE_BEGIN) WSLC_LIVE=1 $(NO_PAID_KEYS) $(SUITE_TEST) ./sandbox/wslc -run '^TestLive' -count=1; $(SUITE_END)
## wslc-gvisor-suite: the live tests of gVisor inside each per-run WSL containers VM, by hand on a Windows machine from a WSL distribution; a missing configuration or a skipped test FAILS
wslc-gvisor-suite:
	@$(SUITE_BEGIN) WSLC_LIVE=1 $(NO_PAID_KEYS) $(SUITE_TEST) ./sandbox/wslc -run '^TestGVisorLive' -count=1 -timeout 30m; $(SUITE_END)
## wslc-docker-check: with DOCKER=1, the wslc provider's shared-mode run path and boundary test against the local docker through a stand-in for wslc.exe; a skipped test FAILS; never evidence about WSL containers
wslc-docker-check:
	@if [ "$(DOCKER)" = "1" ]; then $(SUITE_BEGIN) WSLC_LIVE=1 SANDBOX_WSLC_PATH=$(CURDIR)/sandbox/wslc/testdata/docker-standin.sh SANDBOX_WSLC_IMAGE=plimsoll/sandbox:latest $(NO_PAID_KEYS) $(SUITE_TEST) ./sandbox/wslc -run '^TestLive' -skip '^(TestLivePerRun|TestLiveEnvironmentCanary)' -count=1; $(SUITE_END); else echo "skip wslc-docker-check (set DOCKER=1)"; fi

# The guarded-egress path is the one claim `make audit E2B=1` cannot make: its live
# tests need three deployment-specific variables, so e2b-suite leaves them out by name.
# This target is the deliberate run, and it fails rather than skips when its
# configuration is missing.
#
#   E2B_API_KEY                 the account key
#   E2B_GUARD_URL               the externally reachable HTTPS guard route
#   E2B_LIVE_GRANT_BASE_URL     origin of a real HTTPS API to prove against
#   E2B_LIVE_GUARD_LISTEN       optional: local addr that self-serves the handler
#
## e2b-guard-live: prove the guarded E2B egress path; missing configuration or a skipped test FAILS (spends)
e2b-guard-live:
	@$(SUITE_BEGIN) E2B_GUARD_LIVE_REQUIRED=1 env -u DOCKER_SBX_TOKEN $(SUITE_TEST) ./sandbox -run 'TestE2BGuardLive|TestE2BSessionGuardLive' -count=1; $(SUITE_END)

# The live E2B session suite: the startup and session smoke tests, the session
# conformance suite and the guest's privileges, against the real service. It spends
# (a microVM per case, about 2 cents a pass at the template's size), so it runs only
# here, never in e2b-suite or the gate. E2B_TEMPLATE picks the template (default base).
## e2b-template-recipe: build plimsoll's E2B template recipe locally (e2b/e2b.Dockerfile; nothing reaches E2B, nothing is billed) and run the startup check and a session on it; a missing daemon or a skipped test FAILS
.PHONY: e2b-template-recipe
e2b-template-recipe:
	docker build -f e2b/e2b.Dockerfile -t plimsoll-local/e2b-template:dev e2b
	@$(SUITE_BEGIN) SANDBOX_TEST_REQUIRE_DOCKER=1 PLIMSOLL_E2B_TEMPLATE_IMAGE=plimsoll-local/e2b-template:dev $(NO_PAID_KEYS) $(SUITE_TEST) ./sandbox -run 'TestE2BTemplateRecipeOnALocalImage' -count=1 -timeout 10m; $(SUITE_END)

## e2b-session-live: prove E2B sessions against the live service, the daemon's unclaimed close included; a missing E2B_API_KEY or a skipped test FAILS (paid)
e2b-session-live:
	@$(SUITE_BEGIN) E2B_SESSION_LIVE=1 env -u DOCKER_SBX_TOKEN $(SUITE_TEST) ./sandbox -run 'TestLiveE2BSessions|TestLiveE2BSessionRoads|TestLiveE2BDaemonClosesAnUnclaimedSession' -count=1 -timeout 40m; $(SUITE_END)

## dockercloud-guard-live: prove a Docker Cloud host-API grant end to end on the Connect API (paid, well under a cent; needs a public guard route to this process, see TestDockerCloudGuardLive); missing configuration or a skipped test FAILS
dockercloud-guard-live:
	@$(SUITE_BEGIN) DOCKERCLOUD_GUARD_LIVE_REQUIRED=1 DOCKERCLOUD_LIVE_REQUIRED=1 env -u E2B_API_KEY $(SUITE_TEST) ./sandbox -run 'TestDockerCloudGuardLive' -count=1 -timeout 10m; $(SUITE_END)


# The website targets that used to sit here drove the commercial site's local stack
# through scripts/ , which is private and does not ship. In a public clone they were
# advertised by `make help` and failed with "No such file or directory". The scripts
# are documented directly in the private docs/website-runbook.md; a Makefile is the
# wrong place for a target only half the tree can run.

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
