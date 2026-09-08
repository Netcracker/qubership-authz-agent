# copy-policies: copy Rego source files from policies/ into the chart's
# generated directory so that helm template / helm package produces a
# non-empty policy ConfigMap.
#
# charts/authz-agent/files/opa/policies/ is gitignored — populate it with
# this target before running helm template, helm package or chart tests.
copy-policies:
	@mkdir -p charts/authz-agent/files/opa/policies
	@cp policies/*.rego charts/authz-agent/files/opa/policies/
	@echo "[copy-policies] copied $(shell ls policies/*.rego | wc -l | tr -d ' ') Rego files to charts/authz-agent/files/opa/policies/"

# lint: run all linters against the full tree (mirrors CI super-linter checks).
#
# Requires: golangci-lint, shellcheck, yamllint, npx (markdownlint-cli2),
#           python3, zizmor.  Install zizmor/yamllint: pip install yamllint zizmor
lint:
	@echo "[lint] Go — root module"
	golangci-lint run ./...
	@echo "[lint] Go — test/parity/suite"
	cd test/parity/suite && golangci-lint run ./...
	@echo "[lint] Go — test/integration/testify"
	cd test/integration/testify && golangci-lint run --build-tags integration ./...
	@echo "[lint] Go — test/integration/pipstub"
	cd test/integration/pipstub && golangci-lint run ./...
	@echo "[lint] Shell"
	find . -name '*.sh' -not -path './.git/*' | xargs shellcheck --severity=error
	@echo "[lint] YAML"
	find . \( -name '*.yml' -o -name '*.yaml' \) \
	    -not -path './.git/*' \
	    -not -path './node_modules/*' \
	    -not -path './charts/*/templates/*.yaml' \
	  | xargs $${YAMLLINT_BIN:-$${HOME}/.local/bin/yamllint} -c .github/linters/.yaml-lint.yml
	@echo "[lint] Markdown"
	npx --yes markdownlint-cli2 --config .github/linters/.markdown-lint.yml "**/*.md" "#node_modules" \
	    "#apm_modules" "#.agents" "#.claude/rules" "#.claude/skills" "#.cursor/rules"
	@echo "[lint] GitHub Actions (zizmor)"
	$${ZIZMOR_BIN:-$${HOME}/.local/bin/zizmor} --config .github/linters/zizmor.yaml \
	    .github/workflows/*.yaml .github/workflows/*.yml
	@echo "[lint] All checks passed."

# install-hooks: point git at the bundled hooks directory.
install-hooks:
	git config core.hooksPath .githooks
	@echo "[install-hooks] pre-commit hook active (core.hooksPath=.githooks)"

# ── kind end-to-end ──────────────────────────────────────────────────────────
# Install the chart on a kind cluster and run the runtime suite against it.
# `make e2e` runs every step; CI calls the same targets one by one. See
# test/k8s/README.md.
KIND_CLUSTER ?= authz-e2e
E2E_NAMESPACE ?= authz-e2e
E2E_ARTIFACTS ?= test/artifacts/kind
E2E_KUBECTL := kubectl --context kind-$(KIND_CLUSTER) -n $(E2E_NAMESPACE)
# Extra arguments for the chart install, for example
# E2E_HELM_ARGS='--set OPA_IMAGE=local/authz-agent:ci' to run the single service in
# place of the OPA container.
E2E_HELM_ARGS ?=
# Where the suites send their requests. The chart's Service fronts the Pod
# either way; http://authz-agent-direct:8080 is the public listener of the
# service standing in for the OPA container (test/k8s/authz-agent-direct.yaml),
# which is a manual aid rather than a target of its own.
E2E_BASE_URL ?= http://authz-agent:8080
PARITY_AC_BASE_URL ?= http://authz-agent:8080
# The topology the suite is told it runs against; e2e-single sets it.
E2E_SINGLE_SERVICE ?= false
E2E_AUTHN := test/k8s/authn
E2E_IMAGES := authz-agent authz-agent-pap-client authz-agent-envoy authz-agent-collector \
              authz-agent-token-fetcher authz-policy-admin pip-stub authz-runtime-suite \
              authz-parity-suite

e2e: e2e-cluster e2e-images e2e-harness e2e-install e2e-suite

e2e-cluster:
	kind get clusters | grep -qx $(KIND_CLUSTER) || kind create cluster --name $(KIND_CLUSTER) --wait 2m

# The images the chart and the harness reference as local/<name>:ci.
e2e-images:
	docker build -t local/authz-agent:ci               -f build/authz-agent/Dockerfile .
	docker build -t local/authz-agent-pap-client:ci    -f build/pap-client/Dockerfile .
	docker build -t local/authz-agent-envoy:ci         -f build/envoy/Dockerfile .
	docker build -t local/authz-agent-collector:ci     -f build/collector/Dockerfile .
	docker build -t local/authz-agent-token-fetcher:ci -f build/token-fetcher/Dockerfile .
	docker build -t local/authz-policy-admin:ci        -f build/authz-policy-admin/Dockerfile .
	docker build -t local/pip-stub:ci                  -f test/integration/pipstub/Dockerfile test/integration/pipstub
	docker build -t local/authz-runtime-suite:ci       -f test/integration/testify/Dockerfile .
	docker build -t local/authz-parity-suite:ci        -f test/parity/suite/Dockerfile test/parity/suite
	kind load docker-image --name $(KIND_CLUSTER) $(addprefix local/,$(addsuffix :ci,$(E2E_IMAGES)))

# Keycloak with the repository realm imports, the two stubs, and the M2M
# client-credentials Secret the chart expects the platform to provision.
e2e-harness:
	kubectl --context kind-$(KIND_CLUSTER) create namespace $(E2E_NAMESPACE) --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -
	$(E2E_KUBECTL) create configmap keycloak-realms --from-file=$(E2E_AUTHN)/authz-test-realm.json --from-file=$(E2E_AUTHN)/cloud-common-realm.json --dry-run=client -o yaml | $(E2E_KUBECTL) apply -f -
	$(E2E_KUBECTL) create secret generic authz-agent-client-credentials --from-file=username=$(E2E_AUTHN)/m2m-credentials/username --from-file=password=$(E2E_AUTHN)/m2m-credentials/password --from-literal=name=authz-agent --dry-run=client -o yaml | $(E2E_KUBECTL) apply -f -
	$(E2E_KUBECTL) apply -f test/k8s/keycloak.yaml -f test/k8s/pip-stub.yaml -f test/k8s/entitlements-mock.yaml -f test/k8s/authz-agent-direct.yaml
	$(E2E_KUBECTL) rollout status deploy/pip-stub --timeout=2m
	$(E2E_KUBECTL) rollout status deploy/entitlements-mock --timeout=2m
	$(E2E_KUBECTL) rollout status deploy/keycloak --timeout=10m

e2e-install: copy-policies
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-agent charts/authz-agent -n $(E2E_NAMESPACE) -f test/k8s/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

# Streams the suite log; the final wait turns the Job outcome into the exit code.
# The Job manifest carries the chart's Service and the five-container
# topology; sed swaps in E2E_BASE_URL and E2E_SINGLE_SERVICE.
e2e-suite:
	$(E2E_KUBECTL) delete job runtime-suite --ignore-not-found
	sed -e 's|value: http://authz-agent:8080$$|value: $(E2E_BASE_URL)|' \
	    -e '/name: SINGLE_SERVICE/{n;s|value: .*|value: "$(E2E_SINGLE_SERVICE)"|;}' \
	    test/k8s/runtime-suite-job.yaml | $(E2E_KUBECTL) apply -f test/k8s/runtime-suite-rbac.yaml -f -
	$(E2E_KUBECTL) wait --for=condition=Ready pod -l job-name=runtime-suite --timeout=3m
	$(E2E_KUBECTL) logs -f job/runtime-suite
	$(E2E_KUBECTL) wait --for=condition=Complete job/runtime-suite --timeout=1m

# The same chart with AUTHZ_SINGLE_SERVICE_ENABLED, so the Pod is the one
# container of ADR 0080, and the runtime suite against it. The Service and
# the Deployment keep their names, so the suite needs no address of its own;
# `make e2e-install` puts the five-container Pod back.
e2e-single: copy-policies
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-agent charts/authz-agent -n $(E2E_NAMESPACE) -f test/k8s/values.yaml --wait --timeout 5m --set AUTHZ_SINGLE_SERVICE_ENABLED=true $(E2E_HELM_ARGS)
	$(MAKE) e2e-suite E2E_SINGLE_SERVICE=true

# `make e2e-images` rebuilds the local images under the same tags, and a
# running Pod keeps the old content: the kubelet never re-reads a tag it
# already has. Restart every Deployment that runs a local image and wait until
# it is Ready again, so the next `e2e-suite` tests the new build. Keycloak is
# pulled, not built, and keeps running.
E2E_LOCAL_DEPLOYMENTS := authz-agent authz-agent-authz-policy-admin pip-stub entitlements-mock
e2e-restart:
	$(E2E_KUBECTL) rollout restart $(addprefix deploy/,$(E2E_LOCAL_DEPLOYMENTS))
	for d in $(E2E_LOCAL_DEPLOYMENTS); do $(E2E_KUBECTL) rollout status deploy/$$d --timeout=3m || exit 1; done

# Everything needed to read a failed run: every container log on the node,
# the namespace events, and the decision logs downloaded through Envoy.
e2e-logs:
	mkdir -p $(E2E_ARTIFACTS)
	kind export logs --name $(KIND_CLUSTER) $(E2E_ARTIFACTS)/cluster
	$(E2E_KUBECTL) get events --sort-by=.lastTimestamp > $(E2E_ARTIFACTS)/events.txt
	-$(E2E_KUBECTL) exec deploy/pip-stub -- wget -qO- http://authz-agent:8080/internal/v1/decision-logs > $(E2E_ARTIFACTS)/decision-logs.jsonl

e2e-down:
	kind delete cluster --name $(KIND_CLUSTER)

# ── parity replay on kind ────────────────────────────────────────────────────
# The parity suite (test/parity) against the chart, in its own namespace so its
# Keycloak realms and Service names match the Compose parity stack. Shares the
# cluster and the images with the e2e targets above.
PARITY_NAMESPACE ?= authz-parity
PARITY_KUBECTL := kubectl --context kind-$(KIND_CLUSTER) -n $(PARITY_NAMESPACE)
PARITY_SEED := test/k8s/parity/idp-seed

parity: e2e-cluster e2e-images parity-harness parity-install parity-suite

# Keycloak with the parity realm imports, the two stubs, and the M2M
# client-credentials Secret for the parity-m2m client of the cloud-common realm.
parity-harness:
	kubectl --context kind-$(KIND_CLUSTER) create namespace $(PARITY_NAMESPACE) --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -
	$(PARITY_KUBECTL) create configmap parity-realms --from-file=$(PARITY_SEED)/cloud-common-realm.json --from-file=$(PARITY_SEED)/parity-realm.json --dry-run=client -o yaml | $(PARITY_KUBECTL) apply -f -
	$(PARITY_KUBECTL) create configmap pip-mock-config --from-file=test/integration/pipstub/config/requestargs.responses.yaml --dry-run=client -o yaml | $(PARITY_KUBECTL) apply -f -
	$(PARITY_KUBECTL) create secret generic authz-agent-client-credentials --from-literal=username=parity-m2m '--from-literal=password=ParityM2MSecret1!@#' --from-literal=name=authz-agent --dry-run=client -o yaml | $(PARITY_KUBECTL) apply -f -
	$(PARITY_KUBECTL) apply -f test/k8s/parity/keycloak.yaml -f test/k8s/parity/pip-mock.yaml -f test/k8s/parity/entitlements-mock.yaml -f test/k8s/authz-agent-direct.yaml
	$(PARITY_KUBECTL) rollout status deploy/pip-mock --timeout=2m
	$(PARITY_KUBECTL) rollout status deploy/entitlements-mock --timeout=2m
	$(PARITY_KUBECTL) rollout status deploy/idp --timeout=10m

parity-install: copy-policies
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-agent charts/authz-agent -n $(PARITY_NAMESPACE) -f test/k8s/parity/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

# Streams the suite log; the final wait turns the Job outcome into the exit code.
# As e2e-suite: sed swaps PARITY_AC_BASE_URL into the Job manifest.
parity-suite:
	$(PARITY_KUBECTL) delete job parity-suite --ignore-not-found
	sed 's|value: http://authz-agent:8080$$|value: $(PARITY_AC_BASE_URL)|' test/k8s/parity/parity-suite-job.yaml | $(PARITY_KUBECTL) apply -f -
	$(PARITY_KUBECTL) wait --for=condition=Ready pod -l job-name=parity-suite --timeout=3m
	$(PARITY_KUBECTL) logs -f job/parity-suite
	$(PARITY_KUBECTL) wait --for=condition=Complete job/parity-suite --timeout=1m

# As e2e-single, in the parity namespace, with the parity replay.
parity-single: copy-policies
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-agent charts/authz-agent -n $(PARITY_NAMESPACE) -f test/k8s/parity/values.yaml --wait --timeout 5m --set AUTHZ_SINGLE_SERVICE_ENABLED=true $(E2E_HELM_ARGS)
	$(MAKE) parity-suite

# The parity counterpart of e2e-restart, for the same reason.
PARITY_LOCAL_DEPLOYMENTS := authz-agent authz-agent-authz-policy-admin pip-mock entitlements-mock
parity-restart:
	$(PARITY_KUBECTL) rollout restart $(addprefix deploy/,$(PARITY_LOCAL_DEPLOYMENTS))
	for d in $(PARITY_LOCAL_DEPLOYMENTS); do $(PARITY_KUBECTL) rollout status deploy/$$d --timeout=3m || exit 1; done

parity-logs:
	mkdir -p $(E2E_ARTIFACTS)/parity
	kind export logs --name $(KIND_CLUSTER) $(E2E_ARTIFACTS)/parity/cluster
	$(PARITY_KUBECTL) get events --sort-by=.lastTimestamp > $(E2E_ARTIFACTS)/parity/events.txt
	-$(PARITY_KUBECTL) exec deploy/pip-mock -- wget -qO- http://authz-agent:8080/internal/v1/decision-logs > $(E2E_ARTIFACTS)/parity/decision-logs.jsonl

.PHONY: copy-policies lint install-hooks e2e e2e-cluster e2e-images e2e-harness e2e-install e2e-suite e2e-single e2e-restart e2e-logs e2e-down parity parity-harness parity-install parity-suite parity-single parity-restart parity-logs
