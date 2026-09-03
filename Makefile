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
	npx --yes markdownlint-cli2 --config .github/linters/.markdown-lint.yml "**/*.md" "#node_modules"
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
E2E_AUTHN := test/integration/runtime/authn/keycloak
E2E_IMAGES := authz-agent-pap-client authz-agent-envoy authz-agent-collector \
              authz-agent-token-fetcher authz-policy-admin pip-stub authz-runtime-suite

e2e: e2e-cluster e2e-images e2e-harness e2e-install e2e-suite

e2e-cluster:
	kind get clusters | grep -qx $(KIND_CLUSTER) || kind create cluster --name $(KIND_CLUSTER) --wait 2m

# The images the chart and the harness reference as local/<name>:ci.
e2e-images:
	docker build -t local/authz-agent-pap-client:ci    -f build/pap-client/Dockerfile .
	docker build -t local/authz-agent-envoy:ci         -f build/envoy/Dockerfile .
	docker build -t local/authz-agent-collector:ci     -f build/collector/Dockerfile .
	docker build -t local/authz-agent-token-fetcher:ci -f build/token-fetcher/Dockerfile .
	docker build -t local/authz-policy-admin:ci        -f build/authz-policy-admin/Dockerfile .
	docker build -t local/pip-stub:ci                  -f test/integration/pipstub/Dockerfile test/integration/pipstub
	docker build -t local/authz-runtime-suite:ci       -f test/integration/testify/Dockerfile .
	kind load docker-image --name $(KIND_CLUSTER) $(addprefix local/,$(addsuffix :ci,$(E2E_IMAGES)))

# Keycloak with the repository realm imports, the two stubs, and the M2M
# client-credentials Secret the chart expects the platform to provision.
e2e-harness:
	kubectl --context kind-$(KIND_CLUSTER) create namespace $(E2E_NAMESPACE) --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -
	$(E2E_KUBECTL) create configmap keycloak-realms --from-file=$(E2E_AUTHN)/authz-test-realm.json --from-file=$(E2E_AUTHN)/cloud-common-realm.json --dry-run=client -o yaml | $(E2E_KUBECTL) apply -f -
	$(E2E_KUBECTL) create secret generic authz-agent-client-credentials --from-file=username=$(E2E_AUTHN)/m2m-credentials/username --from-file=password=$(E2E_AUTHN)/m2m-credentials/password --from-literal=name=authz-agent --dry-run=client -o yaml | $(E2E_KUBECTL) apply -f -
	$(E2E_KUBECTL) apply -f test/k8s/keycloak.yaml -f test/k8s/pip-stub.yaml -f test/k8s/entitlements-mock.yaml
	$(E2E_KUBECTL) rollout status deploy/pip-stub --timeout=2m
	$(E2E_KUBECTL) rollout status deploy/entitlements-mock --timeout=2m
	$(E2E_KUBECTL) rollout status deploy/keycloak --timeout=10m

e2e-install: copy-policies
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-agent charts/authz-agent -n $(E2E_NAMESPACE) -f test/k8s/values.yaml --wait --timeout 5m

# Streams the suite log; the final wait turns the Job outcome into the exit code.
e2e-suite:
	$(E2E_KUBECTL) delete job runtime-suite --ignore-not-found
	$(E2E_KUBECTL) apply -f test/k8s/runtime-suite-job.yaml
	$(E2E_KUBECTL) wait --for=condition=Ready pod -l job-name=runtime-suite --timeout=3m
	$(E2E_KUBECTL) logs -f job/runtime-suite
	$(E2E_KUBECTL) wait --for=condition=Complete job/runtime-suite --timeout=1m

# Everything needed to read a failed run: every container log on the node,
# the namespace events, and the decision logs downloaded through Envoy.
e2e-logs:
	mkdir -p $(E2E_ARTIFACTS)
	kind export logs --name $(KIND_CLUSTER) $(E2E_ARTIFACTS)/cluster
	$(E2E_KUBECTL) get events --sort-by=.lastTimestamp > $(E2E_ARTIFACTS)/events.txt
	-$(E2E_KUBECTL) exec deploy/pip-stub -- wget -qO- http://authz-agent:8080/internal/v1/decision-logs > $(E2E_ARTIFACTS)/decision-logs.jsonl

e2e-down:
	kind delete cluster --name $(KIND_CLUSTER)

.PHONY: copy-policies lint install-hooks e2e e2e-cluster e2e-images e2e-harness e2e-install e2e-suite e2e-logs e2e-down
