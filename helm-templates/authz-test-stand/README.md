# authz-test-stand

The test stand of the authz-agent suites, as a Helm chart: Keycloak with the test realms, instances of the pip-stub
image for the PIP, entitlements, and other stubs, the tenant-manager emulator, the M2M client-credentials Secret, and a
suite Job that `helm test` runs. It is a test fixture, not a production chart. Every part is off by default; the [values
file](values.yaml) describes each one.

Every Pod runs as the non-root user its image names, with the runtime's default seccomp profile, no privilege
escalation, and every capability dropped, so the stand starts in a namespace that enforces the `restricted` Pod Security
Standard. Each container except Keycloak has a read-only root filesystem: Keycloak writes its dev-mode database and its
Quarkus build under `/opt/keycloak` at start.

The kind harnesses install it with [`test/k8s/test-stand-values.yaml`](../../test/k8s/test-stand-values.yaml) (the
runtime suite) and [`test/k8s/parity/test-stand-values.yaml`](../../test/k8s/parity/test-stand-values.yaml) (the parity
suite); see [`test/k8s/README.md`](../../test/k8s/README.md).

## Generated files

The chart reads the realm files and the pip-stub rule files from `files/`, which git does not track. In a checkout,
generate them before you install or lint the chart:

```bash
make test-stand-files
```

The stage `chart-files` of [`build/authz-agent-transfer/Dockerfile`](../../build/authz-agent-transfer/Dockerfile) writes
them: the realms of `test/k8s/authn/` under `files/realms/e2e/`, the realms of `test/k8s/parity/idp-seed/` with the
users of `test/parity/suite/testdata/realm/` under `files/realms/parity/`, and the rule files of
`test/integration/pipstub/config/` under `files/pip-stub/`. Without them, an install that turns Keycloak or a stub with
a rule file on fails with ``no realm files under files/realms/<realms>/: run `make test-stand-files` …`` or
``no file files/pip-stub/<file>: run `make test-stand-files` …``.

## Install from the transfer image

The release publishes the image `ghcr.io/netcracker/qubership-authz-agent-transfer` with the three charts of this
repository under `/charts/`, and this chart's `files/` already generated. The images the chart runs,
`qubership-authz-pip-stub` and `qubership-authz-parity-suite`, are published under the same version; the tenant-manager
emulator is not published.

1. Copy the charts out of the image:

   ```bash
   docker create --name authz-charts ghcr.io/netcracker/qubership-authz-agent-transfer:<version> true
   docker cp authz-charts:/charts ./charts
   docker rm authz-charts
   ```

2. Install the stand with a values file of your own. Start from
   [`test/k8s/parity/test-stand-values.yaml`](../../test/k8s/parity/test-stand-values.yaml) and change what is
   specific to kind:

   - delete `TAG`, `IMAGE_PULL_POLICY`, `pipStub.imageRepository`, and `suite.imageRepository`, so the chart pulls
     the published images and `--set TAG` picks their version;
   - change the addresses in `suite.env` to the services of your stand;
   - turn `idp.enabled` off where the stand has its own Keycloak with the parity realms, and `clientCredentials.enabled`
     off where the platform provisions the client-credentials Secret.

   ```bash
   helm upgrade --install authz-test-stand ./charts/authz-test-stand --set TAG=<version> -f my-test-stand-values.yaml
   ```

3. Run the suite, then print its log. `helm test --logs` prints the logs of test Pods only, and the suite is a Job:
   Helm 4.3 and later print nothing for it, and earlier releases, Helm 3 included, fail with
   `unable to get pod logs`. The Job is named by `suite.name`.

   ```bash
   helm test authz-test-stand --timeout 15m
   kubectl logs job/parity-suite
   ```

`helm test` exits non-zero when the suite fails, and deletes the Job of the previous run before it starts a new one. It
waits no longer than `--timeout`. Three limits bound a run, each no lower than the one before: `-test.timeout` in
`suite.args`, `suite.activeDeadlineSeconds`, and `--timeout`. The chart supports Helm 3.19 or later, or Helm 4.x,
except that Helm 4.0.0 to 4.1.0 do not end `helm test` when the Job fails and wait out `--timeout`; the Makefile
targets stop it themselves, and by hand use Helm 3, or Helm 4.1.1 or later.
