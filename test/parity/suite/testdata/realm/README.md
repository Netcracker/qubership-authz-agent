# Users of the parity realm

Each `*.json` file here is an array of Keycloak user representations that the test stand adds to the `parity` realm of
[`test/k8s/parity/idp-seed/parity-realm.json`](../../../../k8s/parity/idp-seed/parity-realm.json). The stage
`chart-files` of [`build/authz-agent-transfer/Dockerfile`](../../../../../build/authz-agent-transfer/Dockerfile) merges
them, fills in the first name, last name, and email that Keycloak requires for a password grant, and fails when two
files declare the same username or id.
