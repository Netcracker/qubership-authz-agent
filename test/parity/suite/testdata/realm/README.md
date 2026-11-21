# Users of the parity realm

Each `*.json` file here is an array of Keycloak user representations that the test stand adds to the `parity` realm of
[`test/k8s/parity/idp-seed/parity-realm.json`](../../../../k8s/parity/idp-seed/parity-realm.json). The stage
`chart-files` of [`build/authz-agent-transfer/Dockerfile`](../../../../../build/authz-agent-transfer/Dockerfile) merges
them, fills in the first name, last name, and email that Keycloak requires for a password grant where a user
declares none, and fails when two files declare the same username or id.

## Service-account users

A user with `serviceAccountClientId` is the service account of that client and keeps the id the file gives it, so the
`sub` of the client's tokens is the same on every stand. The merge gives such a user no first name, last name, or
email, as Keycloak gives none to the service-account user it creates for a client. `round72-service-account-users.json`
holds the service account of `parity-ts-service`, which `c72-service-id-filter` of round 72 reads as `${subject.id}`.

On a stand that adds these files by hand, add this user with the realm's partial import after the clients of
`../realm-clients/` exist, or in the same request as them, since a partial import creates the clients before the
users:

```json
{
  "ifResourceExists": "OVERWRITE",
  "users": [
    {
      "id": "00000000-0000-0000-0000-000000007203",
      "username": "service-account-parity-ts-service",
      "enabled": true,
      "serviceAccountClientId": "parity-ts-service"
    }
  ]
}
```

- `OVERWRITE` replaces the service-account user that Keycloak created for the client with a generated id. `SKIP`
  keeps that user, and the generated id with it.
- The import fails with `Unable to find client specified for service account link. Client: parity-ts-service` when the
  client does not exist yet.
- The client lists the `service_account` client scope, which puts `client_id` into its tokens. Keycloak assigns that
  scope itself only when it creates the service-account user, so a client added without it and linked to this user
  issues tokens without `client_id`.
