# Run authz-agent under Docker

`compose.yaml` runs the agent from its image with Docker Compose, without Kubernetes, on `linux/amd64` or
`linux/arm64`. Outside Kubernetes the agent works in the M2M mode `legacy`, so it accepts the tokens of the providers
in `authz/trusted-providers.json` and no Kubernetes service account token. It gets its own token from the identity
provider with client credentials.

| File | What it holds |
| --- | --- |
| `compose.yaml` | The service: image, ports, mounts, stop grace period, healthcheck, restart policy |
| `agent.env` | The settings of the agent and of the entrypoint of its image, each with its default and what it does |
| `authz/trusted-providers.json` | The identity providers whose tokens the agent accepts |
| `secret/username`, `secret/password` | The client id and secret of the agent; you create them, git ignores them |

## Before you start

- Docker Engine 28.3.3 or later with the Docker Compose plugin, whose `up` command takes `--wait`. An earlier Engine can
  let another host on the network reach a port published on `127.0.0.1`.
- A host clock synchronized over NTP. The agent compares the expiry and the not-before time of each token with the
  host clock, so a clock that drifts makes it refuse valid tokens or accept expired ones.
- A Keycloak that the container can reach, with a client of the agent in the `cloud-common` realm that may use the
  client credentials grant.
- The base URL of the policy source that the agent pulls its policies from.
  [Policy source](../../README.md#policy-source) lists the sources the agent supports.

## Start the agent

1. Copy this directory to the host.
2. In `authz/trusted-providers.json`, set `issuer` to the issuer of the `cloud-common` realm, which is the `iss` claim
   of its tokens, such as `https://keycloak.example.com/auth/realms/cloud-common`. Add one provider for each further
   issuer whose tokens the agent accepts. The `id` of a provider names the provider in the log lines of the agent,
   and in the details of `/ready` while the provider is marked `"required": true` and has no keys. Each `id` is
   unique in the file and holds only ASCII letters, digits, `.`, `_`, and `-`. With
   `AUTHZ_JWKS_BOOTSTRAP_REQUIRED=true`, the default, the agent needs the keys of every provider before it is ready.
   With `false`, it needs the keys of one provider and of every provider marked `"required": true`.
3. Put the client id of the agent in `secret/username` and its client secret in `secret/password`. The agent runs as
   uid 10001, so that uid has to be able to enter the directory and read each file in it, for example with
   `chmod 0400 secret/*`, `chmod 0500 secret`, and then `sudo chown -R 10001 secret`. With `user:` set in
   `compose.yaml`, give that user the same access instead.
4. In `agent.env`, set `AUTHZ_M2M_TOKEN_URL` to the token endpoint of the `cloud-common` realm and
   `AUTHZ_PAP_CLIENT_SOURCE_URL` to the base URL of the policy source. Over `http`, anyone on the network path can
   read the client secret and the token of the agent, and can send the agent keys, realms, or policies of their own.
   Give the issuers of step 2 and `AUTHZ_M2M_TOKEN_URL` the `https` scheme. Give `AUTHZ_PAP_CLIENT_SOURCE_URL`,
   `AUTHZ_TENANT_MANAGER_URL`, and `AUTHZ_ENTITLEMENTS_URL` the `https` scheme too wherever their service runs on
   another host or on a network that others share. A service without TLS of its own, such as
   `authz-policy-admin`, runs behind a proxy that terminates TLS, or on a network that only it and the agent share.
5. Start the agent and wait until it is ready:

   ```bash
   docker compose up --detach --wait
   ```

6. Check its state:

   ```bash
   curl http://127.0.0.1:8181/ready
   ```

   `/ready` answers 200 once the trusted providers have their keys and the first policies are loaded, and 503 with the
   reason until then.

A value that the row of its variable in the [configuration table](../../components/authz-agent/README.md#configuration)
does not accept, such as `AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s`, stops the start: the container exits with status 1,
Docker restarts it under the restart policy, and `docker compose up --wait` reports it as unhealthy.
`docker compose logs authz-agent` shows a line that names each such variable with the values it accepts.

After you change `agent.env` or `compose.yaml`, run `docker compose up --detach` again: it recreates the container with
the new settings. `docker compose restart` keeps the old ones.

## Trust a private CA

The agent trusts the public CAs of its image for the HTTPS servers it calls: Keycloak, tenant-manager, the policy
source, and the PIPs. To add the CA of your installation, put its certificate in a `.crt`, `.cer`, or `.pem` file in a
directory `ca` beside `compose.yaml`. The user the agent runs as, uid 10001 or the one that `user:` sets, has to be able
to list `ca` and read each file in it, as for `secret` in step 3: the entrypoint skips a certificate it cannot read,
and the agent starts without it. Then add a mount of that directory at `/tmp/cert` under `volumes`, and run
`docker compose up --detach`:

```yaml
      - ./ca:/tmp/cert:ro
```

The entrypoint of the image builds the trust store at each start, from the CAs of the image and the certificates under
`/tmp/cert`, in the `tmpfs` directories that `compose.yaml` mounts. After you add, replace, or remove a certificate
under `ca`, or change its permissions, restart the agent:

```bash
docker compose restart
```

[Trusting a private CA](../../components/authz-agent/README.md#trusting-a-private-ca) describes which files the
entrypoint reads.

## TLS

The agent serves plain HTTP on both ports, so a reverse proxy in front of the public port, `8080`, terminates TLS.
`compose.yaml` publishes both ports on `127.0.0.1` alone, where a proxy that runs on the host reaches them. A proxy in a
container on the same host reaches the agent over the Compose network at `http://authz-agent:8080`, with no port
published for it: run it as a service in a Compose override file, or attach its container to the network
`authz-agent_default`. A proxy on another host needs the public port published on an interface that host reaches:
change the line of `8080` under `ports`. A port that Docker publishes bypasses the rules of ufw and firewalld, so
publish the public port only where the proxy reaches it, and keep the internal port, `8181`, on `127.0.0.1`: it serves
the metrics and the probes to anyone who reaches it.

## Stop and restart

`docker compose stop` gives the agent the 30 seconds that `stop_grace_period` sets. The entrypoint of the image passes
`SIGTERM` on after `SIGTERM_EXIT_DELAY` seconds, which `agent.env` sets to `0`, and the agent then takes up to 10
seconds to finish the requests in flight. `stop_grace_period` has to exceed `SIGTERM_EXIT_DELAY` by more than those 10
seconds, or Docker kills the agent before it stops.
[Stopping the agent](../../components/authz-agent/README.md#stopping-the-agent) describes the delay.

`restart: unless-stopped` restarts the agent when the process exits. Docker does not restart a container that its
healthcheck marks unhealthy, so the monitoring of the installation has to act on that state. When a provider does not
answer while the agent starts, the agent fetches its keys again only after `authz/trusted-providers.json` changes or
the container restarts: once Keycloak answers, run `docker compose restart authz-agent`.

## Settings

`agent.env` sets every variable of the [configuration table](../../components/authz-agent/README.md#configuration),
and the table describes each of them. Each holds its default or a placeholder, except `SIGTERM_EXIT_DELAY`, which this
example sets to `0` (see [Stop and restart](#stop-and-restart)). `agent.env` also sets `M2M_AUTH_MODE`, which the agent
does not read yet and the table does not list.
