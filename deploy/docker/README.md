# Run authz-agent under Docker

`compose.yaml` runs the agent from its image with Docker Compose, without Kubernetes, on `linux/amd64` or
`linux/arm64`. Outside Kubernetes the agent works in the M2M mode `legacy`: it gets its own token from the identity
provider with client credentials, and it accepts no Kubernetes service account tokens.

| File | What it holds |
| --- | --- |
| `compose.yaml` | The service: image, ports, mounts, stop grace period, healthcheck, restart policy |
| `agent.env` | Every setting of the agent, each with its default and what it does |
| `authz/trusted-providers.json` | The identity provider realms whose tokens the agent accepts |
| `secret/username`, `secret/password` | The client id and secret of the agent; you create them, git ignores them |

## Before you start

- Docker Engine with the Docker Compose plugin, whose `up` command takes `--wait`.
- A host clock synchronized over NTP. The agent compares the expiry and the not-before time of each token with the
  host clock, so a clock that drifts makes it refuse valid tokens or accept expired ones.
- A Keycloak that the container can reach, with a client of the agent in the `cloud-common` realm that may use the
  client credentials grant.
- The base URL of the policy source that the agent pulls its policies from.

## Start the agent

1. Copy this directory to the host.
2. In `authz/trusted-providers.json`, set `issuer` to the issuer of the `cloud-common` realm, which is the `iss` claim
   of its tokens, such as `https://keycloak.example.com/auth/realms/cloud-common`. Add one entry for each further realm
   whose tokens the agent accepts. With `AUTHZ_JWKS_BOOTSTRAP_REQUIRED=true`, the default, the agent is ready once
   every realm has its keys; with `false`, once one realm and every realm marked `"required": true` have them.
3. Put the client id of the agent in `secret/username` and its client secret in `secret/password`. The agent runs as
   uid 10001, so each file has to be readable by that uid, for example with `chown 10001 secret/*` and
   `chmod 0400 secret/*`. With `user:` set in `compose.yaml`, make the files readable by that user instead.
4. In `agent.env`, set `AUTHZ_M2M_TOKEN_URL` to the token endpoint of the `cloud-common` realm and
   `AUTHZ_PAP_CLIENT_SOURCE_URL` to the base URL of the policy source.
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

A value of another form or outside its range, such as `AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s`, stops the start: the
container exits with status 1, Docker restarts it under the restart policy, and `docker compose up --wait` reports it
as unhealthy. `docker compose logs authz-agent` shows a line that names each such variable with the values it accepts.

After you change `agent.env` or `compose.yaml`, run `docker compose up --detach` again: it recreates the container with
the new settings. `docker compose restart` keeps the old ones.

## Trust a private CA

The agent calls Keycloak, the policy source, and the PIPs over HTTPS and trusts the public CAs of its image. To add the
CA of your installation, put its certificate in a `.crt`, `.cer`, or `.pem` file in a directory `ca` beside
`compose.yaml`, add a mount of that directory at `/tmp/cert` under `volumes`, and run `docker compose up --detach`:

```yaml
      - ./ca:/tmp/cert:ro
```

The entrypoint of the image adds the certificates to the trust store at each start, and the trust store lives in
volumes that the container keeps across restarts. A restart picks up a certificate that you replace under the same
file name. After you remove or rename one, recreate the container with fresh volumes, or the old certificate stays
trusted:

```bash
docker compose up --detach --force-recreate --renew-anon-volumes
```

[Trusting a private CA](../../components/authz-agent/README.md#trusting-a-private-ca) describes which files the
entrypoint reads.

## TLS

The agent serves plain HTTP on both ports. `compose.yaml` publishes them on `127.0.0.1` alone: put a reverse proxy on
the host in front of the public port, `8080`, to terminate TLS. To publish a port on another interface, change its
line under `ports`. A firewall rule on the host does not cover a port that Docker publishes, so publish the public port
only where the proxy reaches it, and keep the internal port, `8181`, on `127.0.0.1`: it serves the metrics and the
probes to anyone who reaches it.

## Stop and restart

`docker compose stop` gives the agent the 30 seconds that `stop_grace_period` sets. The entrypoint of the image passes
`SIGTERM` on after `SIGTERM_EXIT_DELAY` seconds, which `agent.env` sets to `0`, and the agent then takes up to 10
seconds to finish the requests in flight. `stop_grace_period` has to exceed `SIGTERM_EXIT_DELAY` by more than those 10
seconds, or Docker kills the agent before it stops. A container started with `docker run` instead needs a
`--stop-timeout` of the same length. [Stopping the agent](../../components/authz-agent/README.md#stopping-the-agent)
describes the delay.

`restart: unless-stopped` restarts the agent when the process exits. Docker does not restart a container that its
healthcheck marks unhealthy, so the monitoring of the installation has to act on that state.

## Settings

`agent.env` lists every setting of the agent with its default. The
[configuration table](../../components/authz-agent/README.md#configuration) describes them in full.
