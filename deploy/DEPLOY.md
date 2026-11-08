# Deploying Airlock on Vultr

One Ubuntu 24.04 cloud compute VM runs everything: Caddy (TLS, static `web/`, `/api` proxy),
the Airlock service on `127.0.0.1:8080`, and Docker with gVisor (`runsc`) for the per-task sandboxes.
The agent's model calls go to Vultr Serverless Inference (`https://api.vultrinference.com/v1`).

## Steps

1. Create the VM (Ubuntu 24.04, 2 vCPU / 2 GB is enough with `max_running` 1; use 4 GB for 2 parallel tasks) and point a DNS name at it
   (or use `<ip-with-dashes>.sslip.io`). Open ports 22, 80, 443 only.
2. Copy the code, leaving out working notes:
   `rsync -a --exclude .git --exclude HANDOFF.md --exclude docs/design/ ./ root@<vm>:/opt/airlock/`
3. On the VM, as root, with the inference key typed at a hidden prompt:
   `read -rs K && printf '%s' "$K" | bash /opt/airlock/deploy/bootstrap.sh --host <name> --model <model-id> --price-in <usd> --price-out <usd>; unset K`
   (`--dry-run` lists the steps first.)
4. Check: the script prints `gVisor: ok`; open `https://<name>/`, run the *fix the bug* preset and the
   *try-memory* preset; `curl -sI https://<name>/api/v1/samples` returns 200.

## Limits worth knowing

- Caddy cuts request headers after 5 s and bodies after 10 s, and caps `/api` bodies at 16 KB.
  The service's own socket timeout bounds each read, not a whole request, so these proxy limits matter.
- `quotas.usd_cap` in the template is 1.5 USD (lifetime model spend); the service stops admitting tasks once spend reaches it.
- `quotas.max_running` is 1: one sandbox at a time keeps a 2 GB VM within memory (each sandbox is capped at 512 MB).
- Vultr bills the VM by the hour until it is destroyed and does not stop it when credit runs out, so put the teardown date in your calendar when you deploy.

## Teardown

1. `systemctl disable --now airlock caddy`
2. `docker ps -aq --filter label=airlock=1 | xargs -r docker rm -f`
3. Destroy the VM and any snapshot in the Vultr console; revoke the inference API key.
