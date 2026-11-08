# Airlock: a blast-radius-zero sandbox for coding agents

Built for the **Vultr Agent Rush** hackathon, challenge 01 *Blast Radius Zero*.

**Live demo:** <https://45-76-246-68.sslip.io/> (online until Nov 12, 2026) · **Video (2:54):** <https://github.com/franciseliang99-dot/airlock-sandbox/releases/download/v1.0/airlock-demo.mp4>

When an AI agent writes and runs code for you, the worst case is not a wrong answer. It is the
agent reaching your network, your credentials or your machine. Airlock gives every task its own
throwaway sandbox with no network, no secrets and hard resource limits. It shows you, step by
step, what the agent tried and what the sandbox stopped. The agent's changes come back as a
patch, and you can download that patch only after you approve it.

## Try it

Open the demo, pick a sample repository and a preset, and press **Run**:

| Preset | What the agent is asked to do | What you should see |
|---|---|---|
| Fix the failing tests | Run the tests, fix the bug, re-run | Passing tests and a reviewable diff |
| Try to reach the internet | Download `https://example.com/` | The request fails: the sandbox has no network |
| Allocate too much memory | Allocate about 900 MB | The memory limit stops it, and the report names the limit |
| Look for credentials | List environment variables and home files | Nothing to find: the sandbox receives no secrets |
| Start many background processes | Start 1,000 `sleep` processes | The process limit stops it |

You can also write your own instruction (up to 2,000 characters) against the bundled samples.
Visitors cannot upload files, and nothing anyone submits is shown to other visitors.

## Vultr services used

- **Vultr Cloud Compute**: one Ubuntu 24.04 VM runs the whole application. That includes the web
  front end, the API, the agent loop, and Docker with the gVisor runtime for the sandboxes.
- **Vultr Serverless Inference** (`https://api.vultrinference.com/v1`, OpenAI-compatible): every
  model call the agent makes goes here. The inference key lives only on the VM, outside every sandbox.

## Architecture

```
browser ──HTTPS──▶ Caddy (TLS, static web/, /api proxy: 16 KB body cap, 5 s header / 10 s body timeouts)
                     │
                     ▼
               Airlock service (127.0.0.1:8080, Python stdlib HTTP + SQLite)
               ├─ sessions, per-session / per-IP / global quotas, USD spend cap
               ├─ scheduler (bounded running + queued tasks)
               ├─ agent loop ──HTTPS──▶ Vultr Serverless Inference
               │     closed tool set: list_dir · read_file · write_file · run_command · finish
               └─ sandbox runner ──docker──▶ one gVisor container per task
                                              (destroyed when the task ends, with proof)
```

1. **Session.** The first visit gets an anonymous session: a random token, stored hashed, valid for 12 hours.
2. **Task.** You pick a bundled sample and a preset, or type an instruction. The service checks your
   quotas and the global spend cap before it accepts the task.
3. **Agent loop.** The model plans, using a closed set of five tools. Every step is limited (25 steps,
   5 minutes in total, 60 seconds per command) and every token is charged against the budget. Tool
   output goes back to the model as data, not as instructions.
4. **Sandbox.** Each tool call runs inside the task's own container. When the task ends, the service
   computes a diff against the starting point, removes the container and checks that it is gone.
5. **Report and review.** The page polls an event stream that shows each step and each blocked action.
   The report shows which limits were hit. The patch stays locked until you approve it.
6. **Retention.** Task records are purged within 24 hours.

## How the isolation works

Every sandbox is a fresh container started with:

| Control | Setting |
|---|---|
| Kernel boundary | gVisor (`--runtime=runsc`): the agent's code talks to a user-space kernel, not the host kernel |
| Network | `--network none` |
| Credentials | none: no inherited environment, no `docker.sock`, no API keys; the inference key stays in the service |
| Privileges | `--cap-drop ALL`, `no-new-privileges`, unprivileged user `1000:1000`, `--ipc none` |
| File system | read-only root; writable `/work` (200 MB tmpfs) and `/tmp` (16 MB tmpfs) only |
| Memory | 512 MB, no swap |
| CPU | 1 CPU |
| Processes | 256 (gVisor's own threads count against this limit) |
| Time | 60 s per command, 5 min per task, plus a host-side backstop |
| Lifetime | one task; the container is removed and its absence is verified |

What the sandbox reports is treated as a hint, not proof. For example, code inside the sandbox can
fake a "limit hit". The guarantees come from the container settings above, not from the report.

## Run it locally

You need Linux with Docker and gVisor (`runsc` registered as a Docker runtime). On macOS, a Linux VM
such as colima works.

```bash
docker build -t airlock-sandbox:dev sandbox-image
python3 -m unittest discover -s tests -v     # integration tests are skipped if runsc is missing
```

To run the service, fill in `deploy/config.template.json` (use any OpenAI-compatible endpoint for
development) and start `python3 -m airlock.service --config <path>`. Then serve `web/` and proxy
`/api` to it, as `deploy/Caddyfile` does.

To deploy on Vultr, follow `deploy/DEPLOY.md`. It covers the VM, the bootstrap script (which reads
the inference key from stdin) and teardown.

## Who would pay for this, and what comes next

- **Who:** teams that want to let coding agents run against their repositories but cannot let an
  agent near production credentials or the internal network. Examples are platform teams, security-conscious
  startups and agencies that run agents on client code.
- **How it makes money:** a hosted sandbox API billed per task-minute, plus a self-hosted license for
  companies that must keep code on their own Vultr account.
- **Next:** bring-your-own repository through a scoped, read-only Git integration · per-team network
  allow-lists for package registries · signed, tamper-evident run reports · sandboxes on GPU instances
  for agents that train or evaluate models.

## License

MIT, see `LICENSE`.
