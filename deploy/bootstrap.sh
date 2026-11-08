#!/usr/bin/env bash
# One-time setup of an Ubuntu 24.04 Vultr VM for Airlock. Run as root, after the
# repository has been copied to /opt/airlock:
#   bash /opt/airlock/deploy/bootstrap.sh --host <name> --model <id> --price-in <usd/Mtok> --price-out <usd/Mtok>
# The inference API key is read from stdin (never from argv), e.g.
#   read -rs K && printf '%s' "$K" | bash bootstrap.sh ...
# --dry-run prints the steps without changing the machine.
set -euo pipefail

HOST="" MODEL="" PIN="" POUT="" DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --price-in) PIN="$2"; shift 2 ;;
    --price-out) POUT="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$HOST" ] && [ -n "$MODEL" ] && [ -n "$PIN" ] && [ -n "$POUT" ] || { echo "need --host --model --price-in --price-out" >&2; exit 2; }
[[ "$HOST" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "bad --host" >&2; exit 2; }
[[ "$MODEL" =~ ^[A-Za-z0-9._/:-]+$ ]] || { echo "bad --model" >&2; exit 2; }
[[ "$PIN" =~ ^[0-9]+(\.[0-9]+)?$ && "$POUT" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "bad price" >&2; exit 2; }

APP=/opt/airlock
run() { if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }

[ -f "$APP/airlock/service/__main__.py" ] || { echo "copy the repository to $APP first" >&2; exit 2; }

if [ "$DRY" = 0 ]; then
  KEY="$(cat)"; [ -n "$KEY" ] || { echo "no API key on stdin" >&2; exit 2; }
fi

# 1. Packages: Docker, gVisor, Caddy.
run apt-get update
run apt-get install -y docker.io python3 curl gnupg debian-keyring debian-archive-keyring apt-transport-https
run sh -c 'curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg'
run sh -c 'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list'
run sh -c 'curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg'
run sh -c 'curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list'
run apt-get update
run apt-get install -y runsc caddy
run runsc install
run systemctl restart docker

# 2. Service user, data directory, sandbox image.
id airlock >/dev/null 2>&1 || run useradd --system --home /var/lib/airlock --shell /usr/sbin/nologin airlock
run usermod -aG docker airlock
run install -d -o airlock -g airlock -m 0700 /var/lib/airlock
run docker build -t airlock-sandbox:dev "$APP/sandbox-image"

# 3. Config and key.
run install -d -o root -g airlock -m 0750 /etc/airlock
if [ "$DRY" = 0 ]; then
  sed -e "s#__HOST__#$HOST#" -e "s#__MODEL__#$MODEL#" -e "s#__PRICE_IN__#$PIN#" -e "s#__PRICE_OUT__#$POUT#" \
    "$APP/deploy/config.template.json" > /etc/airlock/config.json
  (umask 077; printf '%s' "$KEY" > /etc/airlock/inference.key)
  chown root:airlock /etc/airlock/config.json; chown airlock:airlock /etc/airlock/inference.key
  chmod 0640 /etc/airlock/config.json; chmod 0400 /etc/airlock/inference.key   # the service rejects any group/other bit on the key
  unset KEY
else
  echo "+ render /etc/airlock/config.json; write /etc/airlock/inference.key (0400 airlock:airlock)"
fi

# 4. Units.
run install -m 0644 "$APP/deploy/airlock.service" /etc/systemd/system/airlock.service
if [ "$DRY" = 0 ]; then sed "s#__HOST__#$HOST#" "$APP/deploy/Caddyfile" > /etc/caddy/Caddyfile; else echo "+ render /etc/caddy/Caddyfile"; fi
run caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
run systemctl daemon-reload
run systemctl enable --now airlock
run systemctl restart caddy

# 5. Checks.
run sh -c 'docker run --rm --runtime=runsc --network=none airlock-sandbox:dev dmesg | grep -q gVisor && echo "gVisor: ok"'
run systemctl --no-pager --lines=5 status airlock
echo "done. Open https://$HOST/"
