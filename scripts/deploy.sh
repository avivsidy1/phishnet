#!/usr/bin/env bash
# Deploys backend/ to the EC2 instance and (re)starts it. Safe to re-run.
#
# Usage: [ALLOWED_EMAILS=a@x.com] [ALLOWED_AUDIENCES=id.apps.googleusercontent.com] \
#          scripts/deploy.sh <ec2-host> [domain]
#   ec2-host           Public DNS name or IP of the instance. Without an Elastic IP this changes
#                      every time the instance is stopped and started.
#   domain             Public HTTPS hostname. Default: <public-ip-with-dashes>.sslip.io
#   ALLOWED_EMAILS     Who may use the add-on: "*" (anyone), "*@domain.com", or a comma-separated list.
#   ALLOWED_AUDIENCES  OAuth client ID(s) of the add-on's Apps Script project (comma-separated).
#                      Both are stored in the server's .env; omit them to keep the current values.
#
# Env overrides: SSH_KEY (default ~/Downloads/instance-key.pem), SSH_USER (default ubuntu),
#   VT_SECRET_ARN: ARN of the AWS Secrets Manager secret holding the VirusTotal key (stored in .env; kept on
#     later runs). With an ARN set, any VT_API_KEY is removed from .env (KEEP_VT_API_KEY=1 keeps it, for the
#     transition). VT_SECRET_ARN=none removes the ARN: rollback to the key file below.
#   VT_KEY_FILE (default ~/.vt_api_key.txt): VirusTotal API key, copied to the server's .env only when no ARN is set.
set -euo pipefail

HOST="${1:?usage: $0 <ec2-host> [domain]}"
DOMAIN="${2:-}"
SSH_KEY="${SSH_KEY:-$HOME/Downloads/instance-key.pem}"
SSH_USER="${SSH_USER:-ubuntu}"
VT_KEY_FILE="${VT_KEY_FILE:-$HOME/.vt_api_key.txt}"
REMOTE_DIR="phish-scorer"  # folder on the server; keeps the pre-PhishNet name (Docker container/volume names derive from it)
BACKEND_DIR="$(cd "$(dirname "$0")/../backend" && pwd)"

ssh_run() {
  ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$SSH_USER@$HOST" "$@"
}

# Values below are embedded in a remote shell command and a config file: allow safe characters only.
require_match() {
  local name="$1" value="$2" pattern="$3"
  if ! [[ "$value" =~ $pattern ]]; then
    echo "Invalid $name: $value" >&2
    exit 1
  fi
}

if [ -z "$DOMAIN" ]; then
  # Ask the instance metadata service (IMDSv2) for the current public IP.
  ip=$(ssh_run 'token=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60");
                curl -s -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/public-ipv4')
  DOMAIN="${ip//./-}.sslip.io"
fi
require_match DOMAIN "$DOMAIN" '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'

env_updates="DOMAIN=$DOMAIN"
if [ -n "${ALLOWED_EMAILS:-}" ]; then
  require_match ALLOWED_EMAILS "$ALLOWED_EMAILS" '^[A-Za-z0-9._%+@,*-]+$'
  env_updates+=" ALLOWED_EMAILS=$ALLOWED_EMAILS"
fi
if [ -n "${ALLOWED_AUDIENCES:-}" ]; then
  require_match ALLOWED_AUDIENCES "$ALLOWED_AUDIENCES" '^[A-Za-z0-9._,-]+$'
  env_updates+=" ALLOWED_AUDIENCES=$ALLOWED_AUDIENCES"
fi

echo "==> Deploying to $HOST as https://$DOMAIN"

echo "==> Copying backend"
tar -C "$BACKEND_DIR" --exclude=.venv --exclude=__pycache__ --exclude=.pytest_cache --exclude=.env -czf - . \
  | ssh_run "mkdir -p ~/$REMOTE_DIR && tar -xzf - -C ~/$REMOTE_DIR"

# VirusTotal key source. Preferred: AWS Secrets Manager, read by the API with the instance role;
# only the ARN (not secret) is stored. VT_SECRET_ARN=none switches back to the key file (rollback).
if [ "${VT_SECRET_ARN:-}" = "none" ]; then
  ssh_run "cd ~/$REMOTE_DIR && touch .env && sed -i '/^VT_API_KEY_SECRET_ARN=/d' .env"
  echo "==> Removed the Secrets Manager ARN (rollback to the key file)"
elif [ -n "${VT_SECRET_ARN:-}" ]; then
  require_match VT_SECRET_ARN "$VT_SECRET_ARN" '^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$'
  ssh_run "cd ~/$REMOTE_DIR && umask 077 && touch .env && sed -i '/^VT_API_KEY_SECRET_ARN=/d' .env &&
    echo 'VT_API_KEY_SECRET_ARN=$VT_SECRET_ARN' >> .env"
fi

if ssh_run "grep -q '^VT_API_KEY_SECRET_ARN=.' ~/$REMOTE_DIR/.env 2>/dev/null"; then
  echo "==> VirusTotal key: AWS Secrets Manager, via the instance's IAM role"
  if [ "${KEEP_VT_API_KEY:-0}" = "1" ]; then
    echo "    keeping VT_API_KEY in .env too (KEEP_VT_API_KEY=1, transition only)"
  else
    ssh_run "sed -i '/^VT_API_KEY=/d' ~/$REMOTE_DIR/.env"
    echo "    no key stored on the server (removed any VT_API_KEY from .env)"
  fi
elif [ -f "$VT_KEY_FILE" ]; then
  # Legacy / rollback: sent on stdin, never as an argument or in output; stored in .env (umask 077).
  echo "==> VirusTotal key: installing from $VT_KEY_FILE into the server's .env"
  tr -d '\r\n' < "$VT_KEY_FILE" | ssh_run "cd ~/$REMOTE_DIR && umask 077 && touch .env && key=\$(cat) &&
    if ! [[ \"\$key\" =~ ^[A-Za-z0-9]+\$ ]]; then echo 'Invalid VirusTotal key format' >&2; exit 1; fi &&
    sed -i '/^VT_API_KEY=/d' .env && printf 'VT_API_KEY=%s\n' \"\$key\" >> .env"
else
  echo "==> VirusTotal key: no ARN and no $VT_KEY_FILE; keeping the server's VT_API_KEY (if any)"
fi

echo "==> Configuring and starting containers"
ssh_run "set -ef; cd ~/$REMOTE_DIR; umask 077; touch .env  # -f: no globbing, ALLOWED_EMAILS may be *
  sed -i '/^API_KEY=/d' .env   # replaced by Google identity tokens
  grep -q '^LOG_LEVEL=' .env || echo 'LOG_LEVEL=INFO' >> .env
  for kv in $env_updates; do
    sed -i \"/^\${kv%%=*}=/d\" .env
    echo \"\$kv\" >> .env
  done
  for key in ALLOWED_EMAILS ALLOWED_AUDIENCES; do
    if ! grep -q \"^\$key=.\" .env; then
      echo \"\$key is not set on the server. Re-run with \$key=... scripts/deploy.sh ...\" >&2
      exit 1
    fi
  done
  docker compose up -d --build --remove-orphans 2>&1 | grep -vE '^ *(#|=>)' | tail -5"

echo "==> Waiting for https://$DOMAIN/health (a new hostname needs a new certificate)"
for _ in $(seq 1 30); do
  if curl -sf -m 5 "https://$DOMAIN/health" >/dev/null 2>&1; then
    echo "OK: https://$DOMAIN is up"
    echo
    echo "If the hostname changed, update the add-on:"
    echo "  appsscript.json  urlFetchWhitelist -> \"https://$DOMAIN/\""
    echo "  Code.gs          BACKEND_URL       -> 'https://$DOMAIN'"
    exit 0
  fi
  sleep 5
done

echo "Health check failed. Inspect with: ssh $SSH_USER@$HOST 'cd ~/$REMOTE_DIR && docker compose logs --tail 50'" >&2
exit 1
