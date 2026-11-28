#!/bin/sh
# The end-to-end check against a real 1Password vault, and what each command
# spends of it: sesame (a release build, the real Core through opcore) on two
# config dirs standing in for two machines, against a fake OAuth provider on
# 127.0.0.1 (as tests/e2e.rs has): provider add -> client -> login -> a
# refresh -> api from the Copy -> a forced refresh -> providers -> provider
# set -> the other machine's first run, which sees the refreshed token ->
# logout -> client --reset -> provider rm. After each step, 6 s for the
# counters to settle, then `op service-account ratelimit`: the token's reads
# and writes and the account's requests it spent, set beside the row of
# docs/budget.md that names the step. Outside the gate: it needs the network
# and a token.
#
#   scripts/e2e.sh [optokens-profile]
#
# The optokens Profile (default `sesame-scratch`) holds
# OP_SERVICE_ACCOUNT_TOKEN for the vault `sesame-scratch`; the script refuses
# any other vault. The token stays in this process's environment and nothing
# prints it, nor any access or refresh token. sesame's items for the provider
# `e2e-<n>` (`sesame.e2e-<n>`, and `sesame-providers` when the vault had none)
# are removed on any exit, archived ones included.
#
# Exits 1 when a step fails, an item is left, or a step's reads or writes
# differ from docs/budget.md. The account's requests are shared by every
# token of the account, so a difference there alone is marked, not failed.
set -eu

profile=${1:-sesame-scratch}
vault=sesame-scratch
cd "$(dirname "$0")/.."
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

fail() { printf 'e2e: FAIL: %s\n' "$*" >&2; exit 1; }

# Release: the 1Password Core runs in wasmi, minutes per sign-in in a debug build.
cargo build --release --quiet
bin=$PWD/target/release/sesame

# From here on nothing prints a token.
eval "$(optokens env "$profile")" || fail "no optokens Profile $profile"
[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] || fail "Profile $profile has no OP_SERVICE_ACCOUNT_TOKEN"
export OP_SERVICE_ACCOUNT_TOKEN
export SESAME_1PASSWORD_VAULT=$vault
unset SESAME_PROVIDERS
for v in $(env | sed -n 's/^\(SESAME_TOKEN_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$v"; done
op vault get "$vault" --format json | jq -e --arg v "$vault" '.name == $v' >/dev/null ||
    fail "the token cannot read the vault '$vault'"

name=e2e-$(date +%s)
work=$(mktemp -d "${TMPDIR:-/tmp}/sesame-e2e.XXXXXX")
# Whether the vault had a `sesame-providers` before: if not, it is this run's.
had_providers=$(op item list --vault "$vault" --format json | jq '[.[] | select(.title == "sesame-providers")] | length')

# The fake provider: the device flow (a login's token lasts 30 s, inside the
# minute sesame wants left, so the first call refreshes it; a refresh's lasts
# an hour) and `/me`. It writes its port to the file it is given.
cat >"$work/provider.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

refreshes = 0

class Fake(BaseHTTPRequestHandler):
    def answer(self, status, body):
        b = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/me":
            return self.answer(200, {"me": "octo"})
        self.answer(404, {})

    def do_POST(self):
        global refreshes
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if self.path == "/device":
            return self.answer(200, {"device_code": "dev", "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device", "expires_in": 60, "interval": 0})
        if self.path == "/token" and "grant_type=urn" in body:
            return self.answer(200, {"access_token": "login-token",
                "refresh_token": "refresh-secret", "expires_in": 30})
        if self.path == "/token" and "grant_type=refresh_token" in body:
            refreshes += 1
            return self.answer(200, {"access_token": f"refreshed-{refreshes}",
                "refresh_token": "refresh-secret", "expires_in": 3600})
        self.answer(404, {})

    def log_message(self, *a):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
with open(sys.argv[1], "w") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
EOF
uv run --no-project python -I "$work/provider.py" "$work/port" &
fake=$!

# sesame's items for $name (active or archived), and `sesame-providers` when
# this run made it: their ids.
ours() {
    op item list --vault "$vault" --include-archive --format json |
        jq -r --arg t "sesame.$name" --argjson had "$had_providers" \
            '.[] | select(.title == $t or ($had == 0 and .title == "sesame-providers")) | .id'
}
cleanup() {
    rc=$?
    kill "$fake" 2>/dev/null || true
    if [ -z "${finished:-}" ]; then
        for args in "logout $name" "client $name --reset" "provider rm $name"; do
            # shellcheck disable=SC2086
            SESAME_CONFIG_DIR=$work/a "$bin" $args >/dev/null 2>&1 || true
        done
    fi
    for id in $(ours); do op item delete "$id" --vault "$vault" >/dev/null 2>&1 || true; done
    left=$(ours | wc -l | tr -d ' ')
    rm -rf "$work"
    printf '\ne2e: items of %s left in %s: %s\n' "$name" "$vault" "$left"
    [ "$left" = 0 ] || rc=1
    [ "$rc" = 0 ] && echo "e2e: ok"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

n=0
until [ -s "$work/port" ]; do
    n=$((n + 1))
    [ "$n" -lt 100 ] || fail "the fake provider did not start"
    sleep 0.1
done
base=http://127.0.0.1:$(cat "$work/port")

# The token's reads, its writes, the account's requests, as used so far.
used() {
    op service-account ratelimit --format json | jq -r '[
        (.[] | select(.type == "token" and .action == "read") | .used),
        (.[] | select(.type == "token" and .action == "write") | .used),
        (.[] | select(.type == "account") | .used)] | @tsv'
}

mismatch=0
rows=$work/rows
printf '| Command | Reads | Writes | Account requests | docs/budget.md |\n|---|---|---|---|---|\n' >"$rows"
before=$(used)
# step <machine> <row of docs/budget.md> <stdin> <sesame args…>: runs it,
# its stdout kept in $out (printed by no step), then measures what it spent.
step() {
    machine=$1 row=$2 input=$3
    shift 3
    printf '\n$ sesame %s   (%s)\n' "$*" "$machine"
    if ! out=$(printf '%s' "$input" | SESAME_CONFIG_DIR=$work/$machine "$bin" "$@" 2>"$work/err"); then
        cat "$work/err" >&2
        fail "sesame $* failed"
    fi
    sleep 6
    after=$(used)
    spent=$(printf '%s\t%s\n' "$before" "$after" | awk -F'\t' '{ print $4-$1 "\t" $5-$2 "\t" $6-$3 }')
    before=$after
    want=$(awk -F' [|] ' -v r="$row" '$1 == "| " r { print $3 "\t" $4 "\t" $5 }' docs/budget.md | sed 's/ |$//')
    [ -n "$want" ] || fail "docs/budget.md has no row '$row'"
    verdict=same
    if [ "$(printf '%s' "$spent" | cut -f1-2)" != "$(printf '%s' "$want" | cut -f1-2)" ]; then
        verdict="differs: $(printf '%s' "$want" | tr '\t' /)"
        mismatch=1
    elif [ "$spent" != "$want" ]; then
        verdict="account differs: $(printf '%s' "$want" | cut -f3) (the account is shared)"
    fi
    printf 'spent %s (reads/writes/account), %s\n' "$(printf '%s' "$spent" | tr '\t' /)" "$verdict"
    printf '| %s | %s | %s |\n' "$row" "$(printf '%s' "$spent" | awk -F'\t' '{ print $1 " | " $2 " | " $3 }')" "$verdict" >>"$rows"
}

step a "\`provider add\`, the first run on a new host" "" provider add "$name" \
    --auth-url "$base/authorize" --token-url "$base/token" --api-base "$base" --host 127.0.0.1 \
    --device-url "$base/device"
step a "\`client\`" "client-secret
" client "$name" --client-id cid --secret-stdin
step a "\`login\`" "" login "$name" --no-browser
step a "a refresh (\`token\`, the token expiring)" "" token "$name"
[ "$out" = refreshed-1 ] || fail "the first token after login was not the refreshed one"
step a "a valid token from the Copy (\`api\`)" "" api "$name" /me
case $out in *octo*) ;; *) fail "api $name /me did not answer the fake provider's /me" ;; esac
step a "a valid token from the Copy (\`token\`)" "" token "$name"
step a "a forced refresh (\`token --min-life 7200\`)" "" token "$name" --min-life 7200
refreshed=$out
step a "\`providers\`" "" providers
step a "\`provider set\`" "" provider set "$name" --about second
step a "\`provider show\`" "" provider show "$name"
step b "\`token\`, the first run on a new host" "" token "$name"
[ "$out" = "$refreshed" ] || fail "the other machine did not see the refreshed token"
echo "ok: the other machine sees the refreshed token"
step a "\`logout\`" "" logout "$name"
step a "\`client --reset\`, the item left empty archived" "" client "$name" --reset
step a "\`provider rm\`, the last provider's fields: their item archived" "" provider rm "$name"
finished=1

printf '\nMeasured on %s, %s:\n\n' "$vault" "$(date -u +%Y-%m-%dT%H:%MZ)"
cat "$rows"
[ "$mismatch" = 0 ] || fail "a step's reads or writes differ from docs/budget.md"
