# The contract's scenarios: each one a few `op` calls as sesame makes them
# (src/store/vault/op.rs), printing what sesame reads of their answers and
# nothing more. Sourced by fake-op (the stand-in) and real-op (the real `op`),
# with $OP set to the program; run by truefit in a fresh directory each time.
# Usage: <wrapper> <scenario>. Needs jq.
set -u
. "$root/tests/contract/vault.sh"
# Every item the contract makes carries the one tag `sesame-contract` (a tag
# is an entry in 1Password's sidebar, so never one per run) and a title
# unique to this run, `sesame-contract.<case>.$run`, so leftovers of another
# run never answer for this one. The run is normalised away (truefit.toml).
run="run$$x$(date +%s)"
tag="sesame-contract"

# On exit, archives what this run made and still active, and what a run cut
# short (killed) left over an hour ago, so the vault keeps none of them.
# Silent: it changes neither the case's stdout nor its exit code.
sweep() {
    "$OP" item list --vault "$vault" --tags "$tag" --format json </dev/null 2>/dev/null |
        jq -r --arg run "$run" --argjson now "$(date +%s)" '.[]?
            | select((.title // "" | endswith("." + $run))
                     or ((try (.created_at[0:19] + "Z" | fromdateiso8601) catch $now) < $now - 3600))
            | .id' 2>/dev/null |
        while read -r stale; do
            "$OP" item delete "$stale" --vault "$vault" --archive </dev/null >/dev/null 2>&1
        done
}
trap sweep EXIT
trap 'exit 130' INT TERM HUP

# What sesame reads of an item: id, title, version, tags (missing reads as
# none), and its own fields: no section, no purpose, a label.
summary() {
    jq -c '{id: (.id | type == "string"), title, version, category,
            tags: (.tags // []),
            fields: [.fields[]? | select((.section.id // "") == "" and .purpose == null and (.label // "") != "")
                     | {label, type, value}]}'
}

# Runs `op "$@"` with $input on a stdin pipe (as sesame does for a write) or
# /dev/null; prints its exit code and its stderr, and leaves stdout in $out.
call() {
    if [ -n "${input+set}" ]; then
        out=$(printf '%s' "$input" | "$OP" "$@" 2>err)
    else
        out=$("$OP" "$@" </dev/null 2>err)
    fi
    code=$?
    unset input
    echo "exit $code"
    [ -s err ] && sed 's/^/stderr /' err
    return 0
}

template() { # <title> [tags json]
    if [ $# -gt 1 ]; then tags=", \"tags\": $2"; else tags=; fi
    printf '{"title": "%s", "category": "SECURE_NOTE"%s, "fields": [%s]}' "$1" "$tags" \
        '{"id": "access_token", "label": "access_token", "type": "CONCEALED", "value": "a-secret"},
         {"id": "scope", "label": "scope", "type": "STRING", "value": "read"}'
}

create() { # <title> [tags json]: the item's id in $id
    input=$(template "$@") call item create --vault "$vault" --format json
    printf '%s\n' "$out" | summary
    id=$(printf '%s' "$out" | jq -r .id)
}

archive() {
    call item delete "$1" --vault "$vault" --archive
}

case "${1:-}" in
missing-item)
    # A get of an item that is not there: "isn't an item" on stderr.
    call item get "sesame-contract.missing.$run" --vault "$vault" --format json
    ;;
missing-vault)
    # A vault the service account cannot see: "isn't a vault".
    call item list --vault "sesame-contract.missing.$run" --tags "$tag" --format json
    ;;
create-get-list-archive)
    # A template from a stdin pipe; the item get and list print; archive:
    # its id still answers (archived, as sesame reads it), its title not.
    create "sesame-contract.item.$run" "[\"$tag\"]"
    call item get "sesame-contract.item.$run" --vault "$vault" --format json
    printf '%s\n' "$out" | summary
    call item list --vault "$vault" --tags "$tag" --format json
    printf '%s\n' "$out" | jq -c --arg run "$run" \
        '[.[] | select(.title | endswith("." + $run)) | {title, id: (.id | type == "string"), version}]'
    archive "$id"
    call item get "$id" --vault "$vault" --format json
    printf '%s\n' "$out" | jq -c '{state, version}'
    call item get "sesame-contract.item.$run" --vault "$vault" --format json
    ;;
edit-without-tags)
    # An edit whose template has no tags (nor category) keeps the item's tags
    # (and its own category), though its own answer shows none.
    create "sesame-contract.edit.$run" "[\"$tag\", \"other\"]"
    input=$(template "sesame-contract.edit.$run" | jq -c 'del(.category)') \
        call item edit "$id" --vault "$vault" --format json
    printf '%s\n' "$out" | summary
    call item get "$id" --vault "$vault" --format json
    printf '%s\n' "$out" | summary
    archive "$id"
    ;;
edit-with-tags)
    # An edit whose template has tags sets them.
    create "sesame-contract.retag.$run" "[\"$tag\"]"
    input=$(template "sesame-contract.retag.$run" "[\"$tag\", \"kept\"]") \
        call item edit "$id" --vault "$vault" --format json
    printf '%s\n' "$out" | summary
    archive "$id"
    ;;
edit-gone)
    # An edit of an item not there (as one another machine removed since it
    # was read): refused, not "isn't an item".
    input=$(template "sesame-contract.gone.$run") \
        call item edit "sesame-contract.gone.$run" --vault "$vault" --format json
    ;;
template-flag-and-stdin)
    # A --template file as well as a template on stdin is refused: sesame
    # never passes --template.
    template "sesame-contract.flag.$run" >t.json
    input=$(template "sesame-contract.flag.$run") \
        call item create --vault "$vault" --template t.json --format json
    ;;
create-stdin-not-a-pipe)
    # No pipe on stdin, no template: op reads none.
    call item create --vault "$vault" --format json
    ;;
write-budget)
    # Writes until op refuses one over the service account's write budget.
    create "sesame-contract.budget.$run" "[\"$tag\"]" >/dev/null
    n=0
    while [ $n -lt ${SESAME_CONTRACT_MAX_WRITES:-1000} ]; do
        n=$((n + 1))
        input=$(template "sesame-contract.budget.$run" "[\"$tag\"]") \
            call item edit "$id" --vault "$vault" --format json >answer
        grep -q '^exit 0$' answer || break
    done
    cat answer
    ;;
over-budget)
    # A write over the budget, refused: the stand-in, told the fault, its
    # first; the real op once these writes have spent the budget.
    input=$(template "sesame-contract.over.$run" "[\"$tag\"]") \
        call item create --vault "$vault" --format json >answer
    id=$(printf '%s' "$out" | jq -r '.id // empty' 2>/dev/null)
    n=0
    while grep -q '^exit 0$' answer && [ $n -lt ${SESAME_CONTRACT_MAX_WRITES:-1000} ]; do
        n=$((n + 1))
        input=$(template "sesame-contract.over.$run" "[\"$tag\"]") \
            call item edit "$id" --vault "$vault" --format json >answer
    done
    cat answer
    ;;
*)
    echo "no scenario \`${1:-}\`: see tests/contract/scenario.sh" >&2
    exit 2
    ;;
esac
