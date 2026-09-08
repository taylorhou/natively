#!/usr/bin/env bash
# End-to-end smoke run through the CLI: a hub, two nodes, three agents,
# 1:1 both ways, a group, a blob, a granted action. Every step is
# ASSERTED - a run in which something was not delivered fails, it does
# not print "DONE". The asserted pytest journey is tests/test_conformance.py
# (in-process, random port); this script is the same walk over real
# processes and the real CLI. Only this run's own processes are ever
# signalled; only this run's own temp dir is ever removed.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$(dirname "$HERE")"
NV="python3 -m natively"
HUB= N1= N2= NVTEST=  # every name the cleanup acts on starts empty: an inherited value is never this run's
cleanup() {
  [ -n "$N1" ] && kill "$N1" 2>/dev/null || true
  [ -n "$N2" ] && kill "$N2" 2>/dev/null || true
  [ -n "$HUB" ] && kill "$HUB" 2>/dev/null || true
  if [ -n "$NVTEST" ] && [ -z "$KEEP" ]; then rm -rf "$NVTEST"; fi  # KEEP=1 leaves the run dir for a look at the logs
  return 0
}
trap cleanup EXIT
# an uncaught signal skips the EXIT trap: exit through it instead, so a
# terminated run still kills its own processes and removes its own dir
trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP
fail() { echo "ITEST FAILED: $*" >&2; exit 1; }
trap 'fail "a step exited non-zero (line $LINENO)"' ERR
set -x
# Never touch a fixed shared path: a hardcoded /tmp/nvtest wiped a live
# soak home on a box where the integration test ran next to a real node.
# Each run gets its own throwaway dir, and its own free port.
NVTEST=$(mktemp -d /tmp/nv-itest.XXXXXX)
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
HUBURL="http://127.0.0.1:$PORT"
# hub
python3 -m natively hub --port "$PORT" --state "$NVTEST"/hub.json &
HUB=$!
sleep 1
# principal
$NV principal-init --out "$NVTEST"/principal.key > "$NVTEST"/principal.out
PPUB=$(grep -A1 'public key' "$NVTEST"/principal.out | tail -1)
# two nodes
$NV --home "$NVTEST"/n1 node-init --name node96 --hub "$HUBURL" --principal-pub "$PPUB"
$NV --home "$NVTEST"/n2 node-init --name node512g8 --hub "$HUBURL" --principal-pub "$PPUB"
FP1=$(python3 -c "from natively import jcs,crypto; print(jcs.sha256(crypto.sign_pub(bytes.fromhex(open('"$NVTEST"/n1/node.key').read().strip())))[:32])")
FP2=$(python3 -c "from natively import jcs,crypto; print(jcs.sha256(crypto.sign_pub(bytes.fromhex(open('"$NVTEST"/n2/node.key').read().strip())))[:32])")
$NV --home "$NVTEST"/n1 agent-add --name alpha --principal "$NVTEST"/principal.key --caps test.ping,msg.send,group.join
$NV --home "$NVTEST"/n2 agent-add --name beta --principal "$NVTEST"/principal.key --caps test.ping,msg.send,group.join
$NV --home "$NVTEST"/n2 agent-add --name gamma --principal "$NVTEST"/principal.key --caps test.ping,msg.send,group.join
# run nodes
$NV --home "$NVTEST"/n1 node-run > "$NVTEST"/n1.log 2>&1 &
N1=$!
$NV --home "$NVTEST"/n2 node-run > "$NVTEST"/n2.log 2>&1 &
N2=$!
sleep 3
# waits for `grep -q PATTERN FILE...` to hold, up to N seconds
# until_grep SECONDS PATTERN GLOB: the glob is a quoted string, expanded on
# every attempt (the files it names may not exist yet when the wait starts)
until_grep() { local n=$1 pat=$2 glob=$3; for _ in $(seq 1 "$n"); do grep -qs -- "$pat" $glob && return 0; sleep 1; done; fail "not found within ${n}s: $pat in $glob"; }
# 1:1 message
$NV --home "$NVTEST"/n1 send --from alpha --to beta@$FP2 --text "hello from alpha"
until_grep 30 '"text": "hello from alpha"' "$NVTEST/n2/inbox/beta/*.json"
echo "--- beta inbox:"; $NV --home "$NVTEST"/n2 inbox --agent beta | grep -q "hello from alpha" || fail "beta inbox does not show the message"
# reply
$NV --home "$NVTEST"/n2 send --from beta --to alpha@$FP1 --text "hi alpha, beta here"
until_grep 30 '"text": "hi alpha, beta here"' "$NVTEST/n1/inbox/alpha/*.json"
# waits (bounded) until every message delivered across the two nodes has
# been acknowledged BY ID: for each inbox record whose sender lives on the
# other node, the sender's ledger prose must carry the ok msg.ack row's
# "acked <msg_id>" line. An empty unacked table proves nothing on its own -
# it is also what a dead-lettered message leaves, and what the sender's disk
# shows between a POST and the save that records it - so the tables are
# checked last, and a msg.undelivered row anywhere fails the run.
wait_drained() {
python3 - "$NVTEST" <<'PY'
import glob, json, os, sys, time
from natively import node as nodemod
root = sys.argv[1]
homes = {n: os.path.join(root, n) for n in ("n1", "n2")}
def bare(k):
    return k.split(":", 1)[1] if isinstance(k, str) and k.startswith("ed25519:") else k
owner = {}  # agent key -> the home its card lives in
for n, home in homes.items():
    for a in nodemod.Node(home).agents.values():
        owner[bare(a["card"]["agent_key"])] = n
def missing():
    out = []
    for n, home in homes.items():
        for f in glob.glob(os.path.join(home, "inbox", "*", "*.json")):
            r = json.load(open(f))
            sender = owner.get(bare(r.get("from")))
            if sender is None or sender == n:
                continue  # a local delivery (never on the wire) or a sender this run does not know
            prose_path = os.path.join(homes[sender], "ledger.jsonl.prose")
            prose = open(prose_path).read() if os.path.exists(prose_path) else ""
            if "\n    acked %s\n" % r["msg_id"] not in prose:
                out.append("%s never saw the ack for %s (delivered to %s)" % (sender, r["msg_id"], n))
    return out
for _ in range(30):
    gone = missing()
    if not gone and all(json.load(open(os.path.join(h, "state.json")))["unacked"] == {} for h in homes.values()):
        break
    time.sleep(1)
else:
    sys.exit("never acknowledged: %s" % "; ".join(missing() or ["an unacked table did not drain"]))
for n, home in homes.items():
    for line in open(os.path.join(home, "ledger.jsonl")):
        if '"action":"msg.undelivered"' in line:
            sys.exit("%s dead-lettered a message instead of seeing it acknowledged: %s" % (n, line.strip()))
PY
}
# both sends acknowledged: an ok msg.ack row on each sender and no unacked entries left
until_grep 30 '"action":"msg.ack".*"outcome":"ok"' "$NVTEST/n1/ledger.jsonl"
until_grep 30 '"action":"msg.ack".*"outcome":"ok"' "$NVTEST/n2/ledger.jsonl"
wait_drained
# group chat: every member, the creator included, holds a group.join grant on its node
cat > "$NVTEST"/join.json <<'JSON'
[{"action":"group.join","resource":"host:NODEKEY:groups","params":{"keys":["group_id"]}}]
JSON
NK1=$(python3 -c "from natively import node; print(node.Node('$NVTEST/n1').node_key)")
NK2=$(python3 -c "from natively import node; print(node.Node('$NVTEST/n2').node_key)")
sed "s|NODEKEY|$NK1|" "$NVTEST"/join.json > "$NVTEST"/join1.json  # keys are base64: / is in their alphabet, | is not
sed "s|NODEKEY|$NK2|" "$NVTEST"/join.json > "$NVTEST"/join2.json
$NV --home "$NVTEST"/n1 grant-issue --agent alpha --principal "$NVTEST"/principal.key --principal-name taylor --scope "$NVTEST"/join1.json --statement "alpha may join groups here" --max-uses 5
J1=$(ls "$NVTEST"/n1/grants/ | sed 's/.json//')
$NV --home "$NVTEST"/n2 grant-issue --agent beta --principal "$NVTEST"/principal.key --principal-name taylor --scope "$NVTEST"/join2.json --statement "beta may join groups here" --max-uses 5
JB=$(ls -t "$NVTEST"/n2/grants/ | head -1 | sed 's/.json//')
$NV --home "$NVTEST"/n2 grant-issue --agent gamma --principal "$NVTEST"/principal.key --principal-name taylor --scope "$NVTEST"/join2.json --statement "gamma may join groups here" --max-uses 5
JG=$(ls -t "$NVTEST"/n2/grants/ | head -1 | sed 's/.json//')
GID=$($NV --home "$NVTEST"/n1 group-create --from alpha --members beta@$FP2,gamma@$FP2 --name testgroup --grants "$JB,$JG" --creator-grants "$J1" | awk '{print $3}')
[ -n "$GID" ] || fail "group-create printed no group id"
until_grep 40 '"action":"group.join".*"outcome":"ok"' "$NVTEST/n2/ledger.jsonl"
$NV --home "$NVTEST"/n1 group-send --from alpha --gid $GID --text "first group message"
until_grep 30 '"text": "first group message"' "$NVTEST/n2/inbox/gamma/*.json"
until_grep 30 '"text": "first group message"' "$NVTEST/n2/inbox/beta/*.json"
$NV --home "$NVTEST"/n2 group-send --from beta --gid $GID --text "beta in the group too"
until_grep 30 '"text": "beta in the group too"' "$NVTEST/n1/inbox/alpha/*.json"
until_grep 30 '"text": "beta in the group too"' "$NVTEST/n2/inbox/gamma/*.json"
echo "--- gamma inbox:"; $NV --home "$NVTEST"/n2 inbox --agent gamma
# attachment
head -c 200000 /dev/urandom > "$NVTEST"/photo.jpg
$NV --home "$NVTEST"/n1 blob --from alpha --to beta@$FP2 --file "$NVTEST"/photo.jpg
until_grep 60 'blob_ref' "$NVTEST/n2/inbox/beta/*.json"
BREC=$(grep -l blob_ref "$NVTEST"/n2/inbox/beta/*.json | head -1)
echo "--- beta inbox tail:"; $NV --home "$NVTEST"/n2 inbox --agent beta --tail 3
$NV --home "$NVTEST"/n2 fetch-blob --agent beta --msg-id "$(basename ${BREC%.json})" --out "$NVTEST"/photo-out.jpg
cmp "$NVTEST"/photo.jpg "$NVTEST"/photo-out.jpg && echo "BLOB ROUNDTRIP OK"
# grant + action: honoured exactly max-uses times, the one past the budget refused
cat > "$NVTEST"/scope.json <<JSON
[{"action":"test.ping","resource":"host:$NK2:ping","params":{}}]
JSON
$NV --home "$NVTEST"/n2 grant-issue --agent beta --principal "$NVTEST"/principal.key --principal-name taylor --scope "$NVTEST"/scope.json --statement "ping the box up to 2 times" --max-uses 2
GID2=$(ls -t "$NVTEST"/n2/grants/ | head -1 | sed 's/.json//')
for i in 1 2 3; do
  $NV --home "$NVTEST"/n1 send --from alpha --to beta@$FP2 --text "ping please $i" --action test.ping --resource "host:$NK2:ping" --grants $GID2
  until_grep 30 "\"text\": \"ping please $i\"" "$NVTEST/n2/inbox/beta/*.json"
done
echo "--- n2 ledger tail:"; $NV --home "$NVTEST"/n2 ledger tail -n 6
[ "$(grep -c '"action":"test.ping","params_hash":"[0-9a-f]*","outcome":"ok"' "$NVTEST"/n2/ledger.jsonl)" = 2 ] || fail "test.ping did not execute exactly twice"
grep -q '"action":"grant.check".*"outcome":"exhausted"' "$NVTEST"/n2/ledger.jsonl || fail "the third ping was not refused as exhausted"
# per message, not in aggregate: the first two acted, the third refused
python3 - "$NVTEST" <<'PY'
import glob, json, sys
root = sys.argv[1]
got = {}
for f in glob.glob("%s/n2/inbox/beta/*.json" % root):
    r = json.load(open(f))
    t = r.get("body", {}).get("text")
    if isinstance(t, str) and t.startswith("ping please "):
        got[t] = r.get("outcome")
want = {"ping please 1": "acted:test.ping", "ping please 2": "acted:test.ping", "ping please 3": "refused"}
if got != want:
    sys.exit("ping outcomes %r, expected %r" % (got, want))
PY
echo "GRANTED PING OK"
# everything sent since - the group, the blob, the pings - acknowledged before the nodes are stopped
wait_drained
echo "--- ledger chains:"; $NV --home "$NVTEST"/n1 ledger verify; $NV --home "$NVTEST"/n2 ledger verify
echo "=== ITEST DONE ==="
