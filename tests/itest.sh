set -e
trap "pkill -f natively; exit 1" ERR
set -x
export PYTHONPATH=/tmp/natively
NV="python3 -m natively"
# Never touch a fixed shared path: a hardcoded /tmp/nvtest wiped a live
# soak home on a box where the integration test ran next to a real node.
# Each run gets its own throwaway dir.
NVTEST=$(mktemp -d /tmp/nv-itest.XXXXXX)
trap 'rm -rf "$NVTEST"' EXIT
# hub
python3 -m natively hub --port 8471 --state "$NVTEST"/hub.json &
HUB=$!
sleep 1
# principal
$NV principal-init --out "$NVTEST"/principal.key > "$NVTEST"/principal.out
PPUB=$(grep -A1 'public key' "$NVTEST"/principal.out | tail -1)
# two nodes
$NV --home "$NVTEST"/n1 node-init --name node96 --hub http://127.0.0.1:8471 --principal-pub "$PPUB"
$NV --home "$NVTEST"/n2 node-init --name node512g8 --hub http://127.0.0.1:8471 --principal-pub "$PPUB"
FP1=$(python3 -c "from natively import jcs,crypto; print(jcs.sha256(crypto.sign_pub(bytes.fromhex(open('"$NVTEST"/n1/node.key').read().strip())))[:32])")
FP2=$(python3 -c "from natively import jcs,crypto; print(jcs.sha256(crypto.sign_pub(bytes.fromhex(open('"$NVTEST"/n2/node.key').read().strip())))[:32])")
$NV --home "$NVTEST"/n1 agent-add --name alpha --principal "$NVTEST"/principal.key --caps test.ping,msg.send
$NV --home "$NVTEST"/n2 agent-add --name beta --principal "$NVTEST"/principal.key --caps test.ping,msg.send
$NV --home "$NVTEST"/n2 agent-add --name gamma --principal "$NVTEST"/principal.key --caps test.ping,msg.send
# run nodes
$NV --home "$NVTEST"/n1 node-run > "$NVTEST"/n1.log 2>&1 &
N1=$!
$NV --home "$NVTEST"/n2 node-run > "$NVTEST"/n2.log 2>&1 &
N2=$!
sleep 3
# 1:1 message
$NV --home "$NVTEST"/n1 send --from alpha --to beta@$FP2 --text "hello from alpha"
sleep 10
echo "--- beta inbox:"; $NV --home "$NVTEST"/n2 inbox --agent beta
# reply
$NV --home "$NVTEST"/n2 send --from beta --to alpha@$FP1 --text "hi alpha, beta here"
sleep 10
echo "--- alpha inbox:"; $NV --home "$NVTEST"/n1 inbox --agent alpha
# group chat
GID=$($NV --home "$NVTEST"/n1 group-create --from alpha --members beta@$FP2,gamma@$FP2 --name testgroup | awk '{print $3}')
sleep 10
$NV --home "$NVTEST"/n1 group-send --from alpha --gid $GID --text "first group message"
$NV --home "$NVTEST"/n2 group-send --from beta --gid $GID --text "beta in the group too" 2>/dev/null || echo "(beta group send - expected only if member state arrived)"
sleep 10
echo "--- gamma inbox:"; $NV --home "$NVTEST"/n2 inbox --agent gamma
# attachment
head -c 200000 /dev/urandom > "$NVTEST"/photo.jpg
$NV --home "$NVTEST"/n1 blob --from alpha --to beta@$FP2 --file "$NVTEST"/photo.jpg
for i in $(seq 1 12); do
  BREC=$(grep -l blob_ref "$NVTEST"/n2/inbox/beta/*.json 2>/dev/null | head -1)
  [ -n "$BREC" ] && break
  sleep 5
done
echo "--- beta inbox tail:"; $NV --home "$NVTEST"/n2 inbox --agent beta --tail 3
$NV --home "$NVTEST"/n2 fetch-blob --agent beta --msg-id "$(basename ${BREC%.json})" --out "$NVTEST"/photo-out.jpg
cmp "$NVTEST"/photo.jpg "$NVTEST"/photo-out.jpg && echo "BLOB ROUNDTRIP OK"
# grant + action
cat > "$NVTEST"/scope.json <<'JSON'
[{"action":"test.ping","resource":"host:any:ping","params":{}}]
JSON
$NV --home "$NVTEST"/n2 grant-issue --agent beta --principal "$NVTEST"/principal.key --principal-name taylor --scope "$NVTEST"/scope.json --statement "ping the box up to 2 times" --max-uses 2
GID2=$(ls "$NVTEST"/n2/grants/ | sed 's/.json//')
$NV --home "$NVTEST"/n1 send --from alpha --to beta@$FP2 --text "ping please" --action test.ping --resource host:any:ping --grants $GID2
sleep 10
echo "--- n2 ledger tail:"; $NV --home "$NVTEST"/n2 ledger tail -n 4
grep -q '"action":"test.ping","params_hash":"[0-9a-f]*","outcome":"ok"' "$NVTEST"/n2/ledger.jsonl && echo "GRANTED PING OK" || { echo "GRANTED PING FAILED"; exit 1; }
echo "--- ledger chains:"; $NV --home "$NVTEST"/n1 ledger verify; $NV --home "$NVTEST"/n2 ledger verify
kill $HUB $N1 $N2 2>/dev/null
echo "=== ITEST DONE ==="
