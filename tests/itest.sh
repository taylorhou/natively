set -e
trap "pkill -f natively; exit 1" ERR
set -x
export PYTHONPATH=/tmp/natively
NV="python3 -m natively"
rm -rf /tmp/nvtest && mkdir -p /tmp/nvtest
# hub
python3 -m natively hub --port 8471 --state /tmp/nvtest/hub.json &
HUB=$!
sleep 1
# principal
$NV principal-init --out /tmp/nvtest/principal.key > /tmp/nvtest/principal.out
PPUB=$(grep -A1 'public key' /tmp/nvtest/principal.out | tail -1)
# two nodes
$NV --home /tmp/nvtest/n1 node-init --name node96 --hub http://127.0.0.1:8471 --principal-pub "$PPUB"
$NV --home /tmp/nvtest/n2 node-init --name node512g8 --hub http://127.0.0.1:8471 --principal-pub "$PPUB"
FP1=$(python3 -c "from natively import jcs,crypto; print(jcs.sha256(crypto.sign_pub(bytes.fromhex(open('/tmp/nvtest/n1/node.key').read().strip())))[:32])")
FP2=$(python3 -c "from natively import jcs,crypto; print(jcs.sha256(crypto.sign_pub(bytes.fromhex(open('/tmp/nvtest/n2/node.key').read().strip())))[:32])")
$NV --home /tmp/nvtest/n1 agent-add --name alpha --principal /tmp/nvtest/principal.key --caps test.ping,msg.send
$NV --home /tmp/nvtest/n2 agent-add --name beta --principal /tmp/nvtest/principal.key --caps test.ping,msg.send
$NV --home /tmp/nvtest/n2 agent-add --name gamma --principal /tmp/nvtest/principal.key --caps test.ping,msg.send
# run nodes
$NV --home /tmp/nvtest/n1 node-run > /tmp/nvtest/n1.log 2>&1 &
N1=$!
$NV --home /tmp/nvtest/n2 node-run > /tmp/nvtest/n2.log 2>&1 &
N2=$!
sleep 3
# 1:1 message
$NV --home /tmp/nvtest/n1 send --from alpha --to beta@$FP2 --text "hello from alpha"
sleep 10
echo "--- beta inbox:"; $NV --home /tmp/nvtest/n2 inbox --agent beta
# reply
$NV --home /tmp/nvtest/n2 send --from beta --to alpha@$FP1 --text "hi alpha, beta here"
sleep 10
echo "--- alpha inbox:"; $NV --home /tmp/nvtest/n1 inbox --agent alpha
# group chat
GID=$($NV --home /tmp/nvtest/n1 group-create --from alpha --members beta@$FP2,gamma@$FP2 --name testgroup | awk '{print $3}')
sleep 10
$NV --home /tmp/nvtest/n1 group-send --from alpha --gid $GID --text "first group message"
$NV --home /tmp/nvtest/n2 group-send --from beta --gid $GID --text "beta in the group too" 2>/dev/null || echo "(beta group send - expected only if member state arrived)"
sleep 10
echo "--- gamma inbox:"; $NV --home /tmp/nvtest/n2 inbox --agent gamma
# attachment
head -c 200000 /dev/urandom > /tmp/nvtest/photo.jpg
$NV --home /tmp/nvtest/n1 blob --from alpha --to beta@$FP2 --file /tmp/nvtest/photo.jpg
for i in $(seq 1 12); do
  BREC=$(grep -l blob_ref /tmp/nvtest/n2/inbox/beta/*.json 2>/dev/null | head -1)
  [ -n "$BREC" ] && break
  sleep 5
done
echo "--- beta inbox tail:"; $NV --home /tmp/nvtest/n2 inbox --agent beta --tail 3
$NV --home /tmp/nvtest/n2 fetch-blob --agent beta --msg-id "$(basename ${BREC%.json})" --out /tmp/nvtest/photo-out.jpg
cmp /tmp/nvtest/photo.jpg /tmp/nvtest/photo-out.jpg && echo "BLOB ROUNDTRIP OK"
# grant + action
cat > /tmp/nvtest/scope.json <<'JSON'
[{"action":"test.ping","resource":"host:any:ping","params":{}}]
JSON
$NV --home /tmp/nvtest/n2 grant-issue --agent beta --principal /tmp/nvtest/principal.key --principal-name taylor --scope /tmp/nvtest/scope.json --statement "ping the box up to 2 times" --max-uses 2
GID2=$(ls /tmp/nvtest/n2/grants/ | sed 's/.json//')
$NV --home /tmp/nvtest/n1 send --from alpha --to beta@$FP2 --text "ping please" --action test.ping --resource host:any:ping --grants $GID2
sleep 10
echo "--- n2 ledger tail:"; $NV --home /tmp/nvtest/n2 ledger tail -n 4
echo "--- ledger chains:"; $NV --home /tmp/nvtest/n1 ledger verify; $NV --home /tmp/nvtest/n2 ledger verify
kill $HUB $N1 $N2 2>/dev/null
echo "=== ITEST DONE ==="
