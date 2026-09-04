# Mesh test bed: nodes that know each other only by name

Three gorgonad nodes in one Docker network, where every `peer` entry in the
config is a DNS name and no address is written anywhere. Docker's embedded DNS
stands in for a Kubernetes headless service: a container answers to its service
name, and its address changes whenever it is recreated.

The bed was written while testing FQDN support (#9) and reproduces the two
failure modes that came up there: a node listing itself as a neighbour, and one
node appearing twice, once by name from the config and once by address from PEX.

## Run

```bash
docker compose -f test/docker/docker-compose.yml up -d --build
./test/docker/check.sh
```

The image is built from the working tree, so it always carries the code you are
testing.

## What a healthy mesh looks like

Give the nodes a few sync cycles, then every node should report exactly two
neighbours, each with a resolved address next to the name:

```
--- node-a ---
--- L2 Cluster Topology (Known nodes: 2) ---
  [node-b (172.31.0.3) :7777 ] SEED [UP]
  [node-c (172.31.0.4) :7777 ] SEED [UP]
```

Signs of trouble:

- `Known nodes` higher than the number of neighbours: the same node is held
  twice, usually once by name and once by address.
- A node listing its own name.
- An entry with no address in brackets that stays `DEAD` while the node is up:
  the name was never resolved, so it never merged with the address entry.

## Cold start

The harder case is a node that starts before its neighbours exist, when DNS
cannot resolve them yet. Start one node alone, let it sit, then bring up the
rest:

```bash
docker compose -f test/docker/docker-compose.yml up -d --build node-a
sleep 15
docker compose -f test/docker/docker-compose.yml up -d node-b node-c
```

Entries begin without addresses and should pick them up on a later cycle.

## Message delivery

```bash
C="docker compose -f test/docker/docker-compose.yml"
$C exec node-a gorgona genkeys
KEY=$($C exec -T node-a sh -c 'ls /etc/gorgona/*.pub | head -1 | xargs basename | sed s/.pub//')
$C exec -T node-a sh -c "cat /etc/gorgona/$KEY.key" > /tmp/k.key
$C exec -T node-c sh -c "cat > /etc/gorgona/$KEY.key" < /tmp/k.key
$C exec node-a sh -c "gorgona send \"\$(date -u '+%Y-%m-%d %H:%M:%S')\" \"\$(date -u -d '+1 day' '+%Y-%m-%d %H:%M:%S')\" 'hello over dns' '$KEY.pub'"
$C exec node-c sh -c "timeout 8 gorgona listen last 1 '$KEY'"
```

An alert sent from one node should come back on another.

## Cleanup

```bash
docker compose -f test/docker/docker-compose.yml down
```
