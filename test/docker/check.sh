#!/bin/bash
# Prints the mesh topology each node sees. With three nodes and no duplicates
# every node reports "Known nodes: 2", each entry carrying a resolved address.
PSK=$(sed -n 's/^sync_psk *= *//p' "$(dirname "$0")/node-a.conf" | awk '{print $1}')
COMPOSE="docker compose -f $(dirname "$0")/docker-compose.yml"

for node in node-a node-b node-c; do
    echo "--- $node ---"
    $COMPOSE exec -T "$node" bash -c \
        "exec 3<>/dev/tcp/localhost/7777 && echo 'status $PSK' >&3 && timeout 5 cat <&3" \
        2>/dev/null | sed -n '/L2 Cluster Topology/,/^-----/p'
done
