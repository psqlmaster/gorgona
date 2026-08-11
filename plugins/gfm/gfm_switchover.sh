#!/bin/bash
# /usr/local/bin/gfm_switchover.sh
# Скрипт управляемой передачи роли Master -> Standby

CONF=$1

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ -z "$CONF" ] || [ ! -f "$CONF" ]; then
    echo -e "${RED}Error: Usage: $0 /path/to/gfm.conf${NC}"
    exit 1
fi

# Усиленная функция чтения конфига
get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

# Читаем параметры
BASE_DIR=$(get_val "paths" "base_dir")
[ -z "$BASE_DIR" ] && BASE_DIR="/etc/gorgona"

PG_SERVICE=$(get_val "postgresql" "service_name")
CLUSTER_ID=$(get_val "cluster" "cluster_id")
MY_PUB_HASH=$(get_val "cluster" "my_pub_hash")
GORGONA_BIN=$(get_val "paths" "gorgona_bin")
[ -z "$GORGONA_BIN" ] && GORGONA_BIN="/usr/bin/gorgona"

# ПЕРЕХОДИМ В ДИРЕКТОРИЮ С КЛЮЧАМИ (Критически важно для listen)
if [ -d "$BASE_DIR" ]; then
    cd "$BASE_DIR" || exit 1
else
    echo -e "${RED}Error: Base directory $BASE_DIR not found!${NC}"
    exit 1
fi

send_event() {
    local message=$1
    $GORGONA_BIN send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
        "EVENT|$(hostname)|$message" "${MY_PUB_HASH}.pub"
}

STATUS_FILE="${BASE_DIR}/status_${CLUSTER_ID}.json"
MY_HOSTNAME=$(hostname)

if [ ! -f "$STATUS_FILE" ]; then
    echo -e "${RED}Error: Status file $STATUS_FILE not found!${NC}"
    exit 1
fi

ROLE=$(grep -oP '"role": "\K[^"]+' "$STATUS_FILE")

if [ "$ROLE" != "LEADER" ]; then
    echo -e "${YELLOW}Notice: Node is $ROLE, not LEADER for $CLUSTER_ID. Switchover ignored.${NC}"
    exit 0
fi

echo -e "${GREEN}>>> Initiating graceful switchover for cluster: $CLUSTER_ID...${NC}"
send_event "SWITCHOVER INITIATED: Node is preparing to step down."

# --- ПРОВЕРКА КВОРУМА ---
echo "Scanning mesh for active neighbors (last 100 messages)..."

# Делаем попытку получить данные. 
# Ключ теперь будет найден, так как мы сделали cd /etc/gorgona
RAW_MESH_DATA=$(timeout 10s "$GORGONA_BIN" listen last 100 "$MY_PUB_HASH")

# Отладочный вывод (раскомментировать если Neighbors все равно 0)
# echo "DEBUG: RAW_DATA_LEN: ${#RAW_MESH_DATA}"

ACTIVE_NODES=$(echo "$RAW_MESH_DATA" | grep "|" | grep -E "LEADER_STATUS|MONITOR|CANDIDATE|EVENT" | grep -v "$MY_HOSTNAME" | cut -d'|' -f2 | sort -u | wc -l)

if [ "$ACTIVE_NODES" -lt 1 ]; then
    REASON="ABORTED: No other nodes found in mesh. Quorum check failed (Neighbors: $ACTIVE_NODES)."
    echo -e "${RED}$REASON${NC}"
    send_event "$REASON"
    exit 1
fi

echo -e "${GREEN}Quorum OK: Found $ACTIVE_NODES unique neighbor(s). Proceeding...${NC}"

# --- ВЫПОЛНЕНИЕ ---
echo "Stopping GFM manager..."
systemctl stop "gfm@${CLUSTER_ID}"

echo "Stopping PostgreSQL ($PG_SERVICE)..."
systemctl stop "$PG_SERVICE"

send_event "SWITCHOVER IN PROGRESS: Services stopped. Waiting for elections..."

echo "Waiting 60 seconds for the new leader..."
sleep 60

echo "Starting GFM manager (returning as Standby)..."
systemctl start "gfm@${CLUSTER_ID}"

send_event "SWITCHOVER COMPLETED: Node returned to cluster."
echo -e "${GREEN}>>> Switchover finished.${NC}"
