#!/bin/bash
# /usr/local/bin/gfm_switchover.sh
# Скрипт управляемой передачи роли Master -> Standby (Multi-instance aware)

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

get_val() {
    local section=$1
    local key=$2
    # Добавляем =[[:space:]]* в выражение замены
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

if [ -d "$BASE_DIR" ]; then
    cd "$BASE_DIR" || exit 1
fi

# Исправленный формат события (добавляем CLUSTER_ID для логов)
send_event() {
    local message=$1
    $GORGONA_BIN send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
        "EVENT|$CLUSTER_ID|$(hostname)|$message" "${MY_PUB_HASH}.pub"
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
echo "Scanning mesh for active neighbors of $CLUSTER_ID..."

RAW_MESH_DATA=$(timeout 10s "$GORGONA_BIN" listen last 100 "$MY_PUB_HASH")

# ТОЧЕЧНОЕ ИСПРАВЛЕНИЕ ЛОГИКИ ПОДСЧЕТА:
# 1. Фильтруем только те сообщения, где есть наш CLUSTER_ID
# 2. Используем awk для надежного извлечения имени хоста (3-е поле в новом протоколе)
ACTIVE_NODES=$(echo "$RAW_MESH_DATA" | grep "$CLUSTER_ID" | grep -E "LEADER_STATUS|CANDIDATE|EVENT" | grep -v "$MY_HOSTNAME" | awk -F'|' '{print $3}' | sort -u | wc -l)

# Дополнительно проверяем MONITOR сообщения (там хост - 2-е поле, cid нет)
MONITOR_NODES=$(echo "$RAW_MESH_DATA" | grep "MONITOR" | grep -v "$MY_HOSTNAME" | awk -F'|' '{print $2}' | sort -u | wc -l)

# Итоговое количество соседей
TOTAL_NEIGHBORS=$((ACTIVE_NODES > MONITOR_NODES ? ACTIVE_NODES : MONITOR_NODES))

if [ "$TOTAL_NEIGHBORS" -lt 1 ]; then
    REASON="ABORTED: No other nodes found for $CLUSTER_ID. Quorum check failed (Neighbors: $TOTAL_NEIGHBORS)."
    echo -e "${RED}$REASON${NC}"
    send_event "$REASON"
    exit 1
fi

echo -e "${GREEN}Quorum OK: Found $TOTAL_NEIGHBORS active neighbor(s). Proceeding...${NC}"

# --- ВЫПОЛНЕНИЕ ---
echo "Stopping GFM manager for $CLUSTER_ID..."
systemctl stop "gfm@${CLUSTER_ID}"

echo "Stopping PostgreSQL ($PG_SERVICE)..."
systemctl stop "$PG_SERVICE"

send_event "SWITCHOVER IN PROGRESS: Services stopped. Waiting for elections..."

echo "Waiting 60 seconds for the new leader to take over..."
sleep 60

echo "Starting GFM manager (returning as Standby)..."
systemctl start "gfm@${CLUSTER_ID}"

send_event "SWITCHOVER COMPLETED: Node returned to cluster as Standby."
echo -e "${GREEN}>>> Switchover finished.${NC}"
