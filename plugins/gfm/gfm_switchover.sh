#!/bin/bash
# /usr/local/bin/gfm_switchover.sh
# Скрипт управляемой передачи роли Master -> Standby

CONF=$1

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Проверка аргумента
if [ -z "$CONF" ] || [ ! -f "$CONF" ]; then
    echo -e "${RED}Error: Usage: $0 /path/to/gfm.conf${NC}"
    exit 1
fi

# Универсальная функция чтения конфига (с очисткой пробелов через xargs)
get_val() {
    local key=$1
    grep "^$key" "$CONF" | sed 's/^[^=]*=[[:space:]]*//' | sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

# Читаем параметры
PG_SERVICE=$(get_val "service_name")
CLUSTER_ID=$(get_val "cluster_id")
MY_PUB_HASH=$(get_val "my_pub_hash")
GORGONA_BIN=$(get_val "gorgona_bin")
[ -z "$GORGONA_BIN" ] && GORGONA_BIN="/usr/bin/gorgona"

# Путь к файлу статуса (теперь без лишних пробелов)
STATUS_FILE="/etc/gorgona/status_${CLUSTER_ID}.json"

# Проверка роли через JSON
if [ ! -f "$STATUS_FILE" ]; then
    echo -e "${RED}Error: Status file $STATUS_FILE not found!${NC}"
    exit 1
fi

ROLE=$(grep -oP '"role": "\K[^"]+' "$STATUS_FILE")

if [ "$ROLE" != "LEADER" ]; then
    echo -e "${YELLOW}Notice: Node is $ROLE, not LEADER for $CLUSTER_ID. Switchover ignored.${NC}"
    exit 0
fi

echo -e "${GREEN}>>> Starting graceful switchover for cluster: $CLUSTER_ID...${NC}"

# 1. Отправляем событие в меш, чтобы аудит зафиксировал плановый переход
$GORGONA_BIN send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
    "EVENT|$(hostname)|PLANNED_SWITCHOVER: Stepping down manually" "${MY_PUB_HASH}.pub"

# 2. Останавливаем GFM, чтобы он не пытался поднять базу во время стопа
echo "Stopping GFM manager..."
systemctl stop "gfm@${CLUSTER_ID}"

# 3. Останавливаем PostgreSQL (fast mode для быстрого закрытия сессий)
echo "Stopping PostgreSQL ($PG_SERVICE)..."
systemctl stop "$PG_SERVICE"

# 4. Пауза, чтобы Standby успел заметить пропажу лидера и провести выборы
# Обычно это занимает election_timeout + 10-15 секунд
echo "Waiting 60 seconds for cluster to elect a new leader..."
sleep 60

# 5. Запускаем GFM обратно. 
# Он увидит нового мастера и автоматически уйдет в режим реплики (STANDBY)
echo "Starting GFM manager (returning as Standby)..."
systemctl start "gfm@${CLUSTER_ID}"

echo -e "${GREEN}>>> Switchover process finished.${NC}"
