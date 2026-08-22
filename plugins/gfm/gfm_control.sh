#!/bin/bash
# /usr/local/bin/gfm_control.sh
# Универсальный контроллер инстансов GFM с путями из конфигурации

CONF=$1
ACTION=$2

# --- Цвета для вывода ---
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

if [ -z "$CONF" ] || [ ! -f "$CONF" ]; then
    echo -e "${RED}Usage: $0 <config_path> <start|stop|promote|restart_gfm|status>${NC}"
    exit 1
fi

# Функция извлечения параметров
get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

# 1. Чтение параметров кластера и идентификации
CLUSTER_ID=$(get_val "cluster" "cluster_id")
ADMIN_PUB_HASH=$(get_val "cluster" "admin_pub_hash")
[ -z "$ADMIN_PUB_HASH" ] && ADMIN_PUB_HASH=$(get_val "cluster" "my_pub_hash")

# 2. Чтение путей из секции [paths]
GORGONA_BIN=$(get_val "paths" "gorgona_bin")
[ -z "$GORGONA_BIN" ] && GORGONA_BIN="/usr/bin/gorgona"

PG_CTL=$(get_val "paths" "pg_ctl_bin")
[ -z "$PG_CTL" ] && PG_CTL="/usr/bin/pg_ctlcluster"

# 3. Извлекаем данные инстанса БД
PG_SVC=$(get_val "postgresql" "service_name")
PG_VER=$(get_val "postgresql" "pg_version")
PG_INST=$(get_val "postgresql" "pg_instance_name")

# 4. Служебные переменные
GFM_SVC="gfm@${CLUSTER_ID}"
NODE_NAME=$(hostname)
PUB_KEY_FILE="${ADMIN_PUB_HASH}.pub"
# Переходим в базовую директорию, если она указана, чтобы gorgona нашла .pub ключи
BASE_DIR=$(get_val "paths" "base_dir")
[ -n "$BASE_DIR" ] && [ -d "$BASE_DIR" ] && cd "$BASE_DIR"

# Функция отправки отчета администратору
send_admin_event() {
    local status_msg=$1
    local REPORT="
========================================
CONTROL ACTION: $NODE_NAME ($CLUSTER_ID)
Date: $(date '+%Y-%m-%d %H:%M:%S')
========================================
Action: $ACTION
Target: $CLUSTER_ID
Result: $status_msg
========================================
"
    # Отправляем в меш через бинарник из конфига
    echo "$REPORT" | timeout 10 "$GORGONA_BIN" send \
        "$(date -u '+%Y-%m-%d %H:%M:%S')" \
        "$(date -u -d '+1 day' '+%Y-%m-%d %H:%M:%S')" \
        - "$PUB_KEY_FILE" >/dev/null 2>&1
}

echo -e "${BLUE}>>> Executing '$ACTION' for Cluster: $CLUSTER_ID${NC}"

case "$ACTION" in
    start)
        systemctl start "$PG_SVC" && systemctl start "$GFM_SVC"
        RESULT="Success: Services started"
        ;;
    stop)
        systemctl stop "$GFM_SVC" && systemctl stop "$PG_SVC"
        RESULT="Success: Services stopped"
        ;;
    promote)
        # Используем путь к pg_ctl из конфига
        if sudo -u postgres "$PG_CTL" "$PG_VER" "$PG_INST" promote; then
            RESULT="Success: Node promoted to MASTER"
        else
            RESULT="Error: Promotion failed (check pg_ctl_bin path)"
        fi
        ;;
    restart_gfm)
        systemctl restart "$GFM_SVC"
        RESULT="Success: GFM Manager restarted"
        ;;
    status)
        PG_ST=$(systemctl is-active "$PG_SVC")
        GFM_ST=$(systemctl is-active "$GFM_SVC")
        RESULT="Status check - Postgres: $PG_ST, GFM: $GFM_ST"
        echo -e "Postgres: $PG_ST\nGFM: $GFM_ST"
        ;;
    *)
        echo -e "${RED}Unknown action: $ACTION${NC}"
        exit 1
        ;;
esac

send_admin_event "$RESULT"

echo -e "${GREEN}$RESULT${NC}"

