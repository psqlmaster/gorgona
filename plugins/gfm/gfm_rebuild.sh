#!/bin/bash
# /usr/local/bin/gfm_rebuild.sh
# Smart Recovery Script for PostgreSQL (Multi-Instance Version)

CONF_SRC=$1
MASTER_HOST=$2  # Может быть пустым, тогда ищем сами

# --- Цвета для вывода ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo -e "${BLUE}GFM Smart Rebuild Tool${NC}"
    echo -e "Использование: $0 ${GREEN}<путь_к_конфигу>${NC} [IP_мастера]"
    echo -e "Пример: $0 /etc/gorgona/gfm_pg_prod_5432.conf 192.168.1.170"
    exit 1
}

if [ -z "$CONF_SRC" ] || [ ! -f "$CONF_SRC" ]; then
    usage
fi

# --- Функция чтения конфига ---
get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF_SRC" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

# 1. Чтение параметров из конфига
CLUSTER_ID=$(get_val "cluster" "cluster_id")
MY_PUB_HASH=$(get_val "cluster" "my_pub_hash")
PG_SVC=$(get_val "postgresql" "service_name")
PG_VER=$(get_val "postgresql" "pg_version")
PG_INST=$(get_val "postgresql" "pg_instance_name")
GORGONA_BIN=$(get_val "paths" "gorgona_bin")
[ -z "$GORGONA_BIN" ] && GORGONA_BIN="/usr/bin/gorgona"

# 2. Динамические пути (Стандартные для Debian/Ubuntu)
PG_DATA="/var/lib/postgresql/${PG_VER}/${PG_INST}"
PG_BIN="/usr/lib/postgresql/${PG_VER}/bin"
STATUS_FILE="/etc/gorgona/status_${CLUSTER_ID}.json"
LOG_FILE="/var/log/gorgona/rebuild_${CLUSTER_ID}.log"

# Параметры подключения
USER="repuser"
export PGPASSFILE="/var/lib/postgresql/.pgpass"
MY_NAME=$(hostname)
SLOT_NAME="replica_slot_$(echo ${MY_NAME} | tr '-' '_')_${PG_INST}"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$CLUSTER_ID] $1" | tee -a "$LOG_FILE"
}

mkdir -p /var/log/gorgona
log_msg "--- START RECOVERY ATTEMPT ---"

# 3. Поиск мастера, если он не передан вторым аргументом
if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "null" ]; then
    log_msg "Master IP not provided. Checking local status JSON..."
    if [ -f "$STATUS_FILE" ]; then
        MASTER_HOST=$(grep -oP '"leader": "\K[^"]+' "$STATUS_FILE")
    fi
fi

if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "null" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    log_msg "JSON Leader is stale/empty. Scanning mesh history for LEADER_STATUS..."
    # Ищем последнее сообщение в меше для этого конкретного кластера
    MASTER_HOST=$($GORGONA_BIN listen last 20 "$MY_PUB_HASH" | grep -A 1 "Decrypted Content:" | grep "LEADER_STATUS" | grep -v "$MY_NAME" | tail -n 1 | cut -d'|' -f2)
fi

log_msg "Target Master resolved to: $MASTER_HOST"

if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    log_msg "FATAL: Could not identify a remote Master. Check mesh network."
    exit 1
fi

# 4. Проверка связи с мастером
if ! sudo -u postgres "$PG_BIN/pg_isready" -h "$MASTER_HOST" -t 10; then
    log_msg "FATAL: Master $MASTER_HOST is not accepting connections (pg_isready failed)."
    exit 1
fi

# 5. Остановка локального сервиса
log_msg "Stopping local service $PG_SVC..."
systemctl stop "$PG_SVC"

# 6. Попытка восстановления (pg_rewind или pg_basebackup)
REWIND_OK=0
if [ -f "$PG_DATA/global/pg_control" ]; then
    log_msg "Data exists. Attempting pg_rewind to save bandwidth..."
    # pg_rewind требует, чтобы в postgresql.conf был включен wal_log_hints или чекпоинты
    if sudo -u postgres "$PG_BIN/pg_rewind" --target-pgdata="$PG_DATA" --source-server="host=$MASTER_HOST user=$USER dbname=postgres" >> "$LOG_FILE" 2>&1; then
        log_msg "SUCCESS: pg_rewind completed."
        REWIND_OK=1
    else
        log_msg "NOTICE: pg_rewind failed (this is normal if timelines diverged too much)."
    fi
fi

if [ $REWIND_OK -eq 0 ]; then
    log_msg "Performing full pg_basebackup (rewind failed or DB empty)..."
    # Очистка старых данных (БЕЗОПАСНО: только если переменная PG_DATA не пустая)
    if [ -d "$PG_DATA" ] && [ -n "$PG_VER" ]; then
        rm -rf "${PG_DATA:?}"/*
    fi
    
    # Первая попытка с созданием слота
    if sudo -u postgres "$PG_BIN/pg_basebackup" -h "$MASTER_HOST" -D "$PG_DATA" -U "$USER" -P -R \
        --slot="$SLOT_NAME" --create-slot -X stream --no-password >> "$LOG_FILE" 2>&1; then
        log_msg "SUCCESS: pg_basebackup completed with slot creation."
    else
        log_msg "WARNING: Basebackup with --create-slot failed. Trying using existing slot..."
        if sudo -u postgres "$PG_BIN/pg_basebackup" -h "$MASTER_HOST" -D "$PG_DATA" -U "$USER" -P -R \
            --slot="$SLOT_NAME" -X stream --no-password >> "$LOG_FILE" 2>&1; then
            log_msg "SUCCESS: pg_basebackup completed."
        else
            log_msg "FATAL: All pg_basebackup attempts failed."
            exit 1
        fi
    fi
fi

# 7. Финализация
# В современных версиях PG (12+) standby.signal создается автоматически ключом -R в pg_basebackup,
# но мы подстрахуемся для надежности.
sudo -u postgres touch "$PG_DATA/standby.signal"
chown -R postgres:postgres "$PG_DATA"

log_msg "Starting $PG_SVC..."
systemctl start "$PG_SVC"

log_msg "--- RECOVERY FINISHED SUCCESSFULLY ---"
