#!/bin/bash
# /usr/local/bin/gfm_rebuild.sh
# Smart Recovery Script for PostgreSQL (Multi-Instance Version)

CONF_SRC=$1
MASTER_HOST=$2 

# --- Цвета для вывода ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo -e "${BLUE}GFM Smart Rebuild Tool${NC}"
    echo -e "Использование: $0 ${GREEN}<путь_к_конфигу>${NC} [IP_мастера]"
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

# 1. Чтение параметров
CLUSTER_ID=$(get_val "cluster" "cluster_id")
MY_PUB_HASH=$(get_val "cluster" "my_pub_hash")
PG_SVC=$(get_val "postgresql" "service_name")
PG_VER=$(get_val "postgresql" "pg_version")
PG_INST=$(get_val "postgresql" "pg_instance_name")
PG_PORT=$(get_val "postgresql" "port")
[ -z "$PG_PORT" ] && PG_PORT=5432
GORGONA_BIN=$(get_val "paths" "gorgona_bin")
[ -z "$GORGONA_BIN" ] && GORGONA_BIN="/usr/bin/gorgona"

PG_DATA="/var/lib/postgresql/${PG_VER}/${PG_INST}"
PG_BIN="/usr/lib/postgresql/${PG_VER}/bin"
STATUS_FILE="/etc/gorgona/status_${CLUSTER_ID}.json"
LOG_FILE="/var/log/gorgona/rebuild_${CLUSTER_ID}.log"

USER="repuser"
export PGPASSFILE="/var/lib/postgresql/.pgpass"
MY_NAME=$(hostname)
SLOT_NAME="replica_slot_$(echo ${MY_NAME} | tr '-' '_')_${PG_INST}"
PUB_KEY_ARG="${MY_PUB_HASH}.pub"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$CLUSTER_ID] $1" | tee -a "$LOG_FILE"
}

# --- Функция отправки сообщения в меш Gorgona ---
send_gorgona_event() {
    local event_text=$1
    local start_time=$(date -u +'%Y-%m-%d %H:%M:%S')
    local end_time=$(date -u -d "+1 hour" +'%Y-%m-%d %H:%M:%S')
    local msg="EVENT|$CLUSTER_ID|$MY_NAME|$event_text"
    
    # Отправка через бинарник gorgona
    $GORGONA_BIN send "$start_time" "$end_time" "$msg" "$PUB_KEY_ARG" >/dev/null 2>&1
}

mkdir -p /var/log/gorgona
log_msg "--- START RECOVERY CHECK ---"

# ==============================================================================
# ЗАЩИТА: ПРОВЕРКА ТЕКУЩЕЙ РЕПЛИКАЦИИ
# ==============================================================================
# Если Postgres запущен, проверяем, не работает ли уже репликация
if sudo -u postgres "$PG_BIN/pg_isready" -p "$PG_PORT" -t 3 >/dev/null 2>&1; then
    IS_RECOVERY=$(sudo -u postgres "$PG_BIN/psql" -p "$PG_PORT" -At -c "SELECT pg_is_in_recovery();" 2>/dev/null)
    WAL_RECEIVER_ACTIVE=$(sudo -u postgres "$PG_BIN/psql" -p "$PG_PORT" -At -c "SELECT count(*) FROM pg_stat_wal_receiver;" 2>/dev/null)

    if [[ "$IS_RECOVERY" == "t" ]] && [[ "$WAL_RECEIVER_ACTIVE" -gt 0 ]]; then
        REPORT="Replication is already ACTIVE and STREAMING. Rebuild aborted. To change leader use: gfm_cluster_switch"
        log_msg "PROTECTION: $REPORT"
        send_gorgona_event "$REPORT"
        echo -e "${GREEN}>>> $REPORT${NC}"
        exit 0
    fi
fi
# ==============================================================================

# 3. Поиск мастера
if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "null" ]; then
    log_msg "Master IP not provided. Checking local status JSON..."
    if [ -f "$STATUS_FILE" ]; then
        MASTER_HOST=$(grep -oP '"leader": "\K[^"]+' "$STATUS_FILE")
    fi
fi

if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "null" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    log_msg "JSON Leader is stale/empty. Scanning mesh history for LEADER_STATUS..."
    MASTER_HOST=$($GORGONA_BIN listen last 20 "$MY_PUB_HASH" | grep -A 1 "Decrypted Content:" | grep "LEADER_STATUS" | grep -v "$MY_NAME" | tail -n 1 | cut -d'|' -f2)
fi

log_msg "Target Master resolved to: $MASTER_HOST"

if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    log_msg "FATAL: Could not identify a remote Master. Check mesh network."
    exit 1
fi

# 4. Проверка связи с мастером
if ! sudo -u postgres "$PG_BIN/pg_isready" -h "$MASTER_HOST" -p "$PG_PORT" -t 10; then
    log_msg "FATAL: Master $MASTER_HOST is not accepting connections on port $PG_PORT."
    exit 1
fi

# 5. Остановка локального сервиса
log_msg "Stopping local service $PG_SVC..."
systemctl stop "$PG_SVC"

# 6. Попытка восстановления (pg_rewind или pg_basebackup)
REWIND_OK=0
if [ -f "$PG_DATA/global/pg_control" ]; then
    log_msg "Data exists. Attempting pg_rewind..."
    if sudo -u postgres "$PG_BIN/pg_rewind" --target-pgdata="$PG_DATA" --source-server="host=$MASTER_HOST port=$PG_PORT user=$USER dbname=postgres" >> "$LOG_FILE" 2>&1; then
        log_msg "SUCCESS: pg_rewind completed."
        REWIND_OK=1
    else
        log_msg "NOTICE: pg_rewind failed, falling back to full pg_basebackup."
    fi
fi

if [ $REWIND_OK -eq 0 ]; then
    log_msg "Performing full pg_basebackup..."
    if [ -d "$PG_DATA" ] && [ -n "$PG_VER" ]; then
        rm -rf "${PG_DATA:?}"/*
    fi
    
    if sudo -u postgres "$PG_BIN/pg_basebackup" -h "$MASTER_HOST" -p "$PG_PORT" -D "$PG_DATA" -U "$USER" -P -R \
        --slot="$SLOT_NAME" --create-slot -X stream --no-password >> "$LOG_FILE" 2>&1; then
        log_msg "SUCCESS: pg_basebackup completed with slot creation."
    else
        log_msg "WARNING: Basebackup with --create-slot failed. Trying using existing slot..."
        if sudo -u postgres "$PG_BIN/pg_basebackup" -h "$MASTER_HOST" -p "$PG_PORT" -D "$PG_DATA" -U "$USER" -P -R \
            --slot="$SLOT_NAME" -X stream --no-password >> "$LOG_FILE" 2>&1; then
            log_msg "SUCCESS: pg_basebackup completed."
        else
            log_msg "FATAL: All pg_basebackup attempts failed."
            exit 1
        fi
    fi
fi

# 7. Финализация
sudo -u postgres touch "$PG_DATA/standby.signal"

if [ $REWIND_OK -eq 1 ]; then
    log_msg "Writing recovery configuration for master $MASTER_HOST..."
    AUTO_CONF="$PG_DATA/postgresql.auto.conf"
    sudo -u postgres touch "$AUTO_CONF"
    sudo -u postgres sed -i '/^primary_conninfo/d; /^primary_slot_name/d' "$AUTO_CONF"
    printf "primary_conninfo = 'host=%s port=%s user=%s application_name=%s'\nprimary_slot_name = '%s'\n" \
        "$MASTER_HOST" "$PG_PORT" "$USER" "$MY_NAME" "$SLOT_NAME" \
        | sudo -u postgres tee -a "$AUTO_CONF" > /dev/null

    log_msg "Ensuring replication slot $SLOT_NAME on $MASTER_HOST..."
    sudo -u postgres "$PG_BIN/psql" -h "$MASTER_HOST" -p "$PG_PORT" -U "$USER" -d postgres -tAc \
        "SELECT pg_create_physical_replication_slot('$SLOT_NAME') WHERE NOT EXISTS \
         (SELECT 1 FROM pg_replication_slots WHERE slot_name = '$SLOT_NAME');" \
        >> "$LOG_FILE" 2>&1
fi

chown -R postgres:postgres "$PG_DATA"

CONF_PATH="/etc/postgresql/${PG_VER}/${PG_INST}/postgresql.conf"
if [ -f "$CONF_PATH" ]; then
    sed -i "s/^port[[:space:]]*=[[:space:]]*.*/port = $PG_PORT/" "$CONF_PATH"
fi

log_msg "Starting $PG_SVC..."
systemctl start "$PG_SVC"
log_msg "--- RECOVERY FINISHED SUCCESSFULLY ---"
