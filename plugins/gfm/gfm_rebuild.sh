#!/bin/bash
# Smart Recovery Script for PostgreSQL 17 (Ultra-Reliable V2)
LOG_FILE="/var/log/gorgona_rebuild.log"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

MASTER_HOST=$1
MY_NAME=$(hostname)
PG_DATA="/var/lib/postgresql/17/main"
PG_BIN="/usr/lib/postgresql/17/bin"
USER="repuser"
export PGPASSFILE="/var/lib/postgresql/.pgpass"
SLOT_NAME="replica_slot_${MY_NAME}"

log_msg "--- START RECOVERY ATTEMPT ---"

# 1. Поиск мастера: пробуем JSON, если пусто - сканируем меш
if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "null" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    MASTER_HOST=$(grep -oP '"leader": "\K[^"]+' /etc/gorgona/cluster_status.json)
fi

if [ "$MASTER_HOST" == "$MY_NAME" ] || [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "null" ]; then
    log_msg "JSON Leader is stale. Scanning mesh history for LEADER_STATUS..."
    # Улучшенный поиск: берем строку ПОСЛЕ 'Decrypted Content:' которая содержит '|'
    MASTER_HOST=$(/usr/bin/gorgona listen last 20 +I9IQuXYW8I= | grep -A 1 "Decrypted Content:" | grep "LEADER_STATUS" | grep -v "$MY_NAME" | tail -n 1 | cut -d'|' -f2)
fi

log_msg "Target Master resolved to: $MASTER_HOST"

if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    log_msg "FATAL: Could not identify a remote Master. Check if the other node is LEADER."
    exit 1
fi

# 2. Проверка связи
if ! sudo -u postgres $PG_BIN/pg_isready -h "$MASTER_HOST" -t 10; then
    log_msg "FATAL: Master $MASTER_HOST is not accepting connections (pg_isready failed)."
    exit 1
fi

# 3. Остановка локальной базы
systemctl stop postgresql

# 4. Ребилд
# Если папка жива - пробуем rewind
if [ -f "$PG_DATA/global/pg_control" ]; then
    log_msg "Attempting pg_rewind..."
    sudo -u postgres $PG_BIN/pg_rewind --target-pgdata="$PG_DATA" --source-server="host=$MASTER_HOST user=$USER dbname=postgres" >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
        REWIND_OK=1
        log_msg "SUCCESS: pg_rewind completed."
    fi
fi

if [ -z "$REWIND_OK" ]; then
    log_msg "Performing full pg_basebackup (rewind failed or DB empty)..."
    rm -rf ${PG_DATA:?}/*
    sudo -u postgres $PG_BIN/pg_basebackup -h "$MASTER_HOST" -D "$PG_DATA" -U "$USER" -P -R \
        --slot="$SLOT_NAME" --create-slot -X stream --no-password >> "$LOG_FILE" 2>&1
    
    if [ $? -ne 0 ]; then
        log_msg "Basebackup failed. Trying without --create-slot..."
        sudo -u postgres $PG_BIN/pg_basebackup -h "$MASTER_HOST" -D "$PG_DATA" -U "$USER" -P -R \
            --slot="$SLOT_NAME" -X stream --no-password >> "$LOG_FILE" 2>&1
    fi
fi

if [ $? -ne 0 ]; then
    log_msg "FATAL: All recovery methods failed."
    exit 1
fi

# 5. Финализация
sudo -u postgres touch "$PG_DATA/standby.signal"
chown -R postgres:postgres "$PG_DATA"
systemctl start postgresql
log_msg "--- RECOVERY FINISHED SUCCESS ---"

