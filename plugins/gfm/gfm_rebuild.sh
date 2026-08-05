#!/bin/bash
#cat /usr/local/bin/gfm_rebuild.sh
set -x
# Smart Recovery Script for PostgreSQL 17 (Ultra-Reliable)
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

# 1. Определяем мастера
if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "null" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    MASTER_HOST=$(grep -oP '"leader": "\K[^"]+' /etc/gorgona/cluster_status.json)
fi

# Если мастер всё еще я сам или не определен - ищем через меш (альтернативный способ)
if [ "$MASTER_HOST" == "$MY_NAME" ] || [ -z "$MASTER_HOST" ]; then
    log_msg "JSON Leader is stale or me. Scanning mesh for LEADER_STATUS..."
    MASTER_HOST=$(/usr/bin/gorgona listen last 5 +I9IQuXYW8I= | grep "LEADER_STATUS" | grep -v "$MY_NAME" | head -n 1 | cut -d'|' -f2)
fi

log_msg "Target Master resolved to: $MASTER_HOST"

if [ -z "$MASTER_HOST" ] || [ "$MASTER_HOST" == "$MY_NAME" ]; then
    log_msg "FATAL: Could not identify a remote Master. Standby cannot rebuild from itself."
    exit 1
fi

# 2. Проверка связи перед деструктивными действиями
if ! sudo -u postgres $PG_BIN/pg_isready -h "$MASTER_HOST" -t 5; then
    log_msg "FATAL: Master $MASTER_HOST is not accepting connections. Aborting rebuild."
    exit 1
fi

# 3. Остановка
systemctl stop postgresql

# 4. Ребилд
if [ -f "$PG_DATA/global/pg_control" ]; then
    log_msg "Attempting pg_rewind..."
    sudo -u postgres $PG_BIN/pg_rewind --target-pgdata="$PG_DATA" --source-server="host=$MASTER_HOST user=$USER dbname=postgres" >> "$LOG_FILE" 2>&1
    [ $? -eq 0 ] && REWIND_OK=1
fi

if [ -z "$REWIND_OK" ]; then
    log_msg "Rewind failed or not possible. Performing full pg_basebackup..."
    rm -rf ${PG_DATA:?}/*
    
    # Пытаемся сделать бэкап (с автоматическим созданием слота)
    sudo -u postgres $PG_BIN/pg_basebackup -h "$MASTER_HOST" -D "$PG_DATA" -U "$USER" -P -R \
        --slot="$SLOT_NAME" --create-slot -X stream --no-password >> "$LOG_FILE" 2>&1
    
    if [ $? -ne 0 ]; then
        log_msg "Basebackup failed. Trying without --create-slot (if slot exists)..."
        sudo -u postgres $PG_BIN/pg_basebackup -h "$MASTER_HOST" -D "$PG_DATA" -U "$USER" -P -R \
            --slot="$SLOT_NAME" -X stream --no-password >> "$LOG_FILE" 2>&1
    fi
fi

if [ $? -ne 0 ]; then
    log_msg "FATAL: All recovery methods failed."
    exit 1
fi

# 5. Запуск
sudo -u postgres touch "$PG_DATA/standby.signal"
systemctl start postgresql
log_msg "--- RECOVERY FINISHED SUCCESS ---"
