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
MY_NAME=$(get_val "cluster" "node_address")
[ -z "$MY_NAME" ] && MY_NAME=$(hostname)

# В именах слотов PostgreSQL допускает только буквы, цифры и подчёркивания,
# так что точки FQDN и дефисы заменяем. Длина идентификатора ограничена 63
# символами: если не влезли, оставляем читаемое начало и дописываем хеш от
# полного имени, иначе две ноды с похожими FQDN получили бы один слот.
SLOT_NAME="replica_slot_$(echo ${MY_NAME} | tr '.-' '__')_${PG_INST}"
if [ ${#SLOT_NAME} -gt 63 ]; then
    SLOT_SUFFIX=$(printf '%s' "$SLOT_NAME" | md5sum | cut -c1-8)
    SLOT_NAME="$(printf '%s' "$SLOT_NAME" | cut -c1-54)_${SLOT_SUFFIX}"
fi
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
# УЛЬТРА-ЗАЩИТА: ПРОВЕРКА РОЛЕЙ И СИНХРОНИЗАЦИЯ С ДЕМОНОМ
# ==============================================================================
LOCK_FILE="/tmp/gfm_db_query_${CLUSTER_ID}.lock"
MAINTENANCE_FLAG="/tmp/gfm_rebuild_in_progress_${CLUSTER_ID}.flag"
# Создаем флаг обслуживания (сигнал для gfm.py приостановить HA-логику)
touch "$MAINTENANCE_FLAG"
# Удаляем флаг автоматически при любом выходе из скрипта (успех или ошибка)
trap 'rm -f "$MAINTENANCE_FLAG"' EXIT
# Захватываем эксклюзивную блокировку, чтобы два скрипта ребилда не терлись друг об друга
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    log_msg "Another rebuild process is already running. Exiting."
    exit 0
fi
# Проверяем локальное состояние (Кто я сейчас?)
if sudo -u postgres "$PG_BIN/pg_isready" -p "$PG_PORT" -t 3 >/dev/null 2>&1; then
    MY_RECOVERY=$(sudo -u postgres "$PG_BIN/psql" -p "$PG_PORT" -At -c "SELECT pg_is_in_recovery();" 2>/dev/null)
    WAL_COUNT=$(sudo -u postgres "$PG_BIN/psql" -p "$PG_PORT" -At -c "SELECT count(*) FROM pg_stat_wal_receiver;" 2>/dev/null)
    # СЦЕНАРИЙ А: Я - работающая реплика. Ребилд не нужен.
    if [[ "$MY_RECOVERY" == "t" ]] && [[ "$WAL_COUNT" -gt 0 ]]; then
        REPORT="Replication is already ACTIVE and STREAMING. Rebuild aborted."
        log_msg "PROTECTION: $REPORT"
        send_gorgona_event "$REPORT"
        echo -e "${GREEN}>>> $REPORT${NC}"
        exit 0
    fi
    # СЦЕНАРИЙ Б: Я - Лидер (Master). Проверяем, не пытаемся ли мы совершить суицид.
    if [[ "$MY_RECOVERY" == "f" ]]; then
        log_msg "I am currently the LEADER. Verifying if target $MASTER_HOST is a valid source..."
        # Проверяем роль того, об кого хотим пересобраться
        TARGET_RECOVERY=$(sudo -u postgres PGPASSFILE="$PGPASSFILE" "$PG_BIN/psql" -h "$MASTER_HOST" -p "$PG_PORT" -U "$USER" -d postgres -At -c "SELECT pg_is_in_recovery();" 2>/dev/null)
        # Если цель - сама является репликой или недоступна
        if [[ "$TARGET_RECOVERY" == "t" ]] || [ -z "$TARGET_RECOVERY" ]; then
            REPORT="Refusing to rebuild: I am LEADER and target $MASTER_HOST is NOT a Master. To switch roles, use gfm_cluster_switch."
            log_msg "CRITICAL: $REPORT"
            send_gorgona_event "$REPORT"
            echo -e "${RED}>>> $REPORT${NC}"
            exit 1
        fi
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

# ==============================================================================
# 6. УМНАЯ ОЧИСТКА СИРОТСКИХ СЛОТОВ (Safe Sweep)
# ==============================================================================
log_msg "Scanning master $MASTER_HOST for inactive orphan slots..."
# Мы ищем все неактивные слоты, которые начинаются на 'replica_slot_'
# и НЕ являются нашим текущим именем ($SLOT_NAME). 
# Фильтр по $PG_INST убираем, так как длинные имена (FQDN) заканчиваются хешем.
QUERY="SELECT slot_name FROM pg_replication_slots WHERE active = 'f' AND slot_name LIKE 'replica_slot_%' AND slot_name != '$SLOT_NAME';"
# Выполняем запрос и сохраняем вывод (включая возможные ошибки в переменную)
ORPHAN_DATA=$(sudo -u postgres PGPASSFILE="$PGPASSFILE" "$PG_BIN/psql" -h "$MASTER_HOST" -p "$PG_PORT" -U "$USER" -d postgres -At -c "$QUERY" 2>&1)
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    log_msg "WARNING: Could not fetch orphan slots. Master said: $ORPHAN_DATA"
    ORPHAN_SLOTS=""
else
    # Очищаем результат от лишних пробелов и превращаем в список
    ORPHAN_SLOTS=$(echo "$ORPHAN_DATA" | xargs)
fi
if [ -n "$ORPHAN_SLOTS" ]; then
    for old_slot in $ORPHAN_SLOTS; do
        log_msg "Removing inactive orphan slot '$old_slot' from master..."
        DROP_RES=$(sudo -u postgres PGPASSFILE="$PGPASSFILE" "$PG_BIN/psql" -h "$MASTER_HOST" -p "$PG_PORT" -U "$USER" -d postgres -tAc "SELECT pg_drop_replication_slot('$old_slot');" 2>&1)
        log_msg "Master response: $DROP_RES"
    done
else
    log_msg "No inactive orphan slots found on master."
fi

# ==============================================================================
# 7. ПОПЫТКА ВОССТАНОВЛЕНИЯ (pg_rewind или pg_basebackup)
# ==============================================================================
REWIND_OK=0
if [ -f "$PG_DATA/global/pg_control" ]; then
    log_msg "Data exists. Attempting pg_rewind..."
    # pg_rewind требует доступа к базе 'postgres'
    if sudo -u postgres PGPASSFILE="$PGPASSFILE" "$PG_BIN/pg_rewind" --target-pgdata="$PG_DATA" --source-server="host=$MASTER_HOST port=$PG_PORT user=$USER dbname=postgres" >> "$LOG_FILE" 2>&1; then
        log_msg "SUCCESS: pg_rewind completed."
        REWIND_OK=1
    else
        log_msg "NOTICE: pg_rewind failed (this is normal if timelines diverged too far), falling back to full pg_basebackup."
    fi
fi

if [ $REWIND_OK -eq 0 ]; then
    log_msg "Performing full pg_basebackup from $MASTER_HOST..."
    # Очистка старых данных перед полной закачкой
    if [ -d "$PG_DATA" ] && [ -n "$PG_VER" ]; then
        rm -rf "${PG_DATA:?}"/*
    fi
    
    # Попытка создать слот во время бэкапа
    if sudo -u postgres PGPASSFILE="$PGPASSFILE" "$PG_BIN/pg_basebackup" -h "$MASTER_HOST" -p "$PG_PORT" -D "$PG_DATA" -U "$USER" -P -R \
        --slot="$SLOT_NAME" --create-slot -X stream >> "$LOG_FILE" 2>&1; then
        log_msg "SUCCESS: pg_basebackup completed with slot creation."
    else
        log_msg "WARNING: Basebackup with --create-slot failed. Trying using existing slot..."
        if sudo -u postgres PGPASSFILE="$PGPASSFILE" "$PG_BIN/pg_basebackup" -h "$MASTER_HOST" -p "$PG_PORT" -D "$PG_DATA" -U "$USER" -P -R \
            --slot="$SLOT_NAME" -X stream >> "$LOG_FILE" 2>&1; then
            log_msg "SUCCESS: pg_basebackup completed."
        else
            log_msg "FATAL: All pg_basebackup attempts failed. Check Master connectivity and HBA."
            exit 1
        fi
    fi
fi

# ==============================================================================
# 8. ФИНАЛИЗАЦИЯ (Конфиги, Слоты и Старт)
# ==============================================================================
# Сигнал для Postgres 12+, что нужно работать в режиме Standby
sudo -u postgres touch "$PG_DATA/standby.signal"

# --- Очистка и запись postgresql.auto.conf ---
log_msg "Cleaning and writing recovery configuration to postgresql.auto.conf..."
AUTO_CONF="$PG_DATA/postgresql.auto.conf"
sudo -u postgres touch "$AUTO_CONF"

# Удаляем все старые дубликаты, чтобы файл не рос (ваша защита от "слоеного пирога")
sudo -u postgres sed -i '/^primary_conninfo/d' "$AUTO_CONF"
sudo -u postgres sed -i '/^primary_slot_name/d' "$AUTO_CONF"

# Пишем одну актуальную строку
printf "primary_conninfo = 'host=%s port=%s user=%s application_name=%s'\nprimary_slot_name = '%s'\n" \
    "$MASTER_HOST" "$PG_PORT" "$USER" "$MY_NAME" "$SLOT_NAME" \
    | sudo -u postgres tee -a "$AUTO_CONF" > /dev/null

# --- Универсальная проверка слота на мастере ---
# Гарантируем, что слот существует, даже если предыдущие шаги его не создали.
log_msg "Ensuring replication slot '$SLOT_NAME' exists on master $MASTER_HOST..."
sudo -u postgres PGPASSFILE="$PGPASSFILE" "$PG_BIN/psql" -h "$MASTER_HOST" -p "$PG_PORT" -U "$USER" -d postgres -tAc \
    "SELECT pg_create_physical_replication_slot('$SLOT_NAME') WHERE NOT EXISTS \
     (SELECT 1 FROM pg_replication_slots WHERE slot_name = '$SLOT_NAME');" \
    >> "$LOG_FILE" 2>&1 || log_msg "NOTICE: Slot creation skipped (it might already be active)."

# Важно: фиксируем права владельца
chown -R postgres:postgres "$PG_DATA"

# Синхронизируем порт в основном конфиге /etc/ (для корректной работы pg_lsclusters)
CONF_PATH="/etc/postgresql/${PG_VER}/${PG_INST}/postgresql.conf"
if [ -f "$CONF_PATH" ]; then
    sed -i "s/^[#[:space:]]*port[[:space:]]*=[[:space:]]*.*/port = $PG_PORT/" "$CONF_PATH"
fi

# Финальный запуск
log_msg "Starting $PG_SVC..."
if systemctl start "$PG_SVC"; then
    log_msg "--- RECOVERY FINISHED SUCCESSFULLY ---"
else
    log_msg "FATAL: Service $PG_SVC failed to start. Check Postgres logs: /var/log/postgresql/..."
    exit 1
fi
