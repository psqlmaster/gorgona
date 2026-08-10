#!/bin/bash
# vim: set ts=4 sw=4 et:
# /usr/local/bin/gfm_health.sh
# Комплексный отчет здоровья узла GFM + Postgres (Multi-instance + Admin Key)

CONF_SRC=$1

# --- Цвета для локального вывода (при ручном запуске) ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# --- Функция подсказки ---
usage() {
    echo -e "${BLUE}GFM Health Reporter${NC}"
    echo -e "Использование: $0 ${GREEN}<путь_к_конфигу>${NC}"
    echo -e "Пример: $0 /etc/gorgona/gfm_pg_prod_5432.conf"
    exit 1
}

# 0. Проверка аргумента (путь к конфигу обязателен)
if [ -z "$CONF_SRC" ] || [ ! -f "$CONF_SRC" ]; then
    usage
fi

# --- Функция извлечения параметров из конфига ---
get_val() {
    local section=$1
    local key=$2
    # Отрезаем комментарии, кавычки, пробелы и символы \r
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF_SRC" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

# 1. Чтение параметров кластера и идентификации
CLUSTER_ID=$(get_val "cluster" "cluster_id")
# Ключ, на который отправляем отчет (Админский)
ADMIN_PUB_HASH=$(get_val "cluster" "admin_pub_hash")
# Если админский ключ не задан, используем локальный (фолбэк)
[ -z "$ADMIN_PUB_HASH" ] && ADMIN_PUB_HASH=$(get_val "cluster" "my_pub_hash")

GORGONA_BIN=$(get_val "paths" "gorgona_bin")
[ -z "$GORGONA_BIN" ] && GORGONA_BIN="/usr/bin/gorgona"

NODE_NAME=$(hostname)
BASE_DIR="/etc/gorgona"
STATUS_FILE="${BASE_DIR}/status_${CLUSTER_ID}.json"
# Файл ключа должен называться <hash>.pub
PUB_KEY_FILE="${ADMIN_PUB_HASH}.pub"

# 2. Собираем данные из GFM JSON (безопасно)
if [ -f "$STATUS_FILE" ]; then
    GFM_ROLE=$(grep -oP '"role": "\K[^"]+' "$STATUS_FILE" || echo "UNKNOWN")
    GFM_LEADER=$(grep -oP '"leader": "\K[^"]+' "$STATUS_FILE" || echo "None")
    GFM_LSN=$(grep -oP '"lsn": "\K[^"]+' "$STATUS_FILE" || echo "0/0")
    GFM_REBUILD=$(grep -oP '"rebuild_active": \K[^,]+' "$STATUS_FILE" || echo "false")
else
    GFM_ROLE="GFM_STATUS_MISSING"
    GFM_LEADER="None"
    GFM_LSN="0/0"
    GFM_REBUILD="unknown"
fi

# 3. Проверка режима Witness (если нет базы, пропускаем SQL тесты)
IS_WITNESS=false
[ -f "${BASE_DIR}/node_type_${CLUSTER_ID}" ] && [ "$(cat ${BASE_DIR}/node_type_${CLUSTER_ID})" == "WITNESS_MODE" ] && IS_WITNESS=true

if [ "$IS_WITNESS" = true ]; then
    PG_MODE="WITNESS (Arbitrator)"
    PG_LSN="n/a"
    REPLICATION_INFO="Witness node does not store database data."
else
    # 4. Проверяем состояние PostgreSQL
    PG_UP=$(sudo -u postgres pg_isready -t 1 >/dev/null 2>&1 && echo "yes" || echo "no")

    if [ "$PG_UP" == "no" ]; then
        PG_MODE="DOWN"
        PG_LSN="0/0"
        REPLICATION_INFO="CRITICAL: PostgreSQL is NOT responding on local socket!"
    else
        # База жива, собираем детальный статус через SQL
        PG_RECOVERY=$(timeout 3s sudo -u postgres psql -At -c "SELECT pg_is_in_recovery();" 2>/dev/null)
        
        if [ "$PG_RECOVERY" == "f" ]; then
            PG_MODE="MASTER (RW)"
            PG_LSN=$(timeout 3s sudo -u postgres psql -At -c "SELECT pg_current_wal_lsn();" 2>/dev/null)
            
            # Считаем отставание в байтах (через pg_wal_lsn_diff) и время
            QUERY="
            SELECT COALESCE(string_agg(
                format('Replica: %s | State: %s | Lag: %s bytes | Time: %s', 
                    client_addr, 
                    state, 
                    pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn),
                    COALESCE(replay_lag::text, '00:00:00')
                ), E'\n'), 'No active replicas connected') 
            FROM pg_stat_replication;"
            
            REPLICATION_INFO=$(timeout 3s sudo -u postgres psql -At -c "$QUERY" 2>/dev/null)
        elif [ "$PG_RECOVERY" == "t" ]; then
            PG_MODE="STANDBY (RO)"
            # Для Standby берем максимальный LSN из полученного/проигранного
            PG_LSN=$(timeout 3s sudo -u postgres psql -At -c "SELECT GREATEST(COALESCE(pg_last_wal_receive_lsn(), '0/0'), COALESCE(pg_last_wal_replay_lsn(), '0/0'));" 2>/dev/null)
            # Состояние процесса приема WAL
            REPLICATION_INFO=$(timeout 3s sudo -u postgres psql -At -c "SELECT format('Source: %s | Status: %s | Delay: %s', sender_host, status, last_msg_receipt_time) FROM pg_stat_wal_receiver;" 2>/dev/null)
            [ -z "$REPLICATION_INFO" ] && REPLICATION_INFO="WARNING: Wal_receiver is idle (no master connection)"
        else
            PG_MODE="ERROR"
            REPLICATION_INFO="Failed to query pg_is_in_recovery status."
        fi
    fi
fi

# 5. Формируем финальный текст отчета
REPORT="
========================================
HEALTH REPORT: $NODE_NAME ($CLUSTER_ID)
Date: $(date '+%Y-%m-%d %H:%M:%S')
========================================
[GFM LAYER]
Cluster ID: $CLUSTER_ID
Role:       $GFM_ROLE
Leader:     $GFM_LEADER
LSN:        $GFM_LSN
Rebuilding: $GFM_REBUILD

[DATABASE LAYER]
Mode:       $PG_MODE
LSN:        ${PG_LSN:-0/0}

[REPLICATION STATUS]
${REPLICATION_INFO}
========================================
"

# 6. Отправка отчета в меш (на ключ АДМИНИСТРАТОРА)
# Мы устанавливаем время жизни сообщения 1 день
echo "$REPORT" | timeout 12 "$GORGONA_BIN" send \
    "$(date -u '+%Y-%m-%d %H:%M:%S')" \
    "$(date -u -d '+1 day' '+%Y-%m-%d %H:%M:%S')" \
    - "$PUB_KEY_FILE"

# 7. Локальное логирование для истории на узле
LOG_FILE="/var/log/gorgona/health_${CLUSTER_ID}.log"
mkdir -p /var/log/gorgona
echo "$REPORT" >> "$LOG_FILE"

# Ротация локального лога (оставляем последние 500 строк)
if [ -f "$LOG_FILE" ]; then
    tail -n 500 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi

# Вывод в консоль (для ручной проверки и логов gorgonad)
echo "$REPORT"
