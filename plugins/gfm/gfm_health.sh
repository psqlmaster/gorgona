#!/bin/bash
# vim /usr/local/bin/gfm_health.sh
# Комплексный отчет здоровья узла GFM + Postgres (Устойчивая версия)

NODE_NAME=$(hostname)
STATUS_FILE="/etc/gorgona/cluster_status.json"
PUB_KEY="zpPVK9fbEqo=.pub" 

# 1. Собираем данные из GFM JSON (безопасно)
if [ -f "$STATUS_FILE" ]; then
    GFM_ROLE=$(grep -oP '"role": "\K[^"]+' $STATUS_FILE || echo "UNKNOWN")
    GFM_LEADER=$(grep -oP '"leader": "\K[^"]+' $STATUS_FILE || echo "None")
    GFM_LSN=$(grep -oP '"lsn": "\K[^"]+' $STATUS_FILE || echo "0/0")
else
    GFM_ROLE="GFM_FILE_MISSING"
    GFM_LEADER="None"
    GFM_LSN="0/0"
fi

# 2. Проверяем, жив ли Postgres вообще
PG_UP=$(sudo -u postgres pg_isready -t 1 >/dev/null 2>&1 && echo "yes" || echo "no")

if [ "$PG_UP" == "no" ]; then
    PG_MODE="DOWN"
    PG_LSN="0/0"
    REPLICATION_INFO="CRITICAL: Postgres socket not responding!"
else
    # Если база жива, собираем данные
    PG_RECOVERY=$(sudo -u postgres psql -At -c "SELECT pg_is_in_recovery();" 2>/dev/null)
    
    if [ "$PG_RECOVERY" == "f" ]; then
        PG_MODE="MASTER (RW)"
        PG_LSN=$(sudo -u postgres psql -At -c "SELECT pg_current_wal_lsn();" 2>/dev/null)
        REPLICATION_INFO=$(sudo -u postgres psql -At -c "SELECT COALESCE(string_agg(format('Replica: %s | State: %s', client_addr, state), E'\n'), 'No active replicas connected') FROM pg_stat_replication;" 2>/dev/null)
    else
        PG_MODE="STANDBY (RO)"
        PG_LSN=$(sudo -u postgres psql -At -c "SELECT GREATEST(COALESCE(pg_last_wal_receive_lsn(), '0/0'), COALESCE(pg_last_wal_replay_lsn(), '0/0'));" 2>/dev/null)
        REPLICATION_INFO=$(sudo -u postgres psql -At -c "SELECT format('Source: %s | Status: %s | Slot: %s', sender_host, status, slot_name) FROM pg_stat_wal_receiver;" 2>/dev/null)
        # Если строк нет, psql вернет пустоту - заменяем на понятный текст
        [ -z "$REPLICATION_INFO" ] && REPLICATION_INFO="WARNING: No replication process (wal_receiver is idle)"
    fi
fi

# 3. Формируем финальный текст отчета
REPORT="
========================================
HEALTH REPORT: $NODE_NAME
Date: $(date '+%Y-%m-%d %H:%M:%S')
========================================
[GFM LAYER]
Role:   $GFM_ROLE
Leader: $GFM_LEADER
LSN:    $GFM_LSN

[DATABASE LAYER]
Mode:   $PG_MODE
LSN:    ${PG_LSN:-0/0}

[REPLICATION]
${REPLICATION_INFO}
========================================
"

# 4. Отправляем отчет в меш Gorgona
# Используем timeout чтобы отчет не завис если gorgonad перегружен
echo "$REPORT" | timeout 10 /usr/bin/gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 days' '+%Y-%m-%d %H:%M:%S')" - "$PUB_KEY"

# Вывод в локальный лог для отладки
echo "$REPORT" >> /var/log/gfm_health_local.log
