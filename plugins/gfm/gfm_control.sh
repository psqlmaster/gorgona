#!/bin/bash
# /usr/local/bin/gfm_control.sh
# Универсальный контроллер для работы через gorgonad

CONF=$1
ACTION=$2

if [ -z "$CONF" ] || [ ! -f "$CONF" ]; then
    echo "Usage: $0 <config_path> <start|stop|promote|restart_gfm>"
    exit 1
fi

# Функция извлечения параметров
get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

# Извлекаем данные
CLUSTER_ID=$(get_val "cluster" "cluster_id")
PG_SVC=$(get_val "postgresql" "service_name")
PG_VER=$(get_val "postgresql" "pg_version")
PG_INST=$(get_val "postgresql" "pg_instance_name")
PG_CTL=$(get_val "paths" "pg_ctl_bin")
[ -z "$PG_CTL" ] && PG_CTL="/usr/bin/pg_ctlcluster"

GFM_SVC="gfm@${CLUSTER_ID}"

case "$ACTION" in
    start)
        echo "Starting $PG_SVC and $GFM_SVC..."
        systemctl start "$PG_SVC"
        systemctl start "$GFM_SVC"
        ;;
    stop)
        echo "Stopping $GFM_SVC and $PG_SVC..."
        systemctl stop "$GFM_SVC"
        systemctl stop "$PG_SVC"
        ;;
    promote)
        echo "Promoting $PG_SVC..."
        sudo -u postgres "$PG_CTL" "$PG_VER" "$PG_INST" promote
        ;;
    restart_gfm)
        echo "Restarting $GFM_SVC..."
        systemctl restart "$GFM_SVC"
        ;;
    *)
        echo "Unknown action: $ACTION"
        exit 1
        ;;
esac
