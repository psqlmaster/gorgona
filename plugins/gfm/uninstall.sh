#!/bin/bash
# GFM Cluster Instance Uninstaller (Config-based)

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

CONF_SRC=""
EXCLUDE_DB=false

usage() {
    echo -e "${YELLOW}GFM Instance Uninstaller${NC}"
    echo -e "Использование: $0 ${GREEN}<путь_к_конфигу>${NC} [опции]"
    echo -e ""
    echo -e "Опции:"
    echo -e "  ${BLUE}--exclude-db${NC}    Остановить БД, но НЕ удалять её (сохранить данные)."
    exit 1
}

# Парсинг аргументов
for arg in "$@"; do
    case $arg in
        --exclude-db) EXCLUDE_DB=true ;;
        -h|--help) usage ;;
        *) [ -z "$CONF_SRC" ] && CONF_SRC=$arg ;;
    esac
done

if [ -z "$CONF_SRC" ] || [ ! -f "$CONF_SRC" ]; then
    echo -e "${RED}Ошибка: Файл конфигурации не найден!${NC}"
    usage
fi

get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF_SRC" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

CLUSTER_ID=$(get_val "cluster" "cluster_id")
RAW_NODES=$(get_val "cluster" "quorum_nodes")
PG_VER=$(get_val "postgresql" "pg_version")
PG_INST=$(get_val "postgresql" "pg_instance_name")
PG_SVC=$(get_val "postgresql" "service_name")
PG_PORT=$(get_val "postgresql" "port")

if [ -z "$CLUSTER_ID" ]; then echo -e "${RED}Error: cluster_id not found!${NC}"; exit 1; fi

IFS=',' read -ra ADDR_ARRAY <<< "$RAW_NODES"

echo -e "${RED}--- GFM Uninstallation Started ---${NC}"
echo -e "Target Cluster ID : ${YELLOW}$CLUSTER_ID${NC}"

if [ "$EXCLUDE_DB" = true ]; then
    echo -e "PostgreSQL Action : ${BLUE}STOP ONLY${NC} (Data preserved)"
else
    echo -e "PostgreSQL Action : ${RED}DROP CLUSTER${NC} (Data will be DELETED)"
fi

echo -ne "Confirm uninstallation? (y/N): "
read -r confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

for entry in "${ADDR_ARRAY[@]}"; do
    entry=$(echo $entry | xargs)
    IP=$(echo $entry | cut -d':' -f1)
    PORT=$(echo $entry | cut -d':' -f2)

    [ "$PORT" == "$PG_PORT" ] && ROLE="database" || ROLE="witness"

    echo -e "${BLUE}>>> Cleaning Node: $IP ($ROLE)${NC}"
    
    ssh -n -o StrictHostKeyChecking=no root@$IP "
        # 1. Остановка GFM
        systemctl stop gfm@${CLUSTER_ID} 2>/dev/null
        systemctl disable gfm@${CLUSTER_ID} 2>/dev/null
        
        # 2. Работа с Postgres
        if [ \"$ROLE\" == \"database\" ]; then
            if [ \"$EXCLUDE_DB\" = true ]; then
                echo 'Stopping service...'
                systemctl stop ${PG_SVC} 2>/dev/null
            else
                echo 'Dropping data...'
                pg_dropcluster --stop ${PG_VER} ${PG_INST} 2>/dev/null
            fi
        fi

        # 3. Удаление специфичных для инстанса файлов
        rm -f /etc/gorgona/gfm_${CLUSTER_ID}.conf
        rm -f /etc/gorgona/status_${CLUSTER_ID}.json
        rm -f /var/log/gorgona/rebuild_${CLUSTER_ID}.log

        # 4. Если это был последний GFM инстанс на этой ноде — полная зачистка бинарников
        if ! ls /etc/gorgona/gfm_*.conf >/dev/null 2>&1; then
            echo 'No other GFM instances. Removing binaries and shared services...'
            rm -f /usr/local/bin/gfm.py
            rm -f /usr/local/bin/gfm_rebuild.sh
            rm -f /etc/systemd/system/gfm@.service
            
            systemctl stop gfm-remote 2>/dev/null
            systemctl disable gfm-remote 2>/dev/null
            rm -f /etc/systemd/system/gfm-remote.service
            
            # Удаляем заглушку psql если она осталась от witness
            [ -L /usr/bin/psql ] && [ \"\$(readlink /usr/bin/psql)\" == \"/usr/bin/true\" ] && rm -f /usr/bin/psql
        fi
        
        systemctl daemon-reload
    "
done

echo -e "${GREEN}Uninstall of '$CLUSTER_ID' complete.${NC}"
