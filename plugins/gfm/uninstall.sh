#!/bin/bash
# GFM Cluster Instance Uninstaller (with DB preservation option)

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

CONF_SRC=""
EXCLUDE_DB=false
NODES_FILE="nodes.list"

usage() {
    echo -e "${YELLOW}GFM Instance Uninstaller${NC}"
    echo -e "Использование: $0 ${GREEN}<путь_к_конфигу>${NC} [опции]"
    echo -e ""
    echo -e "Опции:"
    echo -e "  ${BLUE}--exclude-db${NC}    Остановить базу данных, но НЕ удалять её (сохранить данные)."
    echo -e "  -h, --help      Показать эту справку."
    echo -e ""
    echo -e "Пример:"
    echo -e "  $0 ./gfm_prod_5432.conf --exclude-db"
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
    echo -e "${RED}Ошибка: Файл конфигурации не указан или не найден!${NC}"
    usage
fi

# Функция чтения конфига
get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF_SRC" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

CLUSTER_ID=$(get_val "cluster" "cluster_id")
PG_VER=$(get_val "postgresql" "pg_version")
PG_INST=$(get_val "postgresql" "pg_instance_name")
PG_SVC=$(get_val "postgresql" "service_name")

if [ -z "$CLUSTER_ID" ]; then
    echo -e "${RED}Error: Could not find cluster_id in $CONF_SRC${NC}"
    exit 1
fi

echo -e "${RED}--- GFM Uninstallation Started ---${NC}"
echo -e "Target Cluster ID : ${YELLOW}$CLUSTER_ID${NC}"

if [ "$EXCLUDE_DB" = true ]; then
    echo -e "PostgreSQL Action : ${BLUE}STOP ONLY${NC} (Data will be preserved)"
    echo -ne "Confirm GFM removal? (y/N): "
else
    echo -e "PostgreSQL Action : ${RED}DROP CLUSTER${NC} (All data will be DELETED)"
    echo -ne "Confirm ${RED}TOTAL DESTRUCTION${NC} of instance and its DATA? (y/N): "
fi

read -r confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

if [ ! -f "$NODES_FILE" ]; then
    echo -e "${RED}Ошибка: Файл '$NODES_FILE' не найден!${NC}"
    exit 1
fi

while read -r IP ROLE <&3; do
    echo -e "${BLUE}>>> Processing Node: $IP ($ROLE)${NC}"
    
    ssh -n -o StrictHostKeyChecking=no root@$IP "
        # 1. Останавливаем и отключаем GFM инстанс
        systemctl stop gfm@${CLUSTER_ID} 2>/dev/null
        systemctl disable gfm@${CLUSTER_ID} 2>/dev/null
        
        # 2. Работа с PostgreSQL (кроме Witness)
        if [ \"$ROLE\" != \"witness\" ]; then
            if [ \"$EXCLUDE_DB\" = true ]; then
                echo 'Stopping PostgreSQL service ${PG_SVC} (preserving data)...'
                systemctl stop ${PG_SVC} 2>/dev/null
            else
                echo 'Dropping PostgreSQL cluster ${PG_VER} ${PG_INST}...'
                pg_dropcluster --stop ${PG_VER} ${PG_INST} 2>/dev/null
            fi
        fi

        # 3. Удаляем файлы конфигурации, статуса и логи инстанса
        rm -f /etc/gorgona/gfm_${CLUSTER_ID}.conf
        rm -f /etc/gorgona/status_${CLUSTER_ID}.json
        rm -f /etc/gorgona/node_type_${CLUSTER_ID}
        rm -f /var/log/gorgona/*_${CLUSTER_ID}.log

        # 4. Очистка заглушки psql для Witness
        if [ \"$ROLE\" == \"witness\" ]; then
            if [ -L /usr/bin/psql ] && [ \"\$(readlink /usr/bin/psql)\" == \"/usr/bin/true\" ]; then
                if ! ls /etc/gorgona/gfm_*.conf >/dev/null 2>&1; then
                    rm -f /usr/bin/psql
                fi
            fi
        fi

        # 5. Удаление общих скриптов (только если это последний GFM)
        if ! ls /etc/gorgona/gfm_*.conf >/dev/null 2>&1; then
            echo 'No other GFM instances found. Removing shared binaries and templates...'
            rm -f /usr/local/bin/gfm.py
            rm -f /usr/local/bin/gfm_rebuild.sh
            rm -f /usr/local/bin/gfm_health.sh
            rm -f /usr/local/bin/gfm_switchover.sh
            rm -f /usr/local/bin/gfm_control.sh
            rm -f /etc/systemd/system/gfm@.service
            
            systemctl stop gfm-remote 2>/dev/null
            systemctl disable gfm-remote 2>/dev/null
            rm -f /etc/systemd/system/gfm-remote.service
        fi
        
        systemctl daemon-reload
    "
done 3< <(grep -v '^#' "$NODES_FILE" | grep -v '^$')

echo -e "${GREEN}Cleanup of '$CLUSTER_ID' complete.${NC}"
