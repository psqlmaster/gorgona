#!/bin/bash
# GFM Cluster Instance Uninstaller

CONF_SRC=$1
NODES_FILE="nodes.list"

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo -e "${YELLOW}GFM Instance Uninstaller${NC}"
    echo -e "Использование: $0 ${GREEN}<путь_к_конфигу>${NC}"
    echo -e ""
    echo -e "Пример:"
    echo -e "  $0 ./gfm_prod_5432.conf"
    echo -e ""
    echo -e "Скрипт выполнит:"
    echo -e "  1. Остановку и удаление сервиса gfm@ID."
    echo -e "  2. Удаление файлов конфигурации и статуса конкретного инстанса."
    echo -e "  3. Полную очистку системы (удаление gfm.py и др.), если это был последний кластер."
    exit 1
}

# Если аргумент пустой или это запрос справки
if [ -z "$1" ] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    usage
fi

CONF_SRC=$1

if [ ! -f "$CONF_SRC" ]; then
    echo -e "${RED}Ошибка: Файл конфигурации '$CONF_SRC' не найден!${NC}"
    echo -e "Пожалуйста, проверьте путь и повторите попытку."
    exit 1
fi

get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF_SRC" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

CLUSTER_ID=$(get_val "cluster" "cluster_id")

if [ -z "$CLUSTER_ID" ]; then
    echo -e "${RED}Error: Could not find cluster_id in $CONF_SRC${NC}"
    exit 1
fi

echo -e "${RED}--- GFM Uninstallation Started ---${NC}"
echo -e "Target Cluster ID: ${YELLOW}$CLUSTER_ID${NC}"
echo -ne "Confirm uninstallation? (y/N): "
read -r confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

if [ ! -f "nodes.list" ]; then
    echo -e "${RED}Ошибка: Файл 'nodes.list' не найден в текущей директории!${NC}"
    echo -e "Создайте его в формате:"
    echo -e "192.168.1.1 master"
    echo -e "192.168.1.2 standby"
    echo -e "192.168.1.3 witness"
    exit 1
fi

while read -r IP ROLE <&3; do
    echo -e "${BLUE}>>> Cleaning up Node: $IP ($ROLE)${NC}"
    
    ssh -n -o StrictHostKeyChecking=no root@$IP "
        # 1. Останавливаем и отключаем конкретный инстанс
        systemctl stop gfm@${CLUSTER_ID} 2>/dev/null
        systemctl disable gfm@${CLUSTER_ID} 2>/dev/null
        
        # 2. Удаляем файлы, специфичные для этого кластера
        rm -f /etc/gorgona/gfm_${CLUSTER_ID}.conf
        rm -f /etc/gorgona/status_${CLUSTER_ID}.json
        rm -f /etc/gorgona/node_type_${CLUSTER_ID}
        
        # 3. Безопасная очистка psql (только для Witness)
        if [ \"$ROLE\" == \"witness\" ]; then
            if [ -L /usr/bin/psql ] && [ \"\$(readlink /usr/bin/psql)\" == \"/usr/bin/true\" ]; then
                # Проверяем, нет ли других запущенных GFM, которым нужна эта заглушка
                if ! ls /etc/gorgona/gfm_*.conf >/dev/null 2>&1; then
                    rm -f /usr/bin/psql
                fi
            fi
        fi

        # 4. Удаление общих скриптов (ТОЛЬКО если это был последний кластер)
        if ! ls /etc/gorgona/gfm_*.conf >/dev/null 2>&1; then
            echo 'No other GFM instances found. Removing shared scripts and templates...'
            rm -f /usr/local/bin/gfm.py
            rm -f /usr/local/bin/gfm_rebuild.sh
            rm -f /usr/local/bin/gfm_health.sh
            rm -f /usr/local/bin/gfm_switchover.sh
            rm -f /usr/local/bin/gfm_control.sh
            rm -f /etc/systemd/system/gfm@.service
            systemctl stop gfm-remote 2>/dev/null
            systemctl disable gfm-remote 2>/dev/null
            rm -f /etc/systemd/system/gfm-remote.service
        else
            echo 'Other GFM instances still exist. Keeping shared scripts.'
        fi
        
        systemctl daemon-reload
    "
done 3< <(grep -v '^#' "$NODES_FILE" | grep -v '^$')

echo -e "${RED}Cleanup of '$CLUSTER_ID' complete.${NC}"
