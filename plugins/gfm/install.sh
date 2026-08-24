#!/bin/bash
# GFM (Gorgona Failover Manager) Config-based Installer

# Цвета для вывода
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    echo -e "${BLUE}GFM Automated Installer${NC}"
    echo -e "Использование: $0 ${GREEN}<путь_к_конфигу>${NC}"
    echo -e ""
    echo -e "Пример:"
    echo -e "  $0 ./gfm_prod_5432.conf"
    exit 1
}

if [ -z "$1" ] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    usage
fi

CONF_SRC=$1

if [ ! -f "$CONF_SRC" ]; then
    echo -e "${RED}Ошибка: Файл конфигурации '$CONF_SRC' не найден!${NC}"
    exit 1
fi

# --- Функция чтения параметров из INI файла ---
get_val() {
    local section=$1
    local key=$2
    sed -nr "/^\[$section\]/,/^\[.*\]/ { s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p }" "$CONF_SRC" | \
    sed 's/[#;].*//' | tr -d '"' | tr -d "'" | tr -d '\r' | xargs
}

# 1. Извлечение параметров
CLUSTER_ID=$(get_val "cluster" "cluster_id")
PUB_HASH=$(get_val "cluster" "my_pub_hash")
RAW_NODES=$(get_val "cluster" "quorum_nodes")

PG_SVC=$(get_val "postgresql" "service_name")
PG_VER=$(get_val "postgresql" "pg_version")
PG_INST=$(get_val "postgresql" "pg_instance_name")
PG_PORT=$(get_val "postgresql" "port")

if [ -z "$CLUSTER_ID" ]; then echo -e "${RED}Error: cluster_id not found!${NC}"; exit 1; fi
if [ -z "$RAW_NODES" ]; then echo -e "${RED}Error: quorum_nodes not found!${NC}"; exit 1; fi

# Превращаем строку в массив для итерации (разделитель - запятая)
IFS=',' read -ra ADDR_ARRAY <<< "$RAW_NODES"
NODE_COUNT=${#ADDR_ARRAY[@]}

echo -e "${BLUE}--- GFM Automated Deployment ---${NC}"
echo -e "Config        : ${GREEN}$CONF_SRC${NC}"
echo -e "Cluster ID    : ${GREEN}$CLUSTER_ID${NC}"
echo -e "Postgres      : ${GREEN}v$PG_VER ($PG_INST) on port $PG_PORT${NC}"
echo -e "Nodes Count   : ${GREEN}$NODE_COUNT${NC}"

# 2. Сбор карты хостов (Discovery)
echo -ne "Discovery hostnames..."
HOST_MAP=""
for entry in "${ADDR_ARRAY[@]}"; do
    entry=$(echo $entry | xargs) # Чистим пробелы
    IP=$(echo $entry | cut -d':' -f1)
    HNAME=$(ssh -n -o StrictHostKeyChecking=no root@$IP "hostname")
    HOST_MAP+="$IP $HNAME"$'\n'
done
echo -e " [${GREEN}OK${NC}]"

# 3. Основной цикл установки
for entry in "${ADDR_ARRAY[@]}"; do
    entry=$(echo $entry | xargs)
    IP=$(echo $entry | cut -d':' -f1)
    PORT=$(echo $entry | cut -d':' -f2)

    # Роль: если порт совпадает с портом БД из конфига - это база, иначе - witness
    if [ "$PORT" == "$PG_PORT" ]; then
        ROLE="database"
    else
        ROLE="witness"
    fi

    echo -e "\n${BLUE}>>> Node: $IP (Role: $ROLE)${NC}"

    # Настройка /etc/hosts для sudo и быстрой работы
    ssh -n root@$IP "sed -i '/192.168.1./d' /etc/hosts; echo '$HOST_MAP' >> /etc/hosts"

    if [ "$ROLE" == "database" ]; then
        ssh -n root@$IP "
            if ! pg_lsclusters | grep -q \"$PG_VER[[:space:]]\+$PG_INST\"; then
                echo 'Creating PostgreSQL cluster...'
                pg_createcluster $PG_VER $PG_INST --port $PG_PORT
            fi
            # Исправляем symlink psql если он был забит заглушкой от witness
            [ -L /usr/bin/psql ] && [ \"\$(readlink /usr/bin/psql)\" == \"/usr/bin/true\" ] && rm -f /usr/bin/psql
            [ ! -f /usr/bin/psql ] && ln -sf /usr/lib/postgresql/$PG_VER/bin/psql /usr/bin/psql
            systemctl enable $PG_SVC && systemctl start $PG_SVC
        "
    else
        # Настройка Witness (просто заглушка psql)
        ssh -n root@$IP "ln -sf /usr/bin/true /usr/bin/psql 2>/dev/null"
    fi

    # Копирование бинарных файлов GFM
    scp -o StrictHostKeyChecking=no gfm.py gfm_rebuild.sh gfm_health.sh gfm_switchover.sh gfm_control.sh root@$IP:/usr/local/bin/
    # Копирование конфига инстанса
    scp -o StrictHostKeyChecking=no "$CONF_SRC" root@$IP:/etc/gorgona/gfm_${CLUSTER_ID}.conf
    ssh -n root@$IP "chmod +x /usr/local/bin/gfm*"

    # Настройка Systemd
    ssh -n root@$IP "
        # 1. Шаблон сервиса (общий для всех кластеров на этой ноде)
        cat <<EOF > /etc/systemd/system/gfm@.service
[Unit]
Description=Gorgona Failover Manager for %i
After=network.target gorgonad.service %i.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/gfm.py /etc/gorgona/gfm_%i.conf
Restart=always
RestartSec=10
User=root
[Install]
WantedBy=multi-user.target
EOF

        # 2. Сервис Gorgona Remote (слушает команды из меша)
        if [ ! -f /etc/systemd/system/gfm-remote.service ]; then
            cat <<EOF > /etc/systemd/system/gfm-remote.service
[Unit]
Description=Gorgona Remote Execution Service
After=network.target gorgonad.service
[Service]
ExecStart=/usr/bin/gorgona -ev listen new $PUB_HASH
Restart=always
RestartSec=5
User=root
[Install]
WantedBy=multi-user.target
EOF
            systemctl enable gfm-remote && systemctl start gfm-remote
        fi

        systemctl daemon-reload
        systemctl enable gfm@${CLUSTER_ID}
        systemctl restart gfm@${CLUSTER_ID}
    "
    echo -e "${GREEN}Node $IP is configured and GFM is running.${NC}"
done

echo -e "\n${GREEN}Cluster '$CLUSTER_ID' deployment finished successfully!${NC}"
