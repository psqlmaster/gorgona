#!/bin/bash
# GFM (Gorgona Failover Manager) Discovery-based Installer

NODES_FILE="nodes.list"
PUB_HASH="+I9IQuXYW8I="

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

if [ ! -f "$NODES_FILE" ]; then
    echo -e "${RED}Error: $NODES_FILE not found!${NC}"
    exit 1
fi

# Считаем общее количество узлов для кворума
NODE_COUNT=$(grep -v '^#' "$NODES_FILE" | grep -v '^$' | wc -l)

echo -e "${BLUE}--- GFM Cluster Deployment (Discovery Mode) ---${NC}"
echo -e "Cluster Size: ${GREEN}$NODE_COUNT${NC}"

# Шаг 1: Собираем карту хостов для /etc/hosts
echo "Generating host map..."
HOST_MAP=""
while read -r IP ROLE <&3; do
    # Узнаем реальный hostname каждого узла через SSH
    HNAME=$(ssh -n -o StrictHostKeyChecking=no root@$IP "hostname")
    HOST_MAP+="$IP $HNAME"$'\n'
done 3< <(grep -v '^#' "$NODES_FILE" | grep -v '^$')

# Шаг 2: Установка на каждый узел
while read -r IP ROLE <&3; do
    echo -e "\n${BLUE}>>> Provisioning Node: $IP ${ROLE:+(Role: $ROLE)}${NC}"

    # 1. Настройка /etc/hosts (удаляем старое, пишем актуальную карту)
    # Это гарантирует, что ноды увидят друг друга по именам для репликации
    ssh -n root@$IP "
        sed -i '/192.168.1./d' /etc/hosts
        echo '$HOST_MAP' >> /etc/hosts
    "

    # 2. Определение путей к Postgres (авто-поиск)
    ssh -n root@$IP "
        mkdir -p /etc/gorgona /usr/local/bin /var/log/gorgona
        if [ \"$ROLE\" == \"witness\" ]; then
            ln -sf /usr/bin/true /usr/bin/psql
            echo 'WITNESS_MODE' > /etc/gorgona/node_type
        else
            # Восстанавливаем реальный psql если была заглушка
            [ -L /usr/bin/psql ] && [ \"\$(readlink /usr/bin/psql)\" == \"/usr/bin/true\" ] && rm -f /usr/bin/psql
            # Ищем бинарник 17-й версии
            REAL_PSQL=\$(ls /usr/lib/postgresql/17/bin/psql 2>/dev/null)
            [ -n \"\$REAL_PSQL\" ] && ln -sf \$REAL_PSQL /usr/bin/psql
            echo 'DB_MODE' > /etc/gorgona/node_type
        fi
    "

    # 3. Копирование файлов управления
    scp -o StrictHostKeyChecking=no gfm.py gfm_rebuild.sh gfm_health.sh gfm_switchover.sh root@$IP:/usr/local/bin/
    ssh -n root@$IP "chmod +x /usr/local/bin/gfm*"

    # 4. Генерация унифицированного gfm.conf
    ssh -n root@$IP "cat <<EOF > /etc/gorgona/gfm.conf
[cluster]
my_pub_hash = $PUB_HASH
quorum_total_nodes = $NODE_COUNT

[timings]
heartbeat_interval = 15
max_missing_heartbeats = 3
monitor_interval = 180
heartbeat_ttl = 45
event_ttl = 86400
default_ttl = 3600

[paths]
base_dir = /etc/gorgona
gorgona_bin = /usr/bin/gorgona
psql_bin = /usr/bin/psql
pg_ctl_bin = /usr/bin/pg_ctlcluster
rebuild_script = /usr/local/bin/gfm_rebuild.sh
EOF"

    # 5. Деплой системных сервисов
    ssh -n root@$IP "
        cat <<EOF > /etc/systemd/system/gfm.service
[Unit]
Description=Gorgona Failover Manager
After=network.target gorgonad.service postgresql.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/gfm.py
Restart=always
RestartSec=10
User=root
[Install]
WantedBy=multi-user.target
EOF

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

        systemctl daemon-reload
        systemctl enable --now gfm gfm-remote
        systemctl restart gfm gfm-remote
    "
    echo -e "${GREEN}Node $IP configured.${NC}"

done 3< <(grep -v '^#' "$NODES_FILE" | grep -v '^$')

echo -e "\n${GREEN}Deployment finished! GFM will now negotiate roles.${NC}"
