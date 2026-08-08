#!/bin/bash
# GFM Cluster Uninstaller - Safe Version

NODES_FILE="nodes.list"
RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}--- GFM Cluster Uninstallation Started ---${NC}"

while read -r IP ROLE <&3; do
    echo ">>> Cleaning up Node: $IP ($ROLE)"
    
    ssh -n -o StrictHostKeyChecking=no root@$IP "
        # 1. Останавливаем только наши сервисы
        systemctl stop gfm gfm-remote 2>/dev/null
        systemctl disable gfm gfm-remote 2>/dev/null
        
        # 2. Удаляем только наши Unit-файлы
        rm -f /etc/systemd/system/gfm.service
        rm -f /etc/systemd/system/gfm-remote.service
        
        # 3. Удаляем только наши скрипты
        rm -f /usr/local/bin/gfm.py
        rm -f /usr/local/bin/gfm_rebuild.sh
        rm -f /usr/local/bin/gfm_health.sh
        rm -f /usr/local/bin/gfm_switchover.sh
        
        # 4. Удаляем конфиг
        rm -f /etc/gorgona/gfm.conf
        
        # 5. БЕЗОПАСНАЯ ОЧИСТКА PSQL
        # Удаляем ссылку только если она указывает на /usr/bin/true (наш Witness-заменитель)
        if [ -L /usr/bin/psql ] && [ \"\$(readlink /usr/bin/psql)\" == \"/usr/bin/true\" ]; then
            rm -f /usr/bin/psql
        fi
        
        systemctl daemon-reload
    "
done 3< <(grep -v '^#' "$NODES_FILE" | grep -v '^$')

echo -e "${RED}GFM cleanup complete.${NC}"
