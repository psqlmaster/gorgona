#!/bin/bash
#cat /usr/local/bin/gfm_switchover.sh
# Скрипт умной передачи власти
# Проверяем свою роль через JSON, который пишет gfm.py
ROLE=$(grep -oP '"role": "\K[^"]+' /etc/gorgona/cluster_status.json)
if [ "$ROLE" != "LEADER" ]; then
    echo "I am not the Leader. Ignoring switchover request."
    exit 0
fi
echo "I am the Leader. Starting graceful switchover..."
# Останавливаем базу "умно"
systemctl stop postgresql
# Ждем, пока реплика увидит пропажу и станет новым Мастером
# (Поскольку таймаут у нас 40-50с, подождем чуть дольше)
sleep 60
# Возвращаемся в кластер как реплика
/usr/local/bin/gfm_rebuild.sh
