#!/bin/bash
#cat /usr/local/bin/gfm_switchover.sh
# Скрипт умной передачи власти
# Проверяем свою роль через JSON, который пишет gfm.py
CONF="/etc/gorgona/gfm.conf"
# Более надежное извлечение значений (берем всё, что после первого знака '=')
GORGONA_BIN=$(grep "gorgona_bin" $CONF | sed 's/^[^=]*=[[:space:]]*//')
MY_PUB_HASH=$(grep "my_pub_hash" $CONF | sed 's/^[^=]*=[[:space:]]*//')
ROLE=$(grep -oP '"role": "\K[^"]+' /etc/gorgona/cluster_status.json)
if [ "$ROLE" != "LEADER" ]; then
    echo "I am not the Leader. Ignoring switchover request."
    exit 0
fi
echo "I am the Leader. Starting graceful switchover..."
$GORGONA_BIN send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S')" \
    "EVENT|$(hostname)|PLANNED_SWITCHOVER: Stepping down manually" "$MY_PUB_HASH.pub"
# Останавливаем базу "умно"
systemctl stop postgresql
systemctl stop gfm
# Ждем, пока реплика увидит пропажу и станет новым Мастером
# (Поскольку таймаут у нас 40-50с, подождем чуть дольше)
sleep 60
systemctl start gfm

