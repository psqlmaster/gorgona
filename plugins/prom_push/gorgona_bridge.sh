#!/bin/bash
set -u
set -o pipefail
PUSHGATEWAY_URL="http://127.0.0.1:9091"
JOB_NAME="gorgona_metrics"
HASH="00ZXdHQToU8="
# Считаем bridge зависшим, если за это время
# не было ни одной успешно отправленной метрики, 15 минут дает хороший запас.
WATCHDOG_TIMEOUT=900
STATE_DIR="/run/gorgona-bridge"
LAST_SUCCESS_FILE="$STATE_DIR/last_success"
mkdir -p "$STATE_DIR"
echo "Starting Gorgona Bridge..."

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}
log() {
    echo "[$(timestamp)] $*"
}
# При старте начинаем отсчет watchdog заново.
date +%s > "$LAST_SUCCESS_FILE"
# Watchdog
watchdog() {
    while true; do
        sleep 30
        [[ -f "$LAST_SUCCESS_FILE" ]] || continue
        last_success=$(cat "$LAST_SUCCESS_FILE" 2>/dev/null || echo 0)
        now=$(date +%s)
        # Защита от кривого значения
        [[ "$last_success" =~ ^[0-9]+$ ]] || continue
        age=$((now - last_success))
        if (( age >= WATCHDOG_TIMEOUT )); then
            log "ERROR: No successful metrics push for ${age}s."
            log "ERROR: Gorgona bridge appears stuck. Exiting for systemd restart."
            # Убиваем весь bridge.
            # systemd KillMode=control-group дополнительно
            # убьет дочерний gorgona.
            kill -TERM "$MAIN_PID" 2>/dev/null || true
            exit 0
        fi
    done
}
# PID основного shell
MAIN_PID=$$
watchdog &
WATCHDOG_PID=$!
# Cleanup
cleanup() {
    log "Stopping Gorgona Bridge..."
    if [[ -n "${WATCHDOG_PID:-}" ]]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM
# Gorgona listener
stdbuf -oL gorgona listen new "$HASH" |
while IFS= read -r line; do
    if [[ "$line" == node_* ]]; then
        if [[ "$line" == node_info* ]]; then
            if [[ "$line" =~ hostname=\"([^\"]+)\" ]]; then
                current_hostname="${BASH_REMATCH[1]}"
            fi
        fi
        buffer+="$line"$'\n'
    elif [[ -z "$line" ]] && [[ -n "$buffer" ]]; then
        instance_name="${current_hostname:-unknown_host}"
        log "Sending metrics for $instance_name"
        if printf "%s" "$buffer" |
            curl \
                --silent \
                --show-error \
                --connect-timeout 3 \
                --max-time 10 \
                --fail \
                --data-binary @- \
                "$PUSHGATEWAY_URL/metrics/job/$JOB_NAME/instance/$instance_name" \
                > /dev/null
        then
            log "Metrics successfully pushed for $instance_name"
            # Обновляем heartbeat ТОЛЬКО после успешного curl.
            date +%s > "$LAST_SUCCESS_FILE"
        else
            log "ERROR: Failed to send metrics for $instance_name"
        fi
        buffer=""
        current_hostname=""
    fi
done
# If gorgona/pipeline exits
PIPE_STATUS=$?
log "ERROR: Gorgona pipeline exited with status $PIPE_STATUS."
log "ERROR: Exiting bridge so systemd can restart it."
exit 1
