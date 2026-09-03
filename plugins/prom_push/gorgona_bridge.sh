#!/bin/bash
#PUSHGATEWAY_URL="http://192.168.1.200:9091"
PUSHGATEWAY_URL="http://127.0.0.1:9091"
JOB_NAME="gorgona_metrics"
HASH="00ZXdHQToU8="
echo "Starting Gorgona Bridge..."
buffer=""
current_hostname=""
# stdbuf -oL заставляет gorgona сбрасывать каждую строку в пайп немедленно
stdbuf -oL gorgona listen new "$HASH" | while IFS= read -r line; do
    if [[ "$line" == node_* ]]; then
        if [[ "$line" == node_info* ]]; then
            # регулярное выражение Bash вместо вызова grep
            if [[ "$line" =~ hostname=\"([^\"]+)\" ]]; then
                current_hostname="${BASH_REMATCH[1]}"
            fi
        fi
        buffer+="$line"$'\n'
    elif [[ -z "$line" ]] && [[ -n "$buffer" ]]; then
        instance_name="${current_hostname:-unknown_host}"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending metrics for $instance_name" 
        # Добавлен таймаут и проверка результата для предотвращения зависаний
        if ! printf "%s" "$buffer" | curl -s --max-time 10 --fail --data-binary @- "$PUSHGATEWAY_URL/metrics/job/$JOB_NAME/instance/$instance_name" > /dev/null; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Failed to send metrics for $instance_name" >&2
        fi
        buffer=""
        current_hostname=""
    fi
done
