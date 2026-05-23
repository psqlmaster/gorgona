#!/bin/bash
PUSHGATEWAY_URL="http://192.168.1.200:9091"
JOB_NAME="gorgona_metrics"
HASH="4YzEYpwB9hc="
echo "Starting Gorgona Bridge..."
buffer=""
current_hostname=""
# stdbuf -oL заставляет gorgona сбрасывать каждую строку в пайп немедленно
stdbuf -oL gorgona listen new "$HASH" | while IFS= read -r line; do
    # Эта строка появится в bash -x сразу как придут данные
    # echo "DEBUG: processing line: $line" 
    if [[ "$line" == node_* ]]; then
        if [[ "$line" == node_info* ]]; then
            current_hostname=$(echo "$line" | grep -oP 'hostname="\K[^"]+')
        fi
        buffer+="$line"$'\n'
    elif [[ -z "$line" ]] && [[ -n "$buffer" ]]; then
        instance_name=${current_hostname:-"unknown_host"}
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending metrics for $instance_name" 
        echo -n "$buffer" | curl -s --data-binary @- "$PUSHGATEWAY_URL/metrics/job/$JOB_NAME/instance/$instance_name"
        buffer=""
        current_hostname=""
    fi
done
