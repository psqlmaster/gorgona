#!/bin/bash
set -u
PUSHGATEWAY_URL="http://127.0.0.1:9091"
JOB_NAME="gorgona_metrics"
HASH="00ZXdHQToU8="
# Если 15 минут нет ни одного node_* сообщения,
# считаем текущий gorgona listener зависшим.
WATCHDOG_TIMEOUT=900
echo "Starting Gorgona Bridge..."
# ------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------
cleanup() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Stopping Gorgona Bridge..."
    if [[ -n "${GORGONA_PID:-}" ]]; then
        kill "$GORGONA_PID" 2>/dev/null || true
        wait "$GORGONA_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM
# ------------------------------------------------------------
# Start gorgona as Bash coprocess
# ------------------------------------------------------------
coproc GORGONA {
    stdbuf -oL gorgona listen new "$HASH"
}
GORGONA_PID=$!
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Started gorgona PID=$GORGONA_PID"
# ------------------------------------------------------------
# Metrics parser
# ------------------------------------------------------------
buffer=""
current_hostname=""
while true; do
    # --------------------------------------------------------
    # Read with timeout.
    #
    # IMPORTANT:
    # timeout is based on ANY gorgona output here, but
    # reconnect messages are handled separately below.
    # --------------------------------------------------------
    if IFS= read -r -t "$WATCHDOG_TIMEOUT" line <&"${GORGONA[0]}"; then
        # ----------------------------------------------------
        # Normal gorgona output
        # ----------------------------------------------------
        # Reconnect is NORMAL and must not trigger restart.
        if [[ "$line" == *"Connection lost, reconnecting"* ]]; then
            echo "$line"
            continue
        fi
        # ----------------------------------------------------
        # Metrics
        # ----------------------------------------------------
        if [[ "$line" == node_* ]]; then
            # A real node_* message means the connection is
            # actually delivering fresh data.
            #
            # The read timeout is therefore effectively reset
            # by every node_* line.
            if [[ "$line" == node_info* ]]; then
                if [[ "$line" =~ hostname=\"([^\"]+)\" ]]; then
                    current_hostname="${BASH_REMATCH[1]}"
                fi
            fi
            buffer+="$line"$'\n'
        elif [[ -z "$line" ]] && [[ -n "$buffer" ]]; then
            instance_name="${current_hostname:-unknown_host}"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending metrics for $instance_name"
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
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] Metrics successfully pushed for $instance_name"
            else
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Failed to send metrics for $instance_name" >&2
            fi
            buffer=""
            current_hostname=""
        fi
    else
        # ----------------------------------------------------
        # read timeout OR gorgona exited
        # ----------------------------------------------------
        if kill -0 "$GORGONA_PID" 2>/dev/null; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: No data received from gorgona for ${WATCHDOG_TIMEOUT}s." >&2
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Restarting bridge..." >&2
            kill "$GORGONA_PID" 2>/dev/null || true
            wait "$GORGONA_PID" 2>/dev/null || true
            exit 1
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Gorgona listener exited." >&2
            wait "$GORGONA_PID" 2>/dev/null || true
            exit 1
        fi
    fi
done
