#!/bin/sh
export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
# ---------------------------------------------------------------------------
# Usage:
#   ban_ip.sh <IP> [REASON]            # Block the IP address for 24 hours 
#   ban_ip.sh --unban <IP>             # Unban the IP (remove all decisions) 
#   ban_ip.sh --unban <IP> [REASON]    # Unban IP (REASON is ignored) 
# ---------------------------------------------------------------------------
DURATION="24h"
UNBAN=0
case "$1" in
    --unban|-u)
        UNBAN=1
        shift
        ;;
esac
IP="$1"
REASON="${2:-Banned via Gorgona P2P}"
if [ -z "$IP" ]; then
    echo "[ERROR] Missing IP argument." >&2
    echo "Usage:" >&2
    echo "  $0 <IP_ADDRESS> [REASON]           # ban" >&2
    echo "  $0 --unban <IP_ADDRESS>            # unban" >&2
    exit 1
fi
CSCLI=$(command -v cscli || echo "/usr/local/bin/cscli")
if [ ! -x "$CSCLI" ]; then
    echo "[ERROR] cscli not found at $CSCLI" >&2
    exit 1
fi
if [ "$UNBAN" -eq 1 ]; then
    echo "[INFO] Removing CrowdSec decisions for IP=$IP"
    # Remove all decisions associated with this IP address (by value) 
    # -o json не нужен, cscli сам выведет результат.
    "$CSCLI" decisions delete --ip "$IP"
    RC=$?
    if [ "$RC" -ne 0 ]; then
        echo "[ERROR] cscli decisions delete failed (rc=$RC)" >&2
        exit "$RC"
    fi
    echo "[INFO] Unban completed for IP=$IP"
    # We send the client a new list 
    if [ -x /usr/local/bin/cscli_decisions_list.sh ]; then
        /usr/local/bin/cscli_decisions_list.sh
    fi
    exit 0
fi
echo "[INFO] Adding CrowdSec decision: IP=$IP, Duration=$DURATION, Reason='$REASON'"
"$CSCLI" decisions add --ip "$IP" --duration "$DURATION" --reason "$REASON"
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "[ERROR] cscli decisions add failed (rc=$RC)" >&2
    exit "$RC"
fi
# We send the client a new list 
if [ -x /usr/local/bin/cscli_decisions_list.sh ]; then
    /usr/local/bin/cscli_decisions_list.sh
fi
