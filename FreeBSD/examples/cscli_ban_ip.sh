#!/bin/sh                                                                       
                                                                                
export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"         
                                                                                
IP="$1"                                                                         
DURATION="24h"                                                                  
REASON="${2:-Banned via Gorgona P2P}"                                           
                                                                                
if [ -z "$IP" ]; then                                                           
    echo "[ERROR] Missing IP argument." >&2                                     
    echo "Usage: $0 <IP_ADDRESS> [REASON]" >&2                                  
    exit 1                                                                      
fi                                                                              
                                                                                
CSCLI=$(command -v cscli || echo "/usr/local/bin/cscli")                        
if [ ! -x "$CSCLI" ]; then                                                      
    echo "[ERROR] cscli not found at $CSCLI" >&2                                
    exit 1                                                                      
fi                                                                              
                                                                                
echo "[INFO] Adding CrowdSec decision: IP=$IP, Duration=$DURATION, Reason='$REASON'"
"$CSCLI" decisions add --ip "$IP" --duration "$DURATION" --reason "$REASON"        
/usr/local/bin/cscli_decisions_list.sh   
