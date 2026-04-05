#!/bin/bash - 
mkdir -p /tmp/test/test1/test2/test3 && cd /tmp/test/test1/test2/test3 && pwd | \
gorgona send "$(date -u '+%Y-%m-%d %H:%M:%S')" "$(date -u -d '+1 days' '+%Y-%m-%d %H:%M:%S')" - "RWTPQzuhzBw=.pub"
