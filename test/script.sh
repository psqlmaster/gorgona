#!/bin/bash - 
mkdir -p /tmp/test/test1/test2/test3 && cd /tmp/test/test1/test2/test3 && pwd | \
gorgona send "2025-10-05 18:42:00" "2030-10-09 09:00:00" - "RWTPQzuhzBw=.pub"
