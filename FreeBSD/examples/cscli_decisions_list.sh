#!/bin/sh

export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

START_DATE=$(date -u '+%Y-%m-%d %H:%M:%S')
EXPIRE_DATE=$(date -u -v+3d '+%Y-%m-%d %H:%M:%S')

/usr/local/bin/cscli decisions list 2>>/tmp/cscli.log | \
/usr/local/bin/gorgona send "$START_DATE" "$EXPIRE_DATE" - "RWTPQzuhzBw=.pub" >> /tmp/cscli.log 2>&1
