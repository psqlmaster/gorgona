### Stheno Bridge HTTP Gateway 

Stheno Bridge is the HTTPS Webhook interface for the Gorgona Stheno server. It allows external applications, scripts, and monitoring tools to inject messages into the Gorgona mesh network using standard HTTP POST requests.

#### Overview

The bridge serves as a secure entry point for automation. It translates incoming JSON payloads into encrypted Gorgona mesh packets and dispatches them through active TCP clients maintained by the Stheno server.

#### Prerequisites

1. Stheno Server running and accessible via HTTPS.
2. A valid username and password for the Stheno instance.
3. The specific Public Key Hash of the recipient (visible in the Stheno Web UI).

#### Authentication

All requests to the bridge must be authenticated using a JSON Web Token (JWT).

#### Obtain a Token

Replace `your_password` and `127.0.0.1` with your actual credentials and server address:

```bash
TOKEN=$(curl -k -s -X POST https://127.0.0.1:8000/api/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "your_password"}' | jq -r .access_token)
```

The token is valid for 3 years by default.

#### Sending Messages

To send a message, use the `/api/webhook/send` endpoint.

#### Basic Request 

You can specify when a message should become readable and when it should expire using Unix timestamps:

```bash
curl -k -X POST https://127.0.0.1:8000/api/webhook/send \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"hash":"RECIPIENT_HASH","text":"Test message expire 3 days","unlock_at":'$(date -u +%s)',"expire_at":'$(date -u -d "+3 days" +%s)'}'
```

#### Example 
```bash
❯ TOKEN=$(curl -k -s -X POST https://192.168.1.200:8000/api/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "admin"}' | jq -r .access_token)
❯ echo $TOKEN
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTc4MDU4MTM0M30.pFBCqyKYARQiaJIcXM4hhYVy7ZByqA1B_Kq3YPSPnpA

❯ curl -k -X POST https://192.168.1.200:8000/api/webhook/send \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"hash":"RWTPQzuhzBw=","text":"Test message expire 3 days","unlock_at":'$(date -u +%s)',"expire_at":'$(date -u -d "+3 days" +%s)'}'

{"status":"ok","message":"Alert sent to Gorgona mesh"}%   
```

#### Payload Fields

| Field       | Type         | Description                                                               |
| ----------- | ------------ | ------------------------------------------------------------------------- |
| `hash`      | String       | The 8-character Base64 hash of the destination key.                       |
| `text`      | String       | The message content to be encrypted and sent.                             |
| `unlock_at` | Int / String | Unix timestamp or human-readable date (`YYYY-MM-DD HH:MM:SS`).            |
| `expire_at` | Int / String | Unix timestamp or human-readable date (`YYYY-MM-DD HH:MM:SS`).            |

Response Codes

  - 200 OK: Message successfully encrypted and accepted by the Gorgona node.
  - 401 Unauthorized: Token is missing, expired, or invalid.
  - 404 Not Found: The specified key hash is not connected or is disabled in the
    Stheno server.
  - 500 Internal Server Error: Encryption failed or the Gorgonad node rejected
    the packet.

#### Integration Example (Bash Script)

```bash
#!/bin/bash

# Configuration
SERVER="https://127.0.0.1:8000"
USER="admin"
PASS="admin"
TARGET_HASH="RWTPQzuhzBw="

# Current time and expiration (3 days later) in human-readable format
NOW=$(date -u '+%Y-%m-%d %H:%M:%S')
EXPIRE=$(date -u -d '+3 days' '+%Y-%m-%d %H:%M:%S')

# 1. Get Token
TOKEN_DATA=$(curl -k -s -X POST "$SERVER/api/login" \
     -H "Content-Type: application/json" \
     -d '{"username":"'$USER'","password":"'$PASS'"}')

TOKEN=$(echo $TOKEN_DATA | jq -r .access_token)

# 2. Send Alert using human-readable dates
curl -k -X POST "$SERVER/api/webhook/send" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"hash":"'$TARGET_HASH'","text":"System alert from '$(hostname)'","unlock_at":"'$NOW'","expire_at":"'$EXPIRE'"}'
```

#### Security Considerations

- **SSL Verification**: The `-k` flag is used for self-signed certificates. In production environments, it is recommended to use valid CA-signed certificates and remove the `-k` flag.
- **Key Access**: The bridge can only send messages using keys that are already added to the Stheno server.
