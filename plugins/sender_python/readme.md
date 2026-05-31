### Gorgona Python Sender Plugin

This plugin provides a lightweight, stateless Python implementation for the **Gorgona Mesh Network**. It allows developers to generate compatible RSA-2048 key pairs and transmit encrypted alerts directly from Python applications.

#### Directory Structure

```text
sender_python/
├── gorgona_sender.py          # The core module (Logic & Cryptography)
├── generate_key_example.py    # Script to create new identities
├── send_emample.py            # Script to broadcast alerts
└── readme.md                  # Documentation
```

#### Features

- **Stateless Operation**: No persistent background connection required.
- **Full Compatibility**: Implements Gorgona's L2 `AUTH` protocol and binary packet format.
- **Industrial Encryption**: Uses `AES-256-GCM` for data and `RSA-OAEP` (SHA-256) for key wrapping.
- **Time-Lock Ready**: Native support for `unlock_at` and `expire_at` UTC timestamps.

#### Installation

The plugin requires the `cryptography` library:

```bash
pip install cryptography
```

#### Usage

##### 1. Generating a Key Pair
Before sending alerts, you need a Gorgona identity. Use `generate_key_example.py` to create a new RSA-2048 private key and its corresponding Public Key Hash.

**Command:**
```bash
python3 generate_key_example.py
```

**Output:**
```text
Your Public Key Hash: TFokvd1JkeM=
--- PRIVATE KEY (Save this safely!) ---
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC24qUDHCBeJXje
... (key content) ...
-----END PRIVATE KEY-----
```

##### 2. Sending an Alert
To send a message, you must provide the Node IP, the `sync_psk` (found in `gorgonad.conf`), and your Private Key. 

The sender automatically calculates the current UTC time for `unlock_at` to ensure the message is accepted by the mesh immediately.

**Command:**
```bash
python3 send_emample.py
```

**Output:**
```text
Current UTC Time: 1780240365
Server response: Alert ID: 182479934210048 added successfully
```

#### Module Integration

To use the sender in your own project, simply import the `GorgonaSender` class:

```python
from gorgona_sender import GorgonaSender
import time

sender = GorgonaSender("64.188.70.158", 7777, "YOUR_PSK")

# Simple send
sender.send_alert(
    private_key_pem=MY_PRIVATE_KEY,
    message="Alert Message",
    unlock_at=int(time.time()),
    expire_at=int(time.time()) + 86400
)
```

#### Technical Specification

- **Binary Protocol**: 4-byte Big-Endian length header followed by the payload.
- **Handshake**: `AUTH|psk|0|0|0`
- **Data Format**: `SEND|pub_hash|unlock|expire|cipher|key|iv|tag`
- **Encryption**: 
    - Symmetric: AES-256-GCM.
    - Asymmetric: RSA-OAEP (MGF1-SHA256).
