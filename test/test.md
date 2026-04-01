# Gorgona Server Protocol Sniffer Test Suite
# Target: 127.0.0.1:7777
```sh
echo "--- Starting Gorgona Sniffer Tests ---"
# TEST 1: Huge Binary Message (256MB)
# Header: 0x0F FF FF FF (268,435,455 bytes). 
# Expected: [WARN] Binary limit exceeded -> Immediate Drop
echo "[1/5] Testing Huge Binary Header..."
printf "\x0F\xFF\xFF\xFF" | nc -w 1 127.0.0.1 7777
# TEST 2: Simulated TLS Handshake (Port Scan)
# Header: 0x16 0x03 0x01 (Common SSL/TLS probe)
# Expected: [WARN] Binary limit exceeded (369MB) -> Immediate Drop (No "Unknown text" trash)
echo "[2/5] Testing Simulated TLS Handshake Scan..."
printf "\x16\x03\x01\x00" | nc -w 1 127.0.0.1 7777
# TEST 3: Text Buffer Overflow
# Sending ~6MB of 'A' characters (exceeds default 5MB limit)
# Expected: [WARN] Text command limit exceeded -> Server error message -> Close
echo "[3/5] Testing Text Limit Overflow (~6MB)..."
head -c 6000000 /dev/zero | tr '\0' 'A' | nc -w 1 127.0.0.1 7777
# TEST 4: Leading Whitespace/Tab Handling
# Header: \t + Spaces + 'info' command
# Expected: [DEBUG] Text command received: info -> Success
echo "[4/5] Testing Tab/Whitespace handling..."
printf "\t    info\n" | nc -w 1 127.0.0.1 7777
# TEST 5: Unknown Text Command
# Expected: [WARN] Unknown text command: HELLO -> Close
echo "[5/5] Testing Unknown Command handling..."
echo "HELLO_GORGONA" | nc -w 1 127.0.0.1 7777
echo "--- Tests Completed. Check server logs for results. ---"
```

#Test 2 — Simulating a replay attack using printf and nc 
```sh
# 1. Данные из вашего лога (длина 450 байт)
PAYLOAD="SEND|4YzEYpwB9hc=|1775068317|1775154717|BOLizDQ33GGG7GU2mUX17I/r|d8rwiF1TdMTqYCiNgHJIFQdbNURCurfFc1ON0fhbiHA77ffsKxJKpEjWVH/YGZEEUVIdokIGde6nNBHS1o2etezz4KNZyCEDpJySNkuNQVHHUkKOUB7L7DfaNSEPFXcrbxr5C06U1iyyJi0beHdt819Vw9Br1r2DnnWa4YiptSsDA9Bv4ZRohvlpbTjF2EQG+svn2joHVW+2ptp1KdGNEMVb01XW/RgB6JAuqqDJge6WoE6riaNMRU7bvWmKNOLvyvPeAWZzJ3oYPJu1TgprJTze5vlYCd21TBUttz84oU4AXqwuogwcmJLYm6wM9jXP/lPzyeaVcdlHITPTtrCeKg==|hCU30mouAs01QERz|iMGXcnWWX80hTtYU1AR24A=="
# 2. Имитируем атаку повтора (Replay Attack) через printf и nc
# \x00\x00\x01\xC2 — это 450 в формате uint32 big-endian
echo "--- Sending Replay Attack Packet ---"
printf "\x00\x00\x01\xC2$PAYLOAD" | nc -w 2 127.0.0.1 7777
```
Error: Replay attack detected (duplicate payload)
## server log
[2026-04-01 18:33:40 UTC] [WARN] [fd:7] [127.0.0.1:37186] Replay attack detected: Duplicate binary payload found.
[2026-04-01 18:33:40 UTC] [DEBUG] [fd:7] [127.0.0.1:37186] Enqueued response (49 bytes): Error: Replay attack detected (duplicate payload)
[2026-04-01 18:33:44 UTC] [INFO] [fd:7] [127.0.0.1:37186] Client disconnected
## replay test after added 1000 akerts
Error: Stale alert (unlock_at time is too old)
## server log
[2026-04-01 18:38:17 UTC] [WARN] [fd:8] [127.0.0.1:49648] Rejected stale alert (unlock_at is 380 seconds behind)
[2026-04-01 18:38:17 UTC] [DEBUG] [fd:8] [127.0.0.1:49648] Enqueued response (46 bytes): Error: Stale alert (unlock_at time is too old)
[2026-04-01 18:38:21 UTC] [INFO] [fd:8] [127.0.0.1:49648] Client disconnected
