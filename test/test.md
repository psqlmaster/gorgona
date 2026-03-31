# Gorgona Server Protocol Sniffer Test Suite
# Target: 127.0.0.1:7777

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
