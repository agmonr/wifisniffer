#!/bin/bash

# Configuration
export NIC="wlx801f024e3b4c"
VENV_DIR="venv"

echo "[*] Using interface: $NIC"

# 1. Unblock and Clean up
echo "[*] Unblocking Wi-Fi and killing conflicting processes..."
rfkill unblock wifi
rfkill unblock all

# Try to stop NetworkManager from interfering with this specific NIC
if command -v airmon-ng >/dev/null 2>&1; then
    airmon-ng check kill
else
    # Manual fallback if airmon-ng is missing
    systemctl stop wpa_supplicant 2>/dev/null
fi

# 2. Put NIC in monitor mode
echo "[*] Setting $NIC to monitor mode..."
ip link set "$NIC" down
if command -v iw >/dev/null 2>&1; then
    iw "$NIC" set monitor control
    MODE_SUCCESS=$?
else
    echo "[!] 'iw' not found. Attempting fallback monitor mode..."
    ip link set "$NIC" type monitor 2>/dev/null
    MODE_SUCCESS=$?
fi
ip link set "$NIC" up

if [ $MODE_SUCCESS -ne 0 ]; then
    echo "[!] Warning: Could not verify monitor mode setting."
fi

# 2. Channel Hopping Function
hop_channels() {
    if ! command -v iw >/dev/null 2>&1; then
        echo "[!] 'iw' not found. Channel hopping disabled."
        return
    fi
    echo "[*] Channel hopping started..."
    while true; do
        for channel in {1..13}; do
            iw dev "$NIC" set channel "$channel"
            sleep 1
        done
    done
}

# Start channel hopping in the background
hop_channels &
HOPPER_PID=$!

# Ensure the hopper is killed when the script exits
trap "kill $HOPPER_PID; echo '[*] Channel hopping stopped.';" EXIT

# 3. Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

# 5. Run the sniffer
echo "[*] Starting mac_sniffer.py..."
"$VENV_DIR/bin/python3" mac_sniffer.py "$NIC"

# 6. Fix permissions (Sniffer creates/updates DB as root, we need it as user for web app)
# Use the owner of the current directory as the target user
TARGET_USER=$(stat -c '%U' .)
TARGET_GROUP=$(stat -c '%G' .)
if [ -f "discovered_macs.db" ]; then
    chown $TARGET_USER:$TARGET_GROUP discovered_macs.db
    chmod 664 discovered_macs.db
fi
