#!/bin/bash

# WIFISNIFFER - Installation Script
# This script sets up WiFi Sniffer as a systemd service.

set -e

INSTALL_DIR=$(pwd)
USER_NAME=$(whoami)
GROUP_NAME=$(id -gn)
VENV_DIR="$INSTALL_DIR/venv"
DEFAULT_NIC="wlx801f024e3b4c"

echo "------------------------------------------------"
echo "   WIFISNIFFER - System Service Installer"
echo "------------------------------------------------"

# 1. Check for root (needed for systemd and monitor mode setup)
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (use sudo)."
   exit 1
fi

# 2. Get the actual user (not root)
REAL_USER=${SUDO_USER:-$USER_NAME}
REAL_GROUP=$(id -gn $REAL_USER)
REAL_HOME=$(eval echo ~$REAL_USER)

echo "[*] Installing for user: $REAL_USER"
echo "[*] Installation directory: $INSTALL_DIR"

# 3. Detect or Ask for Interface
echo ""
if [ -n "$1" ]; then
    NIC="$1"
    echo "[*] Using interface from argument: $NIC"
else
    echo "[?] Available wireless interfaces:"
    iw dev | grep Interface | awk '{print "  - " $2}' || echo "  (None found with 'iw dev')"
    read -p "[?] Enter the wireless interface to use (default: $DEFAULT_NIC): " NIC
    NIC=${NIC:-$DEFAULT_NIC}
fi

# 4. Update the run_mac_sniffer.sh with the selected NIC
echo "[*] Configuring interface $NIC in run_mac_sniffer.sh..."
sed -i "s/^export NIC=.*/export NIC=\"$NIC\"/" "$INSTALL_DIR/run_mac_sniffer.sh"

# 5. Set up Virtual Environment
#echo "[*] Setting up virtual environment..."
#if [ ! -d "$VENV_DIR" ]; then
#    sudo -u $REAL_USER python3 -m venv "$VENV_DIR"
#fi

#echo "[*] Installing dependencies..."
#sudo -u $REAL_USER "$VENV_DIR/bin/pip" install --quiet --upgrade pip
#sudo -u $REAL_USER "$VENV_DIR/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# 6. Create systemd Service Files

echo "[*] Creating systemd service files..."

# Sniffer Service
cat <<EOF > /etc/systemd/system/wifisniffer-sniffer.service
[Unit]
Description=WiFi Sniffer Sniffer Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/bin/bash $INSTALL_DIR/run_mac_sniffer.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Web App Service
cat <<EOF > /etc/systemd/system/wifisniffer-web.service
[Unit]
Description=WiFi Sniffer Web Dashboard
After=network.target wifisniffer-sniffer.service

[Service]
Type=simple
User=$REAL_USER
Group=$REAL_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python3 $INSTALL_DIR/web_app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 7. Reload systemd and enable services
echo "[*] Reloading systemd and enabling services..."
systemctl daemon-reload
systemctl enable wifisniffer-sniffer.service
systemctl enable wifisniffer-web.service

# 8. Set permissions for the database
# Make sure the user can read/write the database even if created by root sniffer
touch "$INSTALL_DIR/discovered_macs.db"
chown $REAL_USER:$REAL_GROUP "$INSTALL_DIR/discovered_macs.db"
chmod 664 "$INSTALL_DIR/discovered_macs.db"

echo ""
echo "------------------------------------------------"
echo "[+] Installation Complete!"
echo "[+] To start the services, run:"
echo "    sudo systemctl start wifisniffer-sniffer"
echo "    sudo systemctl start wifisniffer-web"
echo ""
echo "[+] Status checks:"
echo "    sudo systemctl status wifisniffer-*"
echo ""
echo "[+] Dashboard will be available at: http://localhost:5000"
echo "------------------------------------------------"
