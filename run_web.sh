#!/bin/bash

VENV_DIR="venv"

echo "[*] Initializing WIFISNIFFER Web Environment..."

# 1. Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "[!] Failed to create virtual environment. Ensure python3-venv is installed."
        exit 1
    fi
fi

# 2. Install/Update requirements
if [ -f "requirements.txt" ]; then
    echo "[*] Ensuring all dependencies are installed (Flask, Pandas, etc.)..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[!] Failed to install dependencies."
        exit 1
    fi
else
    echo "[!] requirements.txt not found. Cannot proceed."
    exit 1
fi

# 3. Start the Web Dashboard
echo "[*] Starting Web Dashboard..."
echo "[+] Access the live feed at: http://localhost:5000"
echo "[*] Press Ctrl+C to stop the web server."

"$VENV_DIR/bin/python3" web_app.py
