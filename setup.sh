#!/bin/bash

# Setup script for AI-guided Penetration Testing environment
# This script installs and configures all necessary tools

echo "==== Setting up AI-guided Penetration Testing Environment ===="

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# Update package lists
echo "[+] Updating package lists..."
apt-get update

# Install essential tools
echo "[+] Installing essential packages..."
apt-get install -y python3 python3-pip python3-venv git wget curl

# Check and install Metasploit Framework
if ! command_exists msfconsole; then
    echo "[+] Installing Metasploit Framework..."
    apt-get install -y metasploit-framework
else
    echo "[+] Metasploit Framework is already installed."
fi

# Check and install nmap
if ! command_exists nmap; then
    echo "[+] Installing Nmap..."
    apt-get install -y nmap
else
    echo "[+] Nmap is already installed."
fi

# Check and install searchsploit
if ! command_exists searchsploit; then
    echo "[+] Installing Exploit-DB / searchsploit..."
    apt-get install -y exploitdb
    
    # Update searchsploit database
    searchsploit -u
else
    echo "[+] Searchsploit is already installed."
    # Update searchsploit database
    searchsploit -u
fi

# Check and install nikto
if ! command_exists nikto; then
    echo "[+] Installing Nikto..."
    apt-get install -y nikto
else
    echo "[+] Nikto is already installed."
fi

# Check and install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install PyQt6 openai requests

# Install tool-specific Python packages
echo "[+] Installing tool-specific Python packages..."
pip3 install pymetasploit3 python-libnmap

# Create workspace directory if it doesn't exist
if [ ! -d "./workspace" ]; then
    echo "[+] Creating workspace directory..."
    mkdir -p ./workspace
    chmod 755 ./workspace
fi

# Start Metasploit RPC service
echo "[+] Setting up Metasploit RPC service..."
# Check if msfdb is initialized
if ! msfdb status | grep -q "connected"; then
    echo "[+] Initializing Metasploit database..."
    msfdb init
fi

# Create configuration file for the tool
echo "[+] Creating configuration file..."
CONFIG_DIR="./config"
CONFIG_FILE="$CONFIG_DIR/config.ini"

if [ ! -d "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
fi

cat > "$CONFIG_FILE" << EOF
[DEFAULT]
workspace_dir = ./workspace
log_level = INFO

[METASPLOIT]
host = 127.0.0.1
port = 55552
username = msf
password = password

[CALDERA]
url = http://localhost:8888
api_key = ADMIN123
EOF

chmod 644 "$CONFIG_FILE"

echo "==== Setup Complete ===="
echo "You can now run the AI-guided Penetration Testing Tool."
echo "Configuration file: $CONFIG_FILE"
