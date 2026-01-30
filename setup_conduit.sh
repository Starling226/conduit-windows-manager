#!/bin/bash

# Detect Operating System
OS_TYPE="$(uname)"
echo "[*] Detecting OS: $OS_TYPE"

# Step 1: Change to user home directory
cd "$HOME" || exit

# Step 2: Ensure pip is updated and install dependencies
echo "[*] Updating pip and installing dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install fabric paramiko PyQt5

# Step 3: Setup SSH directory and keys
if [ ! -d ".ssh" ]; then
    mkdir -p ".ssh"
    chmod 700 ".ssh"
fi

cd .ssh || exit

if [ ! -f "id_conduit" ]; then
    echo "[*] Generating SSH key: id_conduit"
    ssh-keygen -t ed25519 -f id_conduit -N ""
else
    echo "[!] id_conduit already exists. Skipping keygen."
fi

# Step 4: Add macOS specific fixes to the Python script if needed
if [ "$OS_TYPE" == "Darwin" ]; then
    echo "[*] macOS detected. Adding High-DPI support check..."
    # Note: This logic can be added to the top of your ConduitQt.py
fi

# Step 5: Directory Check
if [ -d "/opt/conduit" ]; then
    cd "/opt/conduit" || exit
elif [ -d "$HOME/Conduit" ]; then
    cd "$HOME/Conduit" || exit
fi

echo "[SUCCESS] Environment ready. Launching shell..."
exec $SHELL
