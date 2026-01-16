#!/bin/bash
set -e
set -x

if [ $# != 1 ]; then
    echo "[ERROR] Wrong arguments number. Abort."
    exit 1
fi

num_vms=$1
BRIDGE=br0
BRIDGE_IP=192.168.100.1/24

exists=false

# Check bridge existence
if ip link show "$BRIDGE" &>/dev/null; then
    echo "[INFO] Bridge $BRIDGE already exists."
    exists=true
fi

# Check tap devices existence
for ((i = 0; i < num_vms; i++)); do
    if ip link show "tap$i" &>/dev/null; then
        echo "[INFO] tap$i already exists."
        exists=true
    fi
done

# Ask before deleting
if [ "$exists" = true ]; then
    read -p "[WARN] Existing bridge/taps detected. Delete and recreate? (y/N): " answer
    case "$answer" in
        y|Y)
            echo "[INFO] Deleting existing bridge and tap devices..."
            ;;
        *)
            echo "[INFO] Aborting without changes."
            exit 0
            ;;
    esac

    # Delete tap devices
    for ((i = 0; i < num_vms; i++)); do
        if ip link show "tap$i" &>/dev/null; then
            sudo ip link set "tap$i" down || true
            sudo ip tuntap del "tap$i" mode tap || true
        fi
    done

    # Delete bridge
    if ip link show "$BRIDGE" &>/dev/null; then
        sudo ip link set "$BRIDGE" down || true
        sudo ip link del "$BRIDGE" type bridge || true
    fi
fi

# Create bridge
sudo ip link add "$BRIDGE" type bridge
sudo ip link set "$BRIDGE" up
sudo ip addr add "$BRIDGE_IP" dev "$BRIDGE"

# Create tap devices
for ((i = 0; i < num_vms; i++)); do
    sudo ip tuntap add "tap$i" mode tap
    sudo ip link set "tap$i" up
    sudo ip link set "tap$i" master "$BRIDGE"
done

echo "[INFO] Bridge and tap devices successfully created."
