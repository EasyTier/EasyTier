#!/bin/bash
set -e

NS_NAME="et_bench"

echo "=== Creating netns: $NS_NAME ==="
# Clean up old ns
sudo ip netns del "$NS_NAME" 2>/dev/null || true

# Create namespace
sudo ip netns add "$NS_NAME"

# Enable loopback inside namespace
sudo ip netns exec "$NS_NAME" ip link set lo up

echo "=== netns $NS_NAME ready ==="
echo "Both instances will share this namespace's loopback."
echo "TCP/UDP connections to 127.0.0.1 will work inside it."
echo ""
echo "Now run the bench with HOTPATH_NETNS=$NS_NAME:"
echo "  HOTPATH_TUNNEL=tcp HOTPATH_NETNS=$NS_NAME HOTPATH_BENCH_SECS=15 \\"
echo "    cargo run --profile hotpath --features hotpath --example cpu_hotspot_ring"
