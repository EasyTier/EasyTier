ip netns add net_a
ip netns add net_b
ip netns add net_c
ip link add veth0 type veth peer name veth1
ip link set veth0 netns net_a
ip link set veth1 netns net_b
ip netns exec net_a ip addr add 10.144.145.1/24 dev veth0
ip netns exec net_b ip addr add 10.144.145.2/24 dev veth1
ip netns exec net_a ip link set veth0 up
ip netns exec net_b ip link set veth1 up
