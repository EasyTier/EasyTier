#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ ! -x "$1" ]; then
    printf 'Usage: sudo -n sh %s <compiled EasyTier library test binary> [kernel|dns]\n' "$0" >&2
    exit 2
fi

route_test_binary=$1
route_test_suite=${2:-kernel}
case "$route_test_suite" in
    kernel|dns) ;;
    *) printf 'Unknown route test suite: %s\n' "$route_test_suite" >&2; exit 2 ;;
esac

# Always create private mount and network namespaces before touching /dev.
# Building stays with the ordinary user; root only runs the selected tests.
exec unshare --net --mount sh -c '
    set -eu
    mount --make-rprivate /
    mount -t tmpfs tmpfs /dev
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    mknod /dev/null c 1 3
    mknod /dev/random c 1 8
    mknod /dev/urandom c 1 9
    ip link set lo up
    case "$2" in
        kernel) exec "$1" instance::route::backend::linux::tests::kernel_ --ignored --nocapture ;;
        dns) exec "$1" instance::dns_server::tests --nocapture --test-threads=1 ;;
    esac
' easytier-route-kernel "$route_test_binary" "$route_test_suite"
