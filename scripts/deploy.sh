CWD=$(dirname `cargo locate-project | jq '.root' -r`)
cargo build --release --all-targets

TARGET_HOSTS=("root@public.kkrainbow.top" "root@47.242.85.82" "root@192.168.60.162")
CARGO_BUILD_OUTPUT_DIR="$CWD/target/release"

copy_bin_to_remote() {
    local TARGET_HOST=$1
    scp ${CARGO_BUILD_OUTPUT_DIR}/easytier-core $TARGET_HOST:/tmp/easytier-core &
    scp ${CARGO_BUILD_OUTPUT_DIR}/easytier-cli $TARGET_HOST:/tmp/easytier-cli &
}


for TARGET_HOST in ${TARGET_HOSTS[@]}; do
    ssh $TARGET_HOST "killall easytier-core"
    copy_bin_to_remote $TARGET_HOST
done

wait

run_with_args() {
    local TARGET_HOST=$1
    local ARGS=$2
    ssh $TARGET_HOST "nohup /tmp/easytier-core $ARGS > /tmp/easytier-core.log 2>&1 &"
}

run_with_args "root@192.168.60.162" "--ipv4 10.144.144.10 --peers tcp://public.kkrainbow.top:11010"
run_with_args "root@public.kkrainbow.top" "--ipv4 10.144.144.20"
run_with_args "root@47.242.85.82" "--ipv4 10.144.144.30 --peers tcp://public.kkrainbow.top:11010"
