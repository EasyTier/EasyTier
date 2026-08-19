#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
unset KUBECONFIG
kind=${KIND:-kind}
kubectl=${KUBECTL:-kubectl}
cargo=${CARGO:-cargo}
kind_version=v0.32.0
kind_sha256=50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54
kind_node_image='kindest/node@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5'
multus_image='ghcr.io/k8snetworkplumbingwg/multus-cni:v4.3.0'
whereabouts_image='ghcr.io/k8snetworkplumbingwg/whereabouts:v0.9.4'
workload_image='docker.io/library/busybox:1.37.0'
easytier_image='localhost/easytier-cni:test'
namespace=easytier-cni-test

for command in curl docker flock ip jq mktemp sha256sum skopeo timeout; do
    command -v "$command" >/dev/null || {
        echo "$command is required" >&2
        exit 2
    }
done
[[ -x $cargo ]] || command -v "$cargo" >/dev/null || {
    echo "cargo is required" >&2
    exit 2
}
command -v cargo-zigbuild >/dev/null || {
    echo "cargo-zigbuild is required for the static test image" >&2
    exit 2
}
command -v zig >/dev/null || {
    echo "zig is required for the static test image" >&2
    exit 2
}
[[ -x $kubectl ]] || command -v "$kubectl" >/dev/null || {
    echo "kubectl is required" >&2
    exit 2
}
[[ -c /dev/net/tun ]] || {
    echo "/dev/net/tun is unavailable" >&2
    exit 2
}

exec 9>"${TMPDIR:-/tmp}/easytier-kind.lock"
flock --nonblock 9 || {
    echo "another EasyTier kind test owns the host lock" >&2
    exit 1
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/easytier-cni-kind.XXXXXX")
logs=${EASYTIER_CNI_TEST_LOG_DIR:-$tmp/logs}
kubeconfig=$tmp/kubeconfig
kind_config=$tmp/kind.yaml
cluster="easytier-cni-${BASHPID}"
cluster_created=false
mkdir -p "$logs"

collect_logs() {
    [[ $cluster_created == true ]] || return 0
    timeout 30s "$kubectl" get nodes,pods -A -o wide >"$logs/objects.log" 2>&1 || true
    timeout 30s "$kubectl" get events -A --sort-by=.lastTimestamp >"$logs/events.log" 2>&1 || true
    timeout 30s "$kubectl" get ippools.whereabouts.cni.cncf.io -A -o yaml \
        >"$logs/ippools.yaml" 2>&1 || true
    timeout 30s "$kubectl" -n kube-system logs -l app.kubernetes.io/name=easytier-cni \
        --all-containers --prefix >"$logs/easytier.log" 2>&1 || true
    timeout 30s "$kubectl" -n kube-system logs -l app=multus \
        --all-containers --prefix >"$logs/multus.log" 2>&1 || true
    timeout 30s "$kubectl" -n kube-system logs -l app=whereabouts \
        --all-containers --prefix >"$logs/whereabouts.log" 2>&1 || true
    for node in "${cluster}-control-plane" "${cluster}-worker" "${cluster}-worker2"; do
        docker exec "$node" ip address >"$logs/${node}-address.log" 2>&1 || true
        docker exec "$node" ip route >"$logs/${node}-route.log" 2>&1 || true
        docker exec "$node" sh -c 'ls -la /var/lib/easytier-cni/configs /opt/cni/bin' \
            >"$logs/${node}-cni.log" 2>&1 || true
    done
    timeout 120s "$kind" export logs "$logs/kind" --name "$cluster" \
        >"$logs/kind-export.log" 2>&1 || true
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    if [[ $status -ne 0 ]]; then collect_logs; fi
    if [[ $cluster_created == true ]]; then
        "$kind" delete cluster --name "$cluster" >"$logs/kind-delete.log" 2>&1 || {
            docker rm -f "${cluster}-control-plane" "${cluster}-worker" "${cluster}-worker2" \
                >>"$logs/kind-delete.log" 2>&1 || true
        }
    fi
    if [[ $status -eq 0 && -z ${EASYTIER_CNI_TEST_LOG_DIR:-} ]]; then
        rm -rf "$tmp"
    elif [[ $status -ne 0 ]]; then
        echo "kind test failed; diagnostics retained at $logs" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v "$kind" >/dev/null; then
    kind=$tmp/kind
    curl -fsSL --retry 3 \
        "https://github.com/kubernetes-sigs/kind/releases/download/$kind_version/kind-linux-amd64" \
        -o "$kind"
    printf '%s  %s\n' "$kind_sha256" "$kind" | sha256sum --check
    chmod 0755 "$kind"
fi

for image in "$kind_node_image" "$multus_image" "$whereabouts_image" "$workload_image"; do
    docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
done

"$cargo" zigbuild --release --target x86_64-unknown-linux-musl \
    --package easytier --bin easytier-core >"$logs/cargo-build.log" 2>&1
"$cargo" zigbuild --release --target x86_64-unknown-linux-musl \
    --package easytier-cni >>"$logs/cargo-build.log" 2>&1

cat >"$tmp/Dockerfile" <<EOF
FROM alpine:3.21
RUN apk add --no-cache tini
COPY easytier-core easytier-cni /usr/local/bin/
ENTRYPOINT ["/sbin/tini", "--"]
EOF
cp "$repo_root/target/x86_64-unknown-linux-musl/release/easytier-core" "$tmp/easytier-core"
cp "$repo_root/target/x86_64-unknown-linux-musl/release/easytier-cni" "$tmp/easytier-cni"
docker build --provenance=false -t "$easytier_image" "$tmp" >"$logs/docker-build.log" 2>&1

cat >"$kind_config" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/16
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: /dev/net/tun
        containerPath: /dev/net/tun
  - role: worker
    extraMounts:
      - hostPath: /dev/net/tun
        containerPath: /dev/net/tun
  - role: worker
    extraMounts:
      - hostPath: /dev/net/tun
        containerPath: /dev/net/tun
EOF

cluster_created=true
"$kind" create cluster --name "$cluster" --image "$kind_node_image" \
    --config "$kind_config" --kubeconfig "$kubeconfig" --wait 5m \
    >"$logs/kind-create.log" 2>&1
export KUBECONFIG=$kubeconfig
"$kind" load docker-image "$easytier_image" --name "$cluster" \
    >"$logs/kind-load.log" 2>&1
for image in "$multus_image" "$whereabouts_image" "$workload_image"; do
    archive="$tmp/$(tr '/:' '__' <<<"$image").tar"
    skopeo copy --override-os linux --override-arch amd64 \
        "docker-daemon:$image" "docker-archive:$archive:$image" \
        >>"$logs/kind-load.log" 2>&1
    for node in "${cluster}-control-plane" "${cluster}-worker" "${cluster}-worker2"; do
        docker exec --privileged -i "$node" ctr --namespace=k8s.io images import \
            --snapshotter=overlayfs - <"$archive" >>"$logs/kind-load.log" 2>&1
    done
done

for url in \
    'https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/v4.3.0/deployments/multus-daemonset.yml' \
    'https://raw.githubusercontent.com/k8snetworkplumbingwg/whereabouts/v0.9.4/doc/crds/whereabouts.cni.cncf.io_ippools.yaml' \
    'https://raw.githubusercontent.com/k8snetworkplumbingwg/whereabouts/v0.9.4/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml' \
    'https://raw.githubusercontent.com/k8snetworkplumbingwg/whereabouts/v0.9.4/doc/crds/whereabouts.cni.cncf.io_nodeslicepools.yaml' \
    'https://raw.githubusercontent.com/k8snetworkplumbingwg/whereabouts/v0.9.4/doc/crds/daemonset-install.yaml' \
    'https://raw.githubusercontent.com/k8snetworkplumbingwg/whereabouts/v0.9.4/doc/crds/reconciler-deployment.yaml'; do
    name=${url##*/}
    curl -fsSL --retry 3 "$url" -o "$tmp/$name"
done
sed -i "s#ghcr.io/k8snetworkplumbingwg/multus-cni:snapshot#$multus_image#g" \
    "$tmp/multus-daemonset.yml"
sed -i "s#ghcr.io/k8snetworkplumbingwg/whereabouts:latest#$whereabouts_image#g" \
    "$tmp/daemonset-install.yaml" "$tmp/reconciler-deployment.yaml"
"$kubectl" apply -f "$tmp/multus-daemonset.yml"
"$kubectl" apply -f "$tmp/whereabouts.cni.cncf.io_ippools.yaml"
"$kubectl" apply -f "$tmp/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml"
"$kubectl" apply -f "$tmp/whereabouts.cni.cncf.io_nodeslicepools.yaml"
"$kubectl" apply -f "$tmp/daemonset-install.yaml"
"$kubectl" apply -f "$tmp/reconciler-deployment.yaml"
"$kubectl" -n kube-system rollout status daemonset/kube-multus-ds --timeout=5m
"$kubectl" -n kube-system rollout status daemonset/whereabouts --timeout=5m

"$kubectl" -n kube-system create secret generic easytier-cni \
    --from-literal=network-secret=kind-integration-secret

cat >"$tmp/easytier.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: easytier-relay
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: easytier-relay
  template:
    metadata:
      labels:
        app: easytier-relay
    spec:
      containers:
        - name: relay
          image: $easytier_image
          imagePullPolicy: Never
          command: ["easytier-core"]
          args:
            - --network-name
            - kind-easytier-cni
            - --network-secret
            - kind-integration-secret
            - --no-tun
            - "true"
            - --listeners
            - tcp://0.0.0.0:11010
            - --disable-ipv6
            - "true"
            - --stun-servers
            - --console-log-level
            - info
          ports:
            - name: easytier
              containerPort: 11010
---
apiVersion: v1
kind: Service
metadata:
  name: easytier-relay
  namespace: kube-system
spec:
  selector:
    app: easytier-relay
  ports:
    - name: easytier
      port: 11010
      targetPort: 11010
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: easytier-cni
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: easytier-cni
  template:
    metadata:
      labels:
        app.kubernetes.io/name: easytier-cni
    spec:
      hostNetwork: true
      hostPID: true
      tolerations:
        - operator: Exists
      initContainers:
        - name: install-cni
          image: $easytier_image
          imagePullPolicy: Never
          command: ["/bin/sh", "-ec"]
          args:
            - |
              install -m 0755 /usr/local/bin/easytier-cni /host/opt/cni/bin/easytier-cni
              install -d -m 0700 /host/etc/easytier-cni
              install -m 0600 /secret/network-secret /host/etc/easytier-cni/network-secret
          securityContext:
            privileged: true
          volumeMounts:
            - {name: cni-bin, mountPath: /host/opt/cni/bin}
            - {name: cni-config, mountPath: /host/etc/easytier-cni}
            - {name: secret, mountPath: /secret, readOnly: true}
      containers:
        - name: easytier
          image: $easytier_image
          imagePullPolicy: Never
          command: ["/bin/sh", "-ec"]
          args:
            - |
              install -d -m 0700 /var/lib/easytier-cni/configs /run/easytier-cni
              umask 077
              exec easytier-core --daemon --rpc-portal unix:///run/easytier-cni/rpc.sock \
                --config-dir /var/lib/easytier-cni/configs --console-log-level info
          securityContext:
            privileged: true
          readinessProbe:
            exec:
              command: ["/bin/sh", "-ec", "test -S /run/easytier-cni/rpc.sock"]
            periodSeconds: 2
          volumeMounts:
            - {name: tun, mountPath: /dev/net/tun}
            - {name: run, mountPath: /run, mountPropagation: HostToContainer}
            - {name: state, mountPath: /var/lib/easytier-cni}
      volumes:
        - {name: cni-bin, hostPath: {path: /opt/cni/bin}}
        - {name: cni-config, hostPath: {path: /etc/easytier-cni, type: DirectoryOrCreate}}
        - {name: tun, hostPath: {path: /dev/net/tun, type: CharDevice}}
        - {name: run, hostPath: {path: /run, type: Directory}}
        - {name: state, hostPath: {path: /var/lib/easytier-cni, type: DirectoryOrCreate}}
        - {name: secret, secret: {secretName: easytier-cni, defaultMode: 0400}}
EOF
"$kubectl" apply -f "$tmp/easytier.yaml"
"$kubectl" -n kube-system rollout status deployment/easytier-relay --timeout=5m
"$kubectl" -n kube-system rollout status daemonset/easytier-cni --timeout=5m
relay_ip=$("$kubectl" -n kube-system get service easytier-relay \
    -o jsonpath='{.spec.clusterIP}')
[[ $relay_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]

cat >"$tmp/workload.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
---
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: easytier
  namespace: $namespace
spec:
  config: |-
    {
      "cniVersion": "1.0.0",
      "name": "easytier-kind",
      "type": "easytier-cni",
      "rpcPortal": "unix:///run/easytier-cni/rpc.sock",
      "networkName": "kind-easytier-cni",
      "networkSecretFile": "/etc/easytier-cni/network-secret",
      "peers": ["tcp://$relay_ip:11010"],
      "mtu": 1380,
      "timeoutSeconds": 60,
      "ipam": {
        "type": "whereabouts",
        "range": "10.200.0.0/24",
        "range_start": "10.200.0.10",
        "range_end": "10.200.0.250"
      }
    }
---
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: $namespace
  annotations:
    k8s.v1.cni.cncf.io/networks: easytier
spec:
  nodeName: ${cluster}-worker
  containers:
    - name: server
      image: $workload_image
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c", "exec httpd -f -p 8080 -h /etc"]
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: $namespace
  annotations:
    k8s.v1.cni.cncf.io/networks: easytier
spec:
  nodeName: ${cluster}-worker2
  containers:
    - name: client
      image: $workload_image
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c", "sleep 3600"]
EOF
"$kubectl" apply -f "$tmp/workload.yaml"
"$kubectl" -n "$namespace" wait --for=condition=Ready pod/server pod/client --timeout=5m

server_status=$("$kubectl" -n "$namespace" get pod server \
    -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}')
client_status=$("$kubectl" -n "$namespace" get pod client \
    -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}')
server_ip=$(jq -r '.[] | select(.interface == "net1") | .ips[0]' <<<"$server_status")
client_ip=$(jq -r '.[] | select(.interface == "net1") | .ips[0]' <<<"$client_status")
[[ $server_ip =~ ^10\.200\.0\.[0-9]+$ && $client_ip =~ ^10\.200\.0\.[0-9]+$ ]]
[[ $server_ip != "$client_ip" ]]

"$kubectl" -n "$namespace" exec server -- ip address show net1
"$kubectl" -n "$namespace" exec client -- ip address show net1
[[ $("$kubectl" -n "$namespace" exec server -- cat /sys/class/net/net1/mtu) == 1360 ]]
[[ $("$kubectl" -n "$namespace" exec client -- cat /sys/class/net/net1/mtu) == 1360 ]]
connected=false
for _ in $(seq 1 30); do
    if "$kubectl" -n "$namespace" exec client -- ping -c 1 -W 1 "$server_ip" \
        >/dev/null 2>&1; then
        connected=true
        break
    fi
    sleep 1
done
[[ $connected == true ]]
"$kubectl" -n "$namespace" exec client -- ping -c 5 -W 2 "$server_ip"
response=$("$kubectl" -n "$namespace" exec client -- wget -q -T 10 -O - \
    "http://$server_ip:8080/hostname")
[[ $response == server ]]
"$kubectl" -n "$namespace" exec client -- nslookup kubernetes.default.svc.cluster.local >/dev/null

"$kubectl" delete namespace "$namespace" --wait=true --timeout=2m
for node in "${cluster}-worker" "${cluster}-worker2"; do
    [[ -z $(docker exec "$node" sh -c "find /var/lib/easytier-cni/configs -name '*.toml' -print -quit") ]]
done
allocations=$("$kubectl" get ippools.whereabouts.cni.cncf.io -A -o json |
    jq '[.items[].spec.allocations | length] | add // 0')
[[ $allocations -eq 0 ]]

echo "EasyTier CNI kind integration passed: $client_ip -> $server_ip"
