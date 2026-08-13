# EasyTier CNI

`easytier-cni` attaches an EasyTier L3 TUN as a secondary Pod interface. The
Pod keeps its primary Kubernetes CNI interface for cluster services, DNS, and
the EasyTier underlay.

The initial implementation supports one IPv4 address per attachment. It does
not install a default route or modify Pod DNS. IP allocation is delegated to a
standard CNI IPAM plugin; the example uses Whereabouts for cluster-wide address
uniqueness.

Use EasyTier as a standalone Multus delegate. Chained `prevResult` input is not
supported in the initial release.

## Requirements

- Linux nodes with `/dev/net/tun`.
- Multus CNI.
- Whereabouts, or another IPAM plugin that returns one IPv4 address and no
  routes.
- An EasyTier relay or peer reachable through each Pod's primary network.

The node daemon requires privileged access because it enters Pod network
namespaces and creates TUN devices. Its RPC portal listens only on node
through a root-only Unix socket mounted from the node.

## Install

Install Multus and Whereabouts according to their release documentation. The
following resources must exist before installing EasyTier:

- the `NetworkAttachmentDefinition` CRD and Multus node daemon;
- the Whereabouts CRDs, CNI binary, kubeconfig, and reconciler.

Create the EasyTier network secret without placing it in a manifest:

```sh
kubectl -n kube-system create secret generic easytier-cni \
  --from-literal=network-secret="$EASYTIER_NETWORK_SECRET"
```

Pin the EasyTier image in `deploy/daemonset.yaml` to the release being
installed, then apply it:

```sh
kubectl apply -f easytier-contrib/easytier-cni/deploy/daemonset.yaml
kubectl -n kube-system rollout status daemonset/easytier-cni
```

Edit `deploy/network-attachment-definition.yaml` before applying it:

- replace `relay.example.com` with a reachable EasyTier peer;
- choose an EasyTier range that does not overlap node, Pod, Service, LAN, VPN,
  or container-runtime networks;
- use the same `networkName` and secret on every node.

```sh
kubectl apply -f easytier-contrib/easytier-cni/deploy/network-attachment-definition.yaml
```

Attach the network to a Pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: easytier-client
  annotations:
    k8s.v1.cni.cncf.io/networks: easytier
spec:
  containers:
    - name: client
      image: busybox:1.37.0
      command: ["/bin/sh", "-c", "sleep 3600"]
```

Multus creates `net1` by default. The network status annotation reports the
allocated EasyTier address.

## Configuration

| Field | Meaning | Default |
| --- | --- | --- |
| `rpcPortal` | Node daemon Unix socket | `unix:///run/easytier-cni/rpc.sock` |
| `networkName` | EasyTier network name | required |
| `networkSecretFile` | Root-only secret file on the node | required |
| `peers` | Initial EasyTier peer URLs | required |
| `mtu` | EasyTier packet MTU; TUN MTU excludes protocol overhead | `1380` |
| `timeoutSeconds` | ADD/CHECK convergence timeout | `30` |
| `ipam` | Delegated CNI IPAM configuration | required |

The daemon persists each attachment under
`/var/lib/easytier-cni/configs`. The DaemonSet starts with `umask 077` because
those files contain EasyTier network credentials. Do not copy this directory
between nodes.

## Lifecycle

- `ADD` allocates an IP, starts an EasyTier instance in the Pod network
  namespace, waits for the TUN, and returns the interface and IP.
- `DEL` removes the deterministic EasyTier instance and releases IPAM state.
  It remains valid after the Pod network namespace has disappeared.
- `CHECK` verifies delegated IPAM, the daemon instance, TUN name, and IPv4.
Supported CNI version is `1.0.0`.
