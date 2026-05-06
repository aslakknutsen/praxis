#!/usr/bin/env bash
# Sets up a kind cluster with the custom Istio fork (gwxds-enabled) and
# applies the sample Gateway API resources for testing the xDS client.
#
# Prerequisites:
#   kind, kubectl, docker, python3; go when not using --skip-build
#
# Usage:
#   ./setup.sh               # full setup
#   ./setup.sh --skip-build  # skip istiod/istioctl image build (use existing)
#
# Key overrides (env vars):
#   CLUSTER_NAME        kind cluster name           (default: praxis-dev)
#   IMAGE_HUB           registry / org prefix       (default: praxis)
#   IMAGE_NAME          image name                  (default: istiod)
#   IMAGE_TAG           image tag                   (default: dev)
#   ISTIO_NAMESPACE     namespace for istiod        (default: istio-system)
#   GATEWAY_NAME        Gateway resource name       (default: praxis-gw)
#   GATEWAY_NAMESPACE   Gateway namespace           (default: default)
#   ISTIO_SRC           path to Istio fork root     (auto-detected)
#   ISTIOCTL_PATH       path to an existing istioctl binary (skips build)
#   METALLB_VERSION     MetalLB manifest tag        (default: v0.14.9)
#   KIND_DOCKER_NETWORK docker network kind uses    (default: kind)
#   METALLB_IP_POOL     L2 pool "start-end"        (default: derived from docker subnet)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLUSTER_NAME="${CLUSTER_NAME:-praxis-dev}"
IMAGE_HUB="${IMAGE_HUB:-praxis}"
IMAGE_NAME="${IMAGE_NAME:-istiod}"
IMAGE_TAG="${IMAGE_TAG:-dev}"
ISTIO_NAMESPACE="${ISTIO_NAMESPACE:-istio-system}"
GATEWAY_NAME="${GATEWAY_NAME:-praxis-gw}"
GATEWAY_NAMESPACE="${GATEWAY_NAMESPACE:-default}"
METALLB_VERSION="${METALLB_VERSION:-v0.14.9}"
KIND_DOCKER_NETWORK="${KIND_DOCKER_NETWORK:-kind}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Auto-detect the Istio fork: assumes co-located under a shared Go src tree.
ISTIO_SRC="${ISTIO_SRC:-$(cd "$SCRIPT_DIR/../../../../istio.io/istio" 2>/dev/null && pwd || true)}"

# If ISTIOCTL_PATH is set we skip building istioctl; otherwise we build it.
ISTIOCTL_PATH="${ISTIOCTL_PATH:-}"

SKIP_BUILD=false
for arg in "$@"; do
  [[ "$arg" == "--skip-build" ]] && SKIP_BUILD=true
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { echo "==> $*"; }
fatal() { echo "ERROR: $*" >&2; exit 1; }

require() {
  for cmd in "$@"; do
    command -v "$cmd" &>/dev/null || fatal "required tool not found: $cmd"
  done
}

# IPv4 subnet CIDR for the kind docker bridge (first matching line).
kind_docker_ipv4_subnet() {
  docker network inspect "$KIND_DOCKER_NETWORK" \
    --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' 2>/dev/null \
    | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/' | head -1 || true
}

# MetalLB address range inside SUBNET: last up to 50 assignable IPs (avoids low docker/node IPs).
metallb_pool_range_from_subnet() {
  local subnet="$1"
  python3 - "$subnet" <<'PY'
import ipaddress
import sys

net = ipaddress.ip_network(sys.argv[1].strip(), strict=False)
if net.version != 4:
    sys.exit("MetalLB pool auto-detection supports IPv4 docker subnets only")
hosts = list(net.hosts())
if len(hosts) < 4:
    sys.exit("docker subnet too small for MetalLB pool")
n = min(50, len(hosts) - 1)
print(f"{hosts[-n]}-{hosts[-1]}")
PY
}

# ---------------------------------------------------------------------------
# 1. Pre-flight checks
# ---------------------------------------------------------------------------

require kind kubectl docker

if [[ "$SKIP_BUILD" == false ]]; then
  require go
  [[ -d "$ISTIO_SRC" ]] || fatal "Istio source not found at $ISTIO_SRC — set ISTIO_SRC to the fork root"
fi

require python3

if [[ -n "$ISTIOCTL_PATH" ]]; then
  [[ -x "$ISTIOCTL_PATH" ]] || fatal "ISTIOCTL_PATH=$ISTIOCTL_PATH is not executable"
  ISTIOCTL="$ISTIOCTL_PATH"
elif [[ "$SKIP_BUILD" == false ]]; then
  ISTIOCTL="/tmp/istioctl-gwxds"
else
  # Neither provided nor built — fall back to PATH
  require istioctl
  ISTIOCTL="$(command -v istioctl)"
fi

# ---------------------------------------------------------------------------
# 2. Create kind cluster (idempotent)
# ---------------------------------------------------------------------------

info "Creating kind cluster '$CLUSTER_NAME'"
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  info "Cluster already exists, skipping"
else
  kind create cluster --name "$CLUSTER_NAME"
fi

kubectl config use-context "kind-${CLUSTER_NAME}"

# ---------------------------------------------------------------------------
# 3. Install MetalLB (LoadBalancer for kind — Gateway status / gwxds address assignment)
# ---------------------------------------------------------------------------

METALLB_MANIFEST="https://raw.githubusercontent.com/metallb/metallb/${METALLB_VERSION}/config/manifests/metallb-native.yaml"
info "Installing MetalLB ${METALLB_VERSION}"
kubectl apply -f "$METALLB_MANIFEST"
kubectl rollout status -n metallb-system deployment/controller --timeout=180s
kubectl rollout status -n metallb-system daemonset/speaker --timeout=180s

SUBNET="$(kind_docker_ipv4_subnet)"
[[ -n "$SUBNET" ]] || fatal "could not read IPv4 subnet from docker network '$KIND_DOCKER_NETWORK' (set KIND_DOCKER_NETWORK or METALLB_IP_POOL)"

if [[ -n "${METALLB_IP_POOL:-}" ]]; then
  POOL_RANGE="$METALLB_IP_POOL"
  info "Using METALLB_IP_POOL=$POOL_RANGE"
else
  POOL_RANGE="$(metallb_pool_range_from_subnet "$SUBNET")" || fatal "could not compute MetalLB pool from subnet $SUBNET (set METALLB_IP_POOL manually)"
  info "MetalLB L2 pool ${POOL_RANGE} (from docker subnet ${SUBNET})"
fi

kubectl apply -f - <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: kind-pool
  namespace: metallb-system
spec:
  addresses:
    - ${POOL_RANGE}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: kind-l2
  namespace: metallb-system
spec:
  ipAddressPools:
    - kind-pool
EOF

# ---------------------------------------------------------------------------
# 4. Install Gateway API CRDs (v1.5.1 — matching the Istio fork's go.mod)
# ---------------------------------------------------------------------------

GWAPI_VERSION="v1.5.1"
info "Installing Gateway API CRDs $GWAPI_VERSION"
kubectl apply --server-side -f \
  "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GWAPI_VERSION}/standard-install.yaml"

INFERENCE_VERSION="v1.4.0"
info "Installing Gateway API Inference Extension CRDs $INFERENCE_VERSION"
kubectl apply --server-side -f \
  "https://github.com/kubernetes-sigs/gateway-api-inference-extension/releases/download/${INFERENCE_VERSION}/manifests.yaml"

# ---------------------------------------------------------------------------
# 5. Build pilot-discovery + istioctl from the Istio fork
# ---------------------------------------------------------------------------

if [[ "$SKIP_BUILD" == false ]]; then
  info "Building pilot-discovery"
  (
    cd "$ISTIO_SRC"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
      go build -o /tmp/pilot-discovery ./pilot/cmd/pilot-discovery
  )

  info "Building istiod container image ${IMAGE_HUB}/${IMAGE_NAME}:${IMAGE_TAG}"
  docker build -t "${IMAGE_HUB}/${IMAGE_NAME}:${IMAGE_TAG}" -f - /tmp <<'DOCKERFILE'
FROM gcr.io/distroless/base-debian12:nonroot
COPY pilot-discovery /usr/local/bin/pilot-discovery
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/pilot-discovery"]
DOCKERFILE

  info "Loading ${IMAGE_HUB}/${IMAGE_NAME}:${IMAGE_TAG} into kind cluster"
  kind load docker-image "${IMAGE_HUB}/${IMAGE_NAME}:${IMAGE_TAG}" --name "$CLUSTER_NAME"

  if [[ -z "$ISTIOCTL_PATH" ]]; then
    info "Building istioctl"
    (
      cd "$ISTIO_SRC"
      GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -o "$ISTIOCTL" ./istioctl/cmd/istioctl
    )
  fi
fi

# ---------------------------------------------------------------------------
# 6. Install Istio via istioctl
# ---------------------------------------------------------------------------

info "Installing Istio with istioctl ($ISTIOCTL)"
"$ISTIOCTL" install \
  --set "hub=${IMAGE_HUB}" \
  --set "tag=${IMAGE_TAG}" \
  --set "values.pilot.image=${IMAGE_NAME}" \
  --set "values.global.proxy.autoInject=disabled" \
  --set "components.ingressGateways[0].enabled=false" \
  --set "components.egressGateways[0].enabled=false" \
  --set "values.pilot.env.PILOT_ENABLE_GWXDS=true" \
  --namespace "$ISTIO_NAMESPACE" \
  --skip-confirmation

# ---------------------------------------------------------------------------
# 7. Apply Gateway API resources
# ---------------------------------------------------------------------------

info "Applying Gateway API resources"
kubectl create namespace "$GATEWAY_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
GATEWAY_NAME="$GATEWAY_NAME" GATEWAY_NAMESPACE="$GATEWAY_NAMESPACE" \
  envsubst < "$SCRIPT_DIR/resources.yaml" | kubectl apply -f -

# ---------------------------------------------------------------------------
# 8. Done — print next steps
# ---------------------------------------------------------------------------

cat <<EOF

Setup complete.

Port-forward istiod xDS (run this in a separate terminal before starting praxis):

  kubectl port-forward -n $ISTIO_NAMESPACE svc/istiod 15010:15010

Then run praxis with:

  GATEWAY_NAME=$GATEWAY_NAME \\
  GATEWAY_NAMESPACE=$GATEWAY_NAMESPACE \\
  ISTIOD_ADDR=http://localhost:15010 \\
  cargo run -p praxis-server

EOF
