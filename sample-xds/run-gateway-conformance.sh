#!/usr/bin/env bash
# Runs the Kubernetes Gateway API conformance tests against the kind cluster
# created by setup.sh (MetalLB + Gateway API CRDs + Istio gwxds GatewayClass).
#
# The conformance tests live in a nested Go module with a local "replace" on
# the parent module, so this script shallow-clones kubernetes-sigs/gateway-api
# at a tag and runs `go test ./conformance` from the repo root (same as upstream
# `make conformance`).
#
# Prerequisites: git, go, kubectl; cluster already provisioned (see setup.sh).
#
# Usage:
#   ./run-gateway-conformance.sh
#   ./run-gateway-conformance.sh --debug --run-test=HTTPRouteInvalidCrossNamespaceParentRef
#   ./run-gateway-conformance.sh --single-test HTTPRouteSimpleSameNamespace
#   CONFORMANCE_SUPPORTED_FEATURES=Gateway,HTTPRoute,GRPCRoute ./run-gateway-conformance.sh
#
# Environment (defaults align with setup.sh):
#   CLUSTER_NAME                   kind cluster name (default: praxis-dev)
#   GATEWAY_CLASS                  GatewayClass metadata.name (default: istio-gwxds)
#   GATEWAY_API_REF                git tag or branch (default: v1.5.1, matches setup.sh CRDs)
#   GATEWAY_API_SRC                if set, use this checkout instead of cloning
#   GATEWAY_API_REPO               clone URL (default: upstream gateway-api)
#   GATEWAY_API_CACHE              parent directory for the shallow clone (default: XDG_CACHE_HOME/.../praxis-gateway-api-conformance)
#   CONFORMANCE_SUPPORTED_FEATURES comma list for --supported-features (default: Gateway,HTTPRoute)
#   GO_TEST_FLAGS                  go test flags before ./conformance (default: -timeout=3h -count=1 -v)
#
# Any additional arguments are forwarded after the defaults (conformance test flags, e.g. --debug).
#
set -euo pipefail

info()  { echo "==> $*"; }
warn()  { echo "WARN: $*" >&2; }
fatal() { echo "ERROR: $*" >&2; exit 1; }

CLUSTER_NAME="${CLUSTER_NAME:-praxis-dev}"
GATEWAY_CLASS="${GATEWAY_CLASS:-istio-gwxds}"
GATEWAY_API_REF="${GATEWAY_API_REF:-v1.5.1}"
GATEWAY_API_REPO="${GATEWAY_API_REPO:-https://github.com/kubernetes-sigs/gateway-api.git}"
CACHE_ROOT="${GATEWAY_API_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/praxis-gateway-api-conformance}"
CLONE_DIR="${CACHE_ROOT}/gateway-api"
if [[ -z "${GO_TEST_FLAGS:-}" ]]; then
  GO_TEST_FLAGS="-timeout=3h -count=1 -v"
fi
SUPPORTED_FEATURES="${CONFORMANCE_SUPPORTED_FEATURES:-Gateway,HTTPRoute}"
GO_TEST_RUN="${GO_TEST_RUN:-TestConformance}"
SINGLE_TEST="${CONFORMANCE_SINGLE_TEST:-}"
FORWARD_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --single-test)
      [[ $# -ge 2 ]] || fatal "--single-test requires a value"
      SINGLE_TEST="$2"
      shift 2
      ;;
    --single-test=*)
      SINGLE_TEST="${1#*=}"
      shift
      ;;
    *)
      FORWARD_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ -n "$SINGLE_TEST" ]]; then
  GO_TEST_RUN="TestConformance/${SINGLE_TEST}$"
  FORWARD_ARGS+=(--run-test="$SINGLE_TEST")
fi

require() {
  for cmd in "$@"; do
    command -v "$cmd" &>/dev/null || fatal "required tool not found: $cmd"
  done
}

require git go kubectl

CTX="kind-${CLUSTER_NAME}"
kubectl config use-context "$CTX" &>/dev/null || fatal "kubectl context '$CTX' not found (create the cluster with setup.sh first)"

if ! kubectl get gatewayclass "$GATEWAY_CLASS" &>/dev/null; then
  warn "GatewayClass '$GATEWAY_CLASS' not found — tests will fail until it exists (run setup.sh or apply resources.yaml)"
fi

ensure_gateway_api_src() {
  if [[ -n "${GATEWAY_API_SRC:-}" ]]; then
    [[ -d "$GATEWAY_API_SRC" ]] || fatal "GATEWAY_API_SRC is not a directory: $GATEWAY_API_SRC"
    GW_SRC="$(cd "$GATEWAY_API_SRC" && pwd)"
    info "Using GATEWAY_API_SRC=$GW_SRC"
    return
  fi

  mkdir -p "$CACHE_ROOT"

  if [[ ! -d "$CLONE_DIR/.git" ]]; then
    info "Shallow-cloning gateway-api ${GATEWAY_API_REF} into ${CLONE_DIR}"
    git clone --depth 1 --branch "${GATEWAY_API_REF}" "$GATEWAY_API_REPO" "$CLONE_DIR"
  elif ! git -C "$CLONE_DIR" checkout -q "${GATEWAY_API_REF}" 2>/dev/null; then
    warn "Could not checkout ${GATEWAY_API_REF} in existing clone (shallow history); re-cloning"
    rm -rf "$CLONE_DIR"
    git clone --depth 1 --branch "${GATEWAY_API_REF}" "$GATEWAY_API_REPO" "$CLONE_DIR"
  else
    info "Using cached gateway-api at ${CLONE_DIR} (ref ${GATEWAY_API_REF})"
  fi

  GW_SRC="$(cd "$CLONE_DIR" && pwd)"
}

ensure_gateway_api_src

[[ -d "$GW_SRC/conformance" ]] || fatal "missing conformance/ in $GW_SRC (unexpected gateway-api layout)"

info "Running Gateway API conformance (ref=${GATEWAY_API_REF}, gateway-class=${GATEWAY_CLASS})"
info "go test -run regex: ${GO_TEST_RUN}"

cd "$GW_SRC"
# shellcheck disable=SC2086
exec go test ${GO_TEST_FLAGS} -run "${GO_TEST_RUN}" ./conformance \
  -args \
  --gateway-class="${GATEWAY_CLASS}" \
  --supported-features="${SUPPORTED_FEATURES}" \
  "${FORWARD_ARGS[@]}"
