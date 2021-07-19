#!/bin/sh
set -o errexit

REPO_ROOT=$(dirname "${BASH_SOURCE}")/../..
KUBECTL_BIN="${KUBECTL_BIN:-$REPO_ROOT/bin/kubectl}"
HELM_BIN="${HELM_BIN:-$REPO_ROOT/bin/helm}"
KIND_BIN="${KIND_BIN:-$REPO_ROOT/bin/kind}"
TRUST_TAG="${TRUST_TAG:-smoke}"
TRUST_IMAGE="${TRUST_IMAGE:-quay.io/jetstack/cert-manager-trust:$TRUST_TAG}"

echo ">> creating kind cluster..."
$KIND_BIN delete cluster --name trust
$KIND_BIN create cluster --name trust

echo ">> building and loading docker image..."
GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -o $REPO_ROOT/bin/cert-manager-trust-linux $REPO_ROOT/cmd/.
docker build -t $TRUST_IMAGE .
$KIND_BIN load docker-image $TRUST_IMAGE --name trust

echo ">> installing cert-manager..."
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update
$HELM_BIN upgrade -i --create-namespace -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait

echo ">> installing trust..."
$HELM_BIN upgrade -i -n cert-manager cert-manager-trust $REPO_ROOT/deploy/charts/trust/. --set image.tag=$TRUST_TAG --set app.logLevel=2 --wait
