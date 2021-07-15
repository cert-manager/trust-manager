#!/bin/sh
set -o errexit

KUBECTL_BIN="${KUBECTL_BIN:-./bin/kubectl}"
HELM_BIN="${HELM_BIN:-./bin/helm}"
KIND_BIN="${KIND_BIN:-./bin/kind}"
TRUST_TAG="${TRUST_TAG:-smoke}"
TRUST_IMAGE="${TRUST_IMAGE:-quay.io/jetstack/cert-manager-trust:$TRUST_TAG}"

cd $(dirname "${BASH_SOURCE}")/../..

echo ">> creating kind cluster..."
$KIND_BIN delete cluster --name trust
$KIND_BIN create cluster --name trust

echo ">> building and loading docker image..."
GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/cert-manager-trust-linux ./cmd/.
docker build -t $TRUST_IMAGE .
$KIND_BIN load docker-image $TRUST_IMAGE --name trust

echo ">> installing cert-manager..."
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update
$HELM_BIN upgrade -i --create-namespace -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait

echo ">> installing trust..."
$HELM_BIN upgrade -i -n cert-manager cert-manager-trust ./deploy/charts/trust/. --set image.tag=$TRUST_TAG --set app.logLevel=2 --wait
