#!/bin/sh
set -o errexit

REPO_ROOT="${REPO_ROOT:-$(dirname "${BASH_SOURCE}")/../..}"
KUBECTL_BIN="${KUBECTL_BIN:-$REPO_ROOT/bin/kubectl}"
HELM_BIN="${HELM_BIN:-$REPO_ROOT/bin/helm}"
KIND_BIN="${KIND_BIN:-$REPO_ROOT/bin/kind}"
TRUST_TAG="${TRUST_TAG:-smoke}"
TRUST_IMAGE="${TRUST_IMAGE:-quay.io/jetstack/cert-manager-trust:$TRUST_TAG}"

echo ">> building docker image..."
docker build -t $TRUST_IMAGE .


echo ">> pre-creating 'kind' docker network to avoid networking issues in CI"
# When running in our CI environment the Docker network's subnet choice will cause issues with routing
# This works around this till we have a way to properly patch this.
docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind || true
# Sleep for 2s to avoid any races between docker's network subcommand and 'kind create'
sleep 2

echo ">> creating kind cluster..."
$KIND_BIN delete cluster --name trust
$KIND_BIN create cluster --name trust

echo ">> loading docker image..."
$KIND_BIN load docker-image $TRUST_IMAGE --name trust

echo ">> installing cert-manager..."
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update
$HELM_BIN upgrade -i --create-namespace -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait --devel --version v1.7.0-beta.0

echo ">> installing trust..."
$HELM_BIN upgrade -i -n cert-manager cert-manager-trust $REPO_ROOT/deploy/charts/trust/. --set image.tag=$TRUST_TAG --set app.logLevel=2 --wait
