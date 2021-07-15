#!/bin/sh
set -o errexit

cd $(dirname "${BASH_SOURCE}")/../..

BINDIR="${BINDIR:-$(pwd)/bin}"

echo ">> running smoke tests"
${BINDIR}/kind get kubeconfig --name trust > ${BINDIR}/kubeconfig.yaml
${BINDIR}/ginkgo -nodes 1 test/smoke/ -- --kubeconfig-path ${BINDIR}/kubeconfig.yaml
