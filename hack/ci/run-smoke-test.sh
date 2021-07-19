#!/bin/sh
set -o errexit

REPO_ROOT="${REPO_ROOT:-$(dirname "${BASH_SOURCE}")/../..}"
BINDIR="${BINDIR:-$(pwd)/bin}"

echo ">> running smoke tests"
${BINDIR}/kind get kubeconfig --name trust > ${BINDIR}/kubeconfig.yaml
${BINDIR}/ginkgo -nodes 1 $REPO_ROOT/test/smoke/ -- --kubeconfig-path ${BINDIR}/kubeconfig.yaml
