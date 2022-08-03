#!/usr/bin/env bash

set -eu -o pipefail

REPO_ROOT="${REPO_ROOT:-$(dirname "${BASH_SOURCE}")/../..}"
BINDIR="${BINDIR:-$(pwd)/bin}"

echo ">> running smoke tests"
${BINDIR}/kind get kubeconfig --name trust > ${BINDIR}/kubeconfig.yaml
${BINDIR}/ginkgo --nodes 1 --no-color $REPO_ROOT/test/smoke/ -- --kubeconfig-path ${BINDIR}/kubeconfig.yaml
