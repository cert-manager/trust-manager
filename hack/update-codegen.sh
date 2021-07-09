#!/usr/bin/env bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

TRUST_DISTRIBUTION_PKG="github.com/cert-manager/trust"
BOILERPLATE="hack/boilerplate/boilerplate.go.txt"

APIS_PKG="$TRUST_DISTRIBUTION_PKG/pkg/apis"
GROUPS_WITH_VERSIONS="trust:v1alpha1"

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
BIN_DIR=${SCRIPT_ROOT}/bin

function codegen::join() { local IFS="$1"; shift; echo "$*"; }

# enumerate group versions
FQ_APIS=() # e.g. k8s.io/api/apps/v1
for GVs in ${GROUPS_WITH_VERSIONS}; do
  IFS=: read -r G Vs <<<"${GVs}"

  # enumerate versions
  for V in ${Vs//,/ }; do
    FQ_APIS+=("${APIS_PKG}/${G}/${V}")
  done
done

echo "Generating deepcopy funcs"
${BIN_DIR}/deepcopy-gen --input-dirs "$(codegen::join , "${FQ_APIS[@]}")" -O zz_generated.deepcopy --bounding-dirs "${APIS_PKG}" -h $BOILERPLATE

echo "Generating CRDs in ./deploy/charts/trust/templates"
${BIN_DIR}/controller-gen crd schemapatch:manifests=./deploy/charts/trust/templates output:dir=./deploy/charts/trust/templates paths=./pkg/apis/...
