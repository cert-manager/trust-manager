#!/usr/bin/env bash

# +skip_license_check

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

if [[ -z "${1:-}"  ]]; then
	echo "usage: $0 <path-to-controller-gen>" >&2
	exit 1
fi

CONTROLLER_GEN=$(realpath "$1")

echo "Generating CRDs in ./deploy/crds"
$CONTROLLER_GEN crd schemapatch:manifests=./deploy/crds output:dir=./deploy/crds paths=./pkg/apis/...

echo "Updating CRDs with helm templating, writing to ./deploy/charts/trust-manager/templates"
for i in $(ls ./deploy/crds); do

  cat << EOF > ./deploy/charts/trust-manager/templates/$i
{{ if .Values.crds.enabled }}
$(cat ./deploy/crds/$i)
{{ end }}
EOF

done
