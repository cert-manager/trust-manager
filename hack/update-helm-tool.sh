#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
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

HELM_TOOL_BIN=${1:-}

if [[ -z $HELM_TOOL_BIN ]]; then
	echo "usage: $0 <path-to-helm-docs>"
	exit 1
fi

$HELM_TOOL_BIN inject -i ./deploy/charts/trust-manager/values.yaml -o ./deploy/charts/trust-manager/README.md --header-search '^<!-- AUTO-GENERATED -->' --footer-search '^<!-- /AUTO-GENERATED -->'
