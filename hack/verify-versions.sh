#!/usr/bin/env bash

# Copyright 2023 The cert-manager Authors.
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

MAKEFILE_RELEASE_VERSION=$(grep -E "^RELEASE_VERSION" Makefile | awk '{print $3}')

# This is a tortured way to avoid installing yq
HELM_CHART_VALUES_VERSION=$(grep -E -A1 "Target image version" deploy/charts/trust-manager/values.yaml | grep "tag:" | awk '{print $2}')

HELM_CHART_VERSION=$(grep -E "^version:" deploy/charts/trust-manager/Chart.yaml | awk '{print $2}')

# We might not always want appVersion to match version, but for now it probably
# makes sense to enforce that they remain the same
HELM_CHART_APP_VERSION=$(grep -E "^appVersion:" deploy/charts/trust-manager/Chart.yaml | awk '{print $2}')

# echo "makefile RELEASE_VERSION: $MAKEFILE_RELEASE_VERSION"
# echo "helm chart version: $HELM_CHART_VERSION"
# echo "helm chart app version: $HELM_CHART_APP_VERSION"
# echo "helm chart values version: $HELM_CHART_VALUES_VERSION"

mismatch=0

if [[ $MAKEFILE_RELEASE_VERSION != $HELM_CHART_VERSION ]]; then
	echo "!!! mismatch between makefile version and helm chart version"

	mismatch=1
fi

if [[ $MAKEFILE_RELEASE_VERSION != $HELM_CHART_APP_VERSION ]]; then
	echo "!!! mismatch between makefile version and helm chart appVersion"

	mismatch=1
fi

if [[ $MAKEFILE_RELEASE_VERSION != $HELM_CHART_VALUES_VERSION ]]; then
	echo "!!! mismatch between makefile version and helm values controller container tag"

	mismatch=1
fi

if [[ mismatch -ne 0 ]]; then
	echo "at least one version was incorrect"
	exit 1
fi
