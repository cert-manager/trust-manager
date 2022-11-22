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

# File taken from a closed-source project originally written by SgtCoDFish
# Contributed to the trust-manager project under the above Apache license

set -o errexit
set -o nounset
set -o pipefail

# This script is required as "buildx rm" and "buildx create" can return successfully
# before they actually finish. We need to ensure that the builder is actually removed
# or created (as needed) before we proceed.

BUILDX_BUILDER=${1:-}
MODE=${2:-}

if [[ -z $BUILDX_BUILDER ]]; then
	echo "usage: $0 <builder-name> <mode>"
	echo "error: missing builder name. exiting"
	exit 1
fi

if [[ $MODE != "exists" && $MODE != "gone" ]]; then
	echo "usage: $0 <builder-name> <mode>"
	echo "error: invalid mode, expected either 'exists' or 'gone'"
	echo "'exists' means 'wait for the builder to exist'"
	echo "'gone' means 'wait for the builder to not exist'"
	exit 1
fi

RETRIES=5

if [[ $MODE = "exists" ]]; then
	until docker buildx inspect --builder $1 >/dev/null 2>&1 || [ $RETRIES -eq 0 ]; do
		echo "Waiting for buildx builder to exist, $((RETRIES--)) remaining attempts..."
		sleep 1
	done
else
	while docker buildx inspect --builder $1 >/dev/null 2>&1 || [ $RETRIES -eq 0 ]; do
		echo "Waiting for buildx builder to not exist, $((RETRIES--)) remaining attempts..."
		sleep 1
	done
fi
