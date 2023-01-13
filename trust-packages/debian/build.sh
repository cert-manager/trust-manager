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

# This script is designed to be run during a build of the debian bundle container
# As such, it's not designed to be portable and may only work in that situation

EXPECTED_VERSION=${1:-}
VERSION_SUFFIX=${2:-}
DESTINATION_FILE=${3:-}

if [[ -z $EXPECTED_VERSION || -z $VERSION_SUFFIX || -z $DESTINATION_FILE ]]; then
	echo "usage: $0 <expected version> <version suffix> <destination file>"
	exit 1
fi

apt-get -yq update
DEBIAN_FRONTEND=noninteractive apt-get -yq -o=Dpkg::Use-Pty=0 install --no-install-recommends ca-certificates jq tini

INSTALLED_VERSION=$(dpkg-query --show --showformat="\${Version}" ca-certificates)

if [[ "$EXPECTED_VERSION" != "latest" ]]; then
	if [[ "$EXPECTED_VERSION" != "$INSTALLED_VERSION" ]]; then
		echo "expected version $EXPECTED_VERSION but got $INSTALLED_VERSION"
		echo "this might mean that debian released an update between querying for version $EXPECTED_VERSION and running this build script"
		echo "exiting for safety"
		exit 1
	fi
fi

echo "{}" | jq \
	--rawfile bundle /etc/ssl/certs/ca-certificates.crt \
	--arg name "cert-manager-debian" \
	--arg version "$EXPECTED_VERSION$VERSION_SUFFIX" \
	'.name = $name | .bundle = $bundle | .version = $version' \
	> $DESTINATION_FILE

validate-trust-package < $DESTINATION_FILE
