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

# This script uses a container to install the ca-certificates package at the
# specified version and extracts the bundle for use in a trust package OCI image.

CTR=${CTR:-docker}
BIN_VALIDATE_TRUST_PACKAGE=${BIN_VALIDATE_TRUST_PACKAGE:-}

DEBIAN_SOURCE_IMAGE=${1:-}
DESTINATION_FILE=${2:-}
TARGET_DEBIAN_BUNDLE_VERSION=${3:-}
PACKAGE_NAME=${4:-}

function print_usage() {
	echo "usage: $0 <debian-source-image> <destination file> <target version> <package name>"
}

if ! command -v "$CTR" &>/dev/null; then
	print_usage
	echo "This script requires a docker CLI compatible runtime, either docker or podman"
	echo "If CTR is not set, defaults to using docker"
	echo "Couldn't find $CTR command; exiting"
	exit 1
fi

if [[ -z $BIN_VALIDATE_TRUST_PACKAGE ]]; then
	print_usage
	echo "BIN_VALIDATE_TRUST_PACKAGE must be set to the path of the validate-trust-package binary"
	exit 1
fi

if [[ -z $DEBIAN_SOURCE_IMAGE ]]; then
	print_usage
	echo "debian source image must be specified"
	exit 1
fi

if [[ -z $DESTINATION_FILE ]]; then
	print_usage
	echo "destination file must be specified"
	exit 1
fi

if [[ -z $PACKAGE_NAME ]]; then
	print_usage
	echo "package name must be specified"
	exit 1
fi

if [[ -z $TARGET_DEBIAN_BUNDLE_VERSION ]]; then
	print_usage
	echo "target version must be specified"
	exit 1
fi

echo "+++ fetching ca-certificates package version '$TARGET_DEBIAN_BUNDLE_VERSION'"

TMP_DIR=$(mktemp -d)

# register the cleanup function to be called on the EXIT signal
trap 'rm -rf -- "$TMP_DIR"' EXIT

# Install the specified version of ca-certificates in a fresh container and
# extract the bundle.

# NB: It's also very difficult to make 'apt-get' stay quiet when installing
# packages so we just let it be loud and then only take the last line of output

cat << EOF > "$TMP_DIR/run.sh"
#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

apt-get -y update

DEBIAN_FRONTEND=noninteractive \
apt-get install -y --no-install-recommends ca-certificates=${TARGET_DEBIAN_BUNDLE_VERSION}

dpkg-query --show --showformat="\\\${Version}" ca-certificates | tail -n 1 > /workdir/version.txt

cp /etc/ssl/certs/ca-certificates.crt /workdir/ca-certificates.crt
EOF

$CTR run --rm --mount type=bind,source="$TMP_DIR",target=/workdir "$DEBIAN_SOURCE_IMAGE" /bin/bash /workdir/run.sh

installed_version=$(cat "$TMP_DIR/version.txt")

echo "{}" | jq \
	--rawfile bundle $TMP_DIR/ca-certificates.crt \
	--arg name "$PACKAGE_NAME" \
	--arg version "$installed_version" \
	'.name = $name | .bundle = $bundle | .version = $version' \
	> "$DESTINATION_FILE"

${BIN_VALIDATE_TRUST_PACKAGE} < "$DESTINATION_FILE"
