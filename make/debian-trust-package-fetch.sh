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

# This script uses a container to install the latest ca-certificates package, and then
# checks to see if the installed version of that package matches the latest available
# debian trust package image in our container registry.

# If we installed a newer version in the local container, we build a new image container
# and push it upstream

CTR=${CTR:-docker}
BIN_VALIDATE_TRUST_PACKAGE=${BIN_VALIDATE_TRUST_PACKAGE:-}

ACTION=${1:-}
DEBIAN_SOURCE_IMAGE=${2:-}
DESTINATION_FILE=${3:-}
TARGET_DEBIAN_BUNDLE_VERSION=${4:-}

function print_usage() {
	echo "usage: $0 <latest|exact> <debian-source-image> <destination file> <target version>"
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

if [[ -z $ACTION ]]; then
	print_usage
	echo "ACTION must be set to either 'latest' or 'exact'"
	exit 1
elif [[ $ACTION != "latest" && $ACTION != "exact" ]]; then
	print_usage
	echo "ACTION must be set to either 'latest' or 'exact'"
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

if [[ -z $TARGET_DEBIAN_BUNDLE_VERSION ]]; then
	print_usage
	echo "target version must be specified"
	exit 1
fi
target_ca_certificates_version="${TARGET_DEBIAN_BUNDLE_VERSION%.*}"

echo "+++ fetching latest version of ca-certificates package"

TMP_DIR=$(mktemp -d)

# register the cleanup function to be called on the EXIT signal
trap 'rm -rf -- "$TMP_DIR"' EXIT

# Install the latest version of ca-certificates in a fresh container and print the
# installed version

# There are several commands for querying remote repos (e.g. apt-cache madison) but
# it's not clear that these commands are guaranteed to return installable versions
# in order or in a parseable format

# We specifically only want to query the latest version and without a guarantee on
# output ordering it's safest to install what apt thinks is the latest version and
# then see what we got.

# NB: It's also very difficult to make 'apt-get' stay quiet when installing packages
# so we just let it be loud and then only take the last line of output

install_target="ca-certificates"
if [[ "$ACTION" == "exact" ]]; then
	install_target="${install_target}=${target_ca_certificates_version}"
fi

cat << EOF > "$TMP_DIR/run.sh"
#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

apt-get -y update

DEBIAN_FRONTEND=noninteractive \
apt-get install -y --no-install-recommends ${install_target}

dpkg-query --show --showformat="\\\${Version}" ca-certificates | tail -n 1 > /workdir/version.txt

cp /etc/ssl/certs/ca-certificates.crt /workdir/ca-certificates.crt
EOF

$CTR run --rm --mount type=bind,source="$TMP_DIR",target=/workdir "$DEBIAN_SOURCE_IMAGE" /bin/bash /workdir/run.sh

installed_version=$(cat "$TMP_DIR/version.txt")
version_suffix=".0"

if [[ "$ACTION" == "latest" && "$installed_version" == "$target_ca_certificates_version" ]]; then
	version_suffix=".${TARGET_DEBIAN_BUNDLE_VERSION##*.}"
	echo "+++ installed version matches target version; reusing the current suffix '$version_suffix'"
fi

echo "{}" | jq \
	--rawfile bundle $TMP_DIR/ca-certificates.crt \
	--arg name "cert-manager-debian" \
	--arg version "$installed_version$version_suffix" \
	'.name = $name | .bundle = $bundle | .version = $version' \
	> "$DESTINATION_FILE"

${BIN_VALIDATE_TRUST_PACKAGE} < "$DESTINATION_FILE"
