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

REPO=${1:-}
DEBIAN_TRUST_PACKAGE_SUFFIX=${2:-}
REGISTRY_API_URL=${3:-}

DEBIAN_IMAGE=docker.io/library/debian:11-slim

function print_usage() {
	echo "usage: $0 <target-repo> <version-suffix>"
}

if ! command -v $CTR &>/dev/null; then
	print_usage
	echo "This script requires a docker CLI compatible runtime, either docker or podman"
	echo "If CTR is not set, defaults to using docker"
	echo "Couldn't find $CTR command; exiting"
	exit 1
fi

if [[ -z $REPO ]]; then
	print_usage
	echo "Missing target-repo"
	exit 1
fi

if [[ -z $DEBIAN_TRUST_PACKAGE_SUFFIX ]]; then
	print_usage
	echo "Missing version suffix"
	exit 1
fi

function latest_ca_certificate_package_version() {
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

	$CTR run --rm $DEBIAN_IMAGE bash -c 'apt-get -yq update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -qy -o=Dpkg::Use-Pty=0 install --no-install-recommends ca-certificates >/dev/null && dpkg-query --show --showformat="\${Version}" ca-certificates' | tail -1
}

echo "+++ fetching latest version of ca-certificates package"

CA_CERTIFICATES_VERSION=$(latest_ca_certificate_package_version)

# Rather than use CA_CERTIFICATES_VERSION directly as an image tag, suffix our own version number
# that we control.
# We can increment this if we need to build a second version of a given ca-certificates,
# say to add a new file or update the contents.

IMAGE_TAG=$CA_CERTIFICATES_VERSION$DEBIAN_TRUST_PACKAGE_SUFFIX

FULL_IMAGE=$REPO:$IMAGE_TAG

# This ACCEPT_HEADER matches what `crane` sends, and causes the server to
# return a manifest we can parse as expected
ACCEPT_HEADER="Accept: application/vnd.docker.distribution.manifest.v1+json,application/vnd.docker.distribution.manifest.v1+prettyjws,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json"

manifest=$(mktemp)

trap 'rm -f -- "$manifest"' EXIT

echo "+++ searching for $FULL_IMAGE in upstream registry"

# Look for an image tagged with IMAGE_TAG; if this is successful, we're done. If we get a 404 we need to build + upload it. If we get any other error, we need to quit
STATUS_CODE=$(curl --silent --show-error --location --retry 5 --retry-connrefused --output $manifest --write-out "%{http_code}" --header "$ACCEPT_HEADER" $REGISTRY_API_URL/$IMAGE_TAG)

if [[ $STATUS_CODE = "200" ]]; then
	echo "upstream registry appears to contain $FULL_IMAGE, will check supported architectures"

	# NB: This ignores 32-bit ARM versions and other variables, but it works OK for now
	EXPECTED_ARCHES="amd64
arm
arm64
ppc64le
s390x"

	GOT_ARCHES=$(jq '.manifests[].platform.architecture' -r <$manifest | sort)

	if [[ "$GOT_ARCHES" == "$EXPECTED_ARCHES" ]]; then
		echo "upstream registry has all expected arches, exiting"
		exit 0
	fi

	echo "+++ architectures didn't match"
	echo -e "+++ wanted:\n$EXPECTED_ARCHES"
	echo -e "+++ got:\n$GOT_ARCHES"

elif [[ $STATUS_CODE != "404" ]]; then
	echo "fatal: upstream registry returned an unexpected error response $STATUS_CODE, exiting"
	exit 1
fi

echo "+++ latest image appears not to exist or to be missing archictures; building and pushing $FULL_IMAGE"

make DEBIAN_TRUST_PACKAGE_VERSION=$CA_CERTIFICATES_VERSION DEBIAN_TRUST_PACKAGE_SUFFIX=$DEBIAN_TRUST_PACKAGE_SUFFIX trust-package-debian-push
