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
# debian bundle image in our container registry.

# If we installed a newer version in the local container, we build a new image container
# and push it upstream

CTR=${CTR:-docker}

REPO=${1:-}
DEBIAN_BUNDLE_SUFFIX=${2:-}

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

if [[ -z $DEBIAN_BUNDLE_SUFFIX ]]; then
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
# that we control. We can increment this if we need to build a second version of a given ca-certificates,
# say to add a new file or update the contents.

IMAGE_TAG=$CA_CERTIFICATES_VERSION$DEBIAN_BUNDLE_SUFFIX

FULL_IMAGE=$REPO:$IMAGE_TAG

echo "+++ searching for $FULL_IMAGE in upstream registry"

# Look for an image tagged with IMAGE_TAG; if it exists, we're done. If not, we need to build + upload it.
$CTR run --rm gcr.io/go-containerregistry/crane:v0.12.1 digest $FULL_IMAGE && echo "latest image appears to be up-to-date; exiting" && exit 0

echo "+++ latest image appears not to exist; building and pushing $FULL_IMAGE"

make DEBIAN_BUNDLE_VERSION=$CA_CERTIFICATES_VERSION DEBIAN_BUNDLE_SUFFIX=$DEBIAN_BUNDLE_SUFFIX bundle-debian-push
