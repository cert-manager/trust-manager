# Copyright 2025 The cert-manager Authors.
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

# WARNING: Changing this file triggers a build and release of the Debian trust package for Bookworm (Debian 12)
#
# DEBIAN_BOOKWORM_CA_CERTS_VERSION stores the ca-certificates apt package version and is
# automatically updated by Renovate using the Debian deb datasource.
# DEBIAN_BOOKWORM_BUNDLE_RELEASE can be incremented to re-release the trust bundle with the
# same ca-certificates version (e.g. to fix a packaging issue) without overwriting existing
# OCI image tags. Reset to 0 when the ca-certificates version changes.

DEBIAN_BOOKWORM_CA_CERTS_VERSION := 20230311+deb12u1
DEBIAN_BOOKWORM_BUNDLE_RELEASE := 0
DEBIAN_BOOKWORM_BUNDLE_SOURCE_IMAGE=docker.io/library/debian:12-slim
