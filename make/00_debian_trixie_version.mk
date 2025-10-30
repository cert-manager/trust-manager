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

# WARNING: Changing this file triggers a build and release of the Debian trust package for Trixie (Debian 13)
#
# This file is used to store the latest version of the debian trust package and the DEBIAN_BUNDLE_TRIXIE_VERSION
# variable is automatically updated by the `upgrade-debian-trust-package-trixie-version` target and cron GH action.

DEBIAN_BUNDLE_TRIXIE_VERSION := 20250419.20250419
DEBIAN_BUNDLE_TRIXIE_SOURCE_IMAGE=docker.io/library/debian:13-slim
