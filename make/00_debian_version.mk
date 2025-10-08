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

# WARNING: Changing this file triggers a build and release of the debian trust package
# This file is used to store the latest version of the debian trust package and the DEBIAN_BUNDLE_VERSION
# variable is automatically updated by the `upgrade-debian-trust-package-version` target and cron GH action.

DEBIAN_BUNDLE_VERSION := 20210119.1
DEBIAN_BUNDLE_SOURCE_IMAGE=docker.io/library/debian:11-slim
