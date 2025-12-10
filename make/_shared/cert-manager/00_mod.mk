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

images_amd64 ?=
images_arm64 ?=

# renovate: datasource=github-releases packageName=cert-manager/cert-manager
cert_manager_version := v1.19.2

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:ab0905bad1a9acf05ca92b23761a9ecc76b1173053565c81fed727dff948d0f5
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:687398bee209314862fa1a7e830a37d8d7145653a8cc5579edcf9b6d2b766f56
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:041f7bb9259557188d7ff416ce90d670a0d0aa8710203927703743682064270b
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:9f02973f35959c9e7ffc3e09eefab365c9f1e391188d5cccffc00ec6d73a038d

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:a46bf31ceb720e7c55a2c0bc28d862da691fdc86f666ea55389e648c3efb5bef
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:975fe883ae1d1d4025e6beab145ad862250505f2a465d29f87e4b9211e62e6f9
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:f245a83da29efee1d57cd6dc6fcd1adb1f6043e40f8e9b3d7b8ac256a6bae9c1
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:bf36062100c2d3150a47b69bbf9147fb5974ebd0fd377100429191b3997b8cdd
