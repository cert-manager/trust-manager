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
cert_manager_version := v1.20.3

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:1e4af57beb469cc3bb0fb48b9201caea2723819b9ffd3c3ea98568f55b4dd38b
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:a2b12d27950d1603d2c8168c3ccd95d07b93ce6ec4b530316196a31db592a9c0
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:953a97df613f7da7eda8ce4b1c8d8e6b50963db0800fab595d040db6eb5cb060
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:1dae953280843bd637c619597eb0d9144f3d5185b518490494a080b521a1f3c7

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:af62a025ae4f8fd03209b5e0760868296bad5a9370aab0c91ad3b5476bcb282d
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:3c052c134ad1b93122b957f4d214aaa9d85a37b5ff15acc5b4d86f50e3ed822e
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:7c510875e038f79f7fba707b5f86d8736777a4dfefcd42179b08844ee75e685b
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:cbc16f8acc3b5337a9b78f453c99f4c179321e262754b02651d7ae5701a4732e
