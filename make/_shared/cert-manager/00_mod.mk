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
cert_manager_version := v1.19.4

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:d7b1f3c967bccf27a96ee6405fcc5d1f30796d761a3fffacf9058a050b3aa3bc
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:3a83c60dcb008d55edc411886ff0a55999316b3c63b2daaf6e7e0f30fe081c5f
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:a4b866914a5ef3bfde41b81cf002bacd888c217b8b54753626d19da7455f9bb3
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:0d52ef67029b6c3c1be8a07803c9214512a0828bfc5eb4e645a3217e446c7991

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:ceca54ceb2f3db2be02a9fde67ecf0bfe75d7ea6cfaf1fa301402d8ba11467a2
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:cce04565b1eeea8cf1137cfe4230d5ffc44d85b97d0052bd33c05e146a1e7292
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:7d9db1addeab73cd36d248c4918c934f7b89953f2a16c62d8f9257c12ce00277
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:a5ee473ca8365f82426d10ba10196dad84ada234249790e66894e0bec3775d80
