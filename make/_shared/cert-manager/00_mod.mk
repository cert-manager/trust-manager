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
cert_manager_version := v1.19.3

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:c20867070d7f02c1f76c0b98d0d9d6f8fa95d70f504321a68de0a043b236d40e
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:a164796fa15377d82132df84256471027afbc10aa5483ac35c0c075643c9192a
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:083f1824373927c2a806702235c748e0609d06f28cfe66b488da8fbec83c323a
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:9d7f1d5ea42d92f7d5a5a2a7d3a44a95f5082f52f6ec72bdd9c4929a733daa84

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:f5c25399d3fcdb048759c62ce2d235296233a9977e98fca670f70d48418c1733
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:ff5ca45851e62d7b5b708da0118e01e16889bee704e719c6c34c9d94bf4c68f4
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:927383b56b0e1da507d47b1e52c747c7d5ed144594e044caa6c0f51980f80c97
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:f24855adb7a5d576585bf5218076254559362d410cf4303763686bc3689eed0b
