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
cert_manager_version := v1.21.0

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:79a65ab008da7f067d6f68be937ba60d1d8a174168f66b6530c5ed0927c69986
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:d4962457c0c6b7a1399bdc84bd2748070353b5170bf856f697f09b239187b74a
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:af0a4f097872194799c07e24eda4561ade538fcee1d531d7ff824eeb297b0ae5
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:e1a8d1ab948634d36134978c585355c8c4168bacd38750f7ffbb05485957e9e5

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:11494ff2aae47908ef33bc436660e605fec3809dafda35cdb777939909fa0253
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:0583d676e24d4ff0d183342228be379e1ba420c74122bb9bcffeac4727b09248
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:c58bea1e83746e990d5622f39c636896a2eddfb6a871e785ae378f7dfb8ec538
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:6ad5099ec38fc74b4950073147b223cf70a454e960af87c29323859d544f6106
