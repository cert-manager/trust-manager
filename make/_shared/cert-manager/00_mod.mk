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
cert_manager_version := v1.20.0

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:af0cac0906ef524c2657da07fe5bd39dd58bbc737817229e048d47363a1dd4f3
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:ddbed11f6ff0d72692811dd78a26775592a8436b9cefd1071ad1cb26f26f533f
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:4026403e02e370243fefd692714d25cafbf22e34288ffe51e80066d01496d485
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:e0278b3e9d3f4e9bcfb50e786a4d22b8c1f9b1d7715d471107dd40d75cf728d3

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:e4beb9c5bccb658dedf8d2229ee29df4658bab957ee9a4aea5d103c62fe2db99
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:435c8f2c32a65177d6d1b5daa97b4da53f9de172f4fcc77a412043d01f7adce6
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:43f0f8d7e52e181ef815059b932ee36a92650d47f4a930a1600d203a6eb303fe
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:f631ed4bfa17ecd5a26b53b936037de55c297db783b4303f9efe48ad6cde53d5
