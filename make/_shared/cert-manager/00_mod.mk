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
cert_manager_version := v1.19.1

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:9f823aa334ff8c5ac0f096e951faf8b52c52b711b795879b4c8d03d8e80b07a3
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:d5578165a84137e9228e4573bb1697b6a3ca7de09b5b20f53a2c97137d57fcef
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:275e864513bac87ee11f6bdf8fa9e7e21ffbb0ca9e963cb5b58bfc55f25feee0
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:45f08e01df2bba7c270718ca2a5c5df17fb93144ce3cb25dc64ae4f8693e1a29

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:de54b65c07a4d730bf0a27a7d505c3edf54d746d6be1d4da5916937730fc3f58
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:539c0175d5a4c95516de8beb98ac4a761e096e739f492ccdb07a761722653aa2
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:ef6847180c25c46996484eb2a0a5d00eaf9a9f9dd38fba7730091d23a0e322de
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:12bebaaf9d1b0664651b628d3c4d63c6d8b1cf44fe95c5b9d35d2fba1774d9cd
