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

cert_manager_version := v1.16.0-beta.0

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:7262a0a0aee1a9adce9ff3ab3dde4715ddbf63253f934ba1ba8e81f8aecaddb7
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:711120cf4de64a7290e87bf2ecd6c513b405223e6a3221d7489099897514ac63
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:e841d7174cebcd83091523c49d06ef57779ea7ad5c0efbab809411daba2b5eef
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:9cf369704f1e64ab9ebdaf3b5104f5c6d5c9a761d1a67efdfe2fd2cfaaf1c15a

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:1c84bbd8e01a57e49b68fcf620b4eb9f9261cafff3f01cf31cad45a21b098805
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:ddca184e35616c916cea4d454acd7c26b7f67dfff689b34d74e87f0d5303328f
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:59b25f41dc29ef515465a742270930cded2510fd866ddd4842fe065aba817f1c
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:c78b364d8e7a93653ba1841a0a8aac4770a5703c0d2019f396f0bdc4a50f6f5a
