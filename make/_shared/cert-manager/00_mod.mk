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

cert_manager_version := v1.15.0

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:9b5d5e9c0fd4944221d059921cc05f388c9a5fc0b02a60b47f0eccfcd8243331
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:edb1c1e0083ee4cd8e2ccb296ee0f436d2e465ecf90159f9d03141fc19bd3c23
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:85df7b64a3d66de3cd7995ae0f2151b54fd18db424cb7cf84d3bd6d4a39d975f
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:6365e940a5a913a3aeca0ea519102236d9bec5f0e8f0011fa3498c26d18348e5

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:716c154f0eecb381d5f63ba78ee1dd0cce4b57dbe15cbbc121f7e8b1071e6268
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:59cbf06f489a7bb2c859296fa32ac7fcfd315c3f2e802be7805b598303b6cef5
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:039c83b5b081d519e9152c19aedd1c7c17daa09187d1ad21df6689da342bb5b7
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:b2d5b00de8b1de6051c02a3f82cfa4ee617210ef1db5c295440e9a2d2069e547
