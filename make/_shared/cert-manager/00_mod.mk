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

cert_manager_version := v1.14.4

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:f84edf06327f84ed2ca056776659aa144cf3cc982c5403650c24553c5a44b03d
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:8267563833c31cc428b9ae460b890d079a1da09a4d8d00ec299a47dd613fbd24
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:ba5469d1a77b1cb04a703199b0e69bc25644a00498adc3694a0369c87375b4ca
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:2a1545099cf6386ab08e979a58a6280fe123d091c69f8222bfb22c597003a3f0

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:39a6e9e699b3dacb8b92538efbaff85c16d4b30343ebeaaf2f35772ff3cebf53
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:956aac21371499fdcc8811b4b5fc8e2e0d6e552b15723c783fe56270347fc9e0
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:8ea8462c1daa7604f4f2e71e0cdeef3dd5d7e0f04341982a05dc296299766126
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:f4cd54540f8813e63a2f53b5b210454ae2a5fe0949b9f55d8f1270162ebad9a8
