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

cert_manager_version := v1.18.2

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:058a3ee5b133f964acefbd5926a08ace1fb7c0775b92d3bc11e4c7a33de71e25
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:fd289495aed22983861cd8359fc535878ba388842faa9a01a33ebc5c9fe820d2
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:88f79993c4ad584324262419338d4a92919ea1495d984f44e34181c33d33e290
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:f37f4e84f892ec7d44432971336cd4f591a5eaf4f086b5f14d3d7d065721341b

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:980ecb589b54e91fa5c1cd97a0f1689e39ba62eb2904bcf43f63893671065780
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:5d3ae4ae5ba2135ebdc302e943e385544f975179aca9d6039a37e480e431e97c
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:ec280149b4ab0a2c4270deb0c9d5a7eb27ce8ae0cd2790140ca865fc6be5c0a1
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:3fa025c179daeb3672c100ff6c8398f4e428e31e1470b3acaa86ca958bdab7af
