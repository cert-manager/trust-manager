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

cert_manager_version := v1.17.0

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:7722bca28c95b4c568f3d4cd2debc9286e0c4b092f0426840ed4d8ed314c09db
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:d99797c5d6e702416e69defb4c28a978d515a37a8a03b4405c4991b818cc791c
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:e43e270c7c50a3c1872e115df93458a78c230118cc3d12e9f6c848956e94c151
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:ce2f25777ad4a159b736e47dbaabfd62bf2c339c6f49fb6a6de79fb6b4a8ebed

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:d63cd0d15a3ed99736dd5623b798a3dd78fc36495623528d1bf58df37bc4a6cd
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:aaae16a38c8f4176b9645ff3069797ca2ec6e3262142794729440b342d759b89
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:45e8765b48d913ef26188782ec8dbee32f132c142249456a4e06c5c5c41e3927
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:c29e6270e6fc78181bb3a956c0714df24ea56840b9d3916122a36ee25ec6eac6
