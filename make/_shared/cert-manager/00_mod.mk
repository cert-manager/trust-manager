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

cert_manager_version := v1.16.0

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:b45df0d537a7a8ef2d968bd2621547dd43d93230a5b12a89cf496a081db2edd3
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:13d60b82759fec353c5c35280b902bf3f3c8680b471501792b62a7db2ef706e1
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:a98cc73669ed5e3220a064732649c541b4d2c272327271f63f9129a6f234ca63
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:42b5c24cdf9fb68ccc4de4854e0336ac9e05bfacbd4c6ad9b85787db2e73c646

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:af089c67364f0ed282cb11b3994bea7bfa485d75a7b019c2c532ea118455f49b
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:53a5206399898f2f754d45943211a38bdd82a23beb7f3ce33c30950117c95ebc
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:f8f633a1fe9089375e1c0debd5e7b1672ac740f2294453a37863a3d0b6d0a1cc
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:9ab84f036989c71d531882acb3549799265e7f04b5fb719f4fd1bce6f9e2c9b0
