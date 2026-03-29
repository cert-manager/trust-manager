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
cert_manager_version := v1.20.1

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:a6875f0ab2fbb7c7d93fd524b7fd1430c75c1e89d203005a0d22df15fa21a346
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:a11ce0607c2653f05a8da3b67023f45d662814c47fb01536b8836fe1043f429b
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:72ef5f5b9128c1387505a7aad12dc2bd19c3d31c41790766b1f4b2d6a91da8fb
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:5000c49930dbc668de51868ddf721ca55b7378b03de7476ffb314950b9d55018

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:ab365558ac80523c27644d1c47e9e61ce8ec4acd9a03fadf9f404afb4ba21cad
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:3999703d97f33f0f646206b42eac98d35e8dd587d908c13b72a34b50c0ed8773
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:f58fb1bdd70b9cf1f807ddbdfbddbbd3e86220a9b224709a9c607c3d2dff3b54
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:eeea7d068c2d626c0d34a3d29ebc36ce6e513a07180a35a5ab0189d558bff5e3
