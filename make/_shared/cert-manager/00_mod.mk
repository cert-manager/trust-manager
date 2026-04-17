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
cert_manager_version := v1.20.2

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:b8ba5a5d5cd1d9fd8276e900e0a9173b5b8a57bb30a147cffb34b1d33c9b9ab0
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:9459fdf3a31d38b8f482c3975babec3d6150e320998208052a0a751763f64dc7
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:2efc99557cf53745f06d9485d64974ab798339a4f08fce68453fff86f4f62792
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:0839111a33ea8da166017acad85b15404197bb7e8f791e977474413f8c96cd5e

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:e2b55ed3132101abb5b829779386dfcb38bb08b1c329ed854a1267341fbfc664
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:982e7e7caf9cb7e44117cdd73aa81de4b4ccb4d5df9e6ac984d59632644278c4
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:678cf2fab4580a3b9d540a1d27ee969006c83c4a5fe9834475c585073d360897
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:3a247ed94abb5ee53a55f9f2acbbe3caf0dceb1729f9f0cb5e9b867fbea5187a
