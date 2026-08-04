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
cert_manager_version := v1.21.1

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:4c2b5201fd66085b777dc6b256d96d7d346b6445404cec34db5f8aea86182cc5
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:1910ad7e134880e27d229e07affb43da1b07841a77f70c364f17467cb4e49bd9
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:741084291faf115a2909bfe3515458b54926c67f039ac20effd821bac69817a4
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:15cafecd3d23a4fa2226185f78c4792914010b2713f59060a1b9b484029041e4

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:9a2807ada15c98aea85162bed3a9d602a5a4760206158661433be0b3ea133837
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:0c5930d51b9acc07b1d1f6befa46bdc3591fc52c0254f6209bf595eb5fdb3b7c
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:f6ed5d53a40429c99a28b68ce0429f3d75ac9588403519c6772a76df35f37695
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:70a55b1c510c23e60767453633f925cef0434528e5130657f457d83769700863
