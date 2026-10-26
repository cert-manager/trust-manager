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
cert_manager_version := v1.21.3

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:9b262e9493ab3e0daebc2c9cfbddc6df68b9ac91afc036a759584f3d49d607e5
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:165691f631d61931a27e4fbbb82bbed8205431d0446b3c14d170081aeff75f0a
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:fc2845cc042ab57c8b98c5ff62462d50dcd5d8d3302f9e6875cd05042ce1020b
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:6b9e17adc075c80c0c5cb1f901654f0efa4c5d4b1a8b369985ac67f5bbb0b8d2

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:e396f69ba33cf623694dcfb1f7c637911b06d71984350fb44158e0f7938f5a80
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:02d5ccb77275b12db6ab5a6275860be90d334be70def56e16b49e4eb7d96f142
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:acef59f95954b7e94a7f8a3bcccd65608bec579db567ad5e2b5a1d38c4b75f62
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:4049a9f87997def0396a82bcff58197870947ded66d6af0b1674ccce02f5391e
