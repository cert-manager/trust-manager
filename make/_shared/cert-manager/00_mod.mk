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
cert_manager_version := v1.21.2

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:57bb397c639e0e94184ba67848e5dad04284f24645e521e764a0ee5f5002f286
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:aa2bc58725d92a643f5069dde58abc93b65566ded8951348873ac9ee7efef66c
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:b929259301ee75270ab4651d5e6bd4ba7b6624b1ce48ba767d064295a9312101
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:ed347b0ab607058f139b83f41567109456b9776330b63da8086a120afb7f1729

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:72dc9c82e92ab6b192058fb2dce7ac21be8f7bee73dc7c72715599b2cfbf3bea
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:37b8d8a31e45be7a6ee54d8a385e88936c10111f1193820f1c1735651869be4d
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:f88c604159064290c77d94c655ca19a33d8e46781ef90b9ce6d8c3d4a808dc74
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:d8c5973e017d1575c72522caa6188f3c9134103f333363bd7df5c172fb6e7f0b
