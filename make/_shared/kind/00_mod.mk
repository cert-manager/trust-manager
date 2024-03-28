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

kind_k8s_version := v1.29.0

# Goto https://github.com/kubernetes-sigs/kind/releases/tag/<KIND-VERSION> and find the
# multi-arch digest for the image you want to use. Then use crane to get the platform
# specific digest. For example (digest is the multi-arch digest from the release page):
# digest="sha256:eaa1450915475849a73a9227b8f201df25e55e268e5d619312131292e324d570"
# crane digest --platform=linux/amd64 docker.io/kindest/node@$digest
# crane digest --platform=linux/arm64 docker.io/kindest/node@$digest

images_amd64 += docker.io/kindest/node:$(kind_k8s_version)@sha256:54a50c9354f11ce0aa56a85d2cacb1b950f85eab3fe1caf988826d1f89bf37eb
images_arm64 += docker.io/kindest/node:$(kind_k8s_version)@sha256:8ccbd8bc4d52c467f3c79eeeb434827c225600a1d7385a4b1c19d9e038c9e0c0
