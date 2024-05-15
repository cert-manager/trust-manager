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

kind_k8s_version := v1.29.4

# Goto https://github.com/kubernetes-sigs/kind/releases/tag/<KIND-VERSION> and find the
# multi-arch digest for the image you want to use. Then use crane to get the platform
# specific digest. For example (digest is the multi-arch digest from the release page):
# digest="sha256:51a1434a5397193442f0be2a297b488b6c919ce8a3931be0ce822606ea5ca245"
# crane digest --platform=linux/amd64 docker.io/kindest/node@$digest
# crane digest --platform=linux/arm64 docker.io/kindest/node@$digest

images_amd64 += docker.io/kindest/node:$(kind_k8s_version)@sha256:ea40a6bd365a17f71fd3883a1d34a0791d7d6b0eb75832c6d85b6f2326827f1e
images_arm64 += docker.io/kindest/node:$(kind_k8s_version)@sha256:e63a7f74e80b746328fbaa70be406639d0c31c8c8cf0a3d57efdd23c64fe4bba
