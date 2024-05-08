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

kind_k8s_version := v1.29.2

# Goto https://github.com/kubernetes-sigs/kind/releases/tag/<KIND-VERSION> and find the
# multi-arch digest for the image you want to use. Then use crane to get the platform
# specific digest. For example (digest is the multi-arch digest from the release page):
# digest="sha256:51a1434a5397193442f0be2a297b488b6c919ce8a3931be0ce822606ea5ca245"
# crane digest --platform=linux/amd64 docker.io/kindest/node@$digest
# crane digest --platform=linux/arm64 docker.io/kindest/node@$digest

images_amd64 += docker.io/kindest/node:$(kind_k8s_version)@sha256:acc9e82a5a5bd3dfccfd03117e9ef5f96b46108b55cd647fb5e7d0d1a35c9c6f
images_arm64 += docker.io/kindest/node:$(kind_k8s_version)@sha256:068aaa834c09ab60d925a8569c6b5f5b9cf46eccf670499176f3267f2ac3189c
