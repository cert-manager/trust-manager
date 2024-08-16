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

cert_manager_version := v1.15.3

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:631ba2b3bf7be0bd0d446b8bfcbeb56f8fe735cd02a267567a8d94682d03165b
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:6802c6afea2da91f5782880b79008179bb98147a23ce00f3cab5ba799807b5d6
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:373e3acd7b96c87a574f9234bb4fbfd576e3205c502d6da5dade41165c9dc828
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:a896ff5d8029e5a040643935089ef0466fe0c1f6b2fe591f342994c53aada6e2

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:06fed982efd0c2b59736718ace9f7d482fda550d9398cc90b01a9ceb98c3fbb5
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:549347a89682abc0ede551b253a617defc398c7b2b1ede4c66cb71f33326c2d1
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:51fe148d9e5269511f5fdac2db8cb64611acd6b118e5fcade00302442da33a8a
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:a15bfed2b625f7c97029ac4ba2777a13897a4492cc995cafda4594d30ab3d721
