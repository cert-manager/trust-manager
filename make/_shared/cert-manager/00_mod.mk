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

cert_manager_version := v1.14.5

images_amd64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:f37f460aaa7598ba251ff1cbe7438012fd56c4acc94be64245e8a836203c5542
images_amd64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:6d9ebced61371cc903f7934690923034382456f3ce6e0fe2b692c40dbd67d523
images_amd64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:ac34b1905a2ff20789fde27115d3e1aa7b3d09f57efba4e91ae2ba1744de4ad2
images_amd64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:5c74e4e37586dc5c35442515f43ecf222e961b65e954798428ac9239408bc0f3

images_arm64 += quay.io/jetstack/cert-manager-controller:$(cert_manager_version)@sha256:96668890d162a743407c0ef14d7769e970aa16655959b5f5cab0c595167148fa
images_arm64 += quay.io/jetstack/cert-manager-cainjector:$(cert_manager_version)@sha256:719aec5d99e86377829261451985592bc4129c5ca8dcb7f20b32170742f2b29b
images_arm64 += quay.io/jetstack/cert-manager-webhook:$(cert_manager_version)@sha256:874da5701a98e352fa28d88470671eb792a472737a3cf2b7ce9966817e962de8
images_arm64 += quay.io/jetstack/cert-manager-startupapicheck:$(cert_manager_version)@sha256:35d35b325b980cc702324e52b443cc7eb1df7211ce4e8e91d96da4eff4b6c894
