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

define build_trust_manager
	docker buildx build --builder $(BUILDX_BUILDER) \
		--platform=$(3) \
		-t $(CONTAINER_REGISTRY)/trust-manager:$(2) \
		--build-arg GOPROXY=$(GOPROXY) \
		--output $(1) \
		-f ./Dockerfile \
		.
endef

.PHONY: trust-manager-save
trust-manager-save:
	$(call build_trust_manager,type=local$(_COMMA)dest=$(BINDIR)/trust-manager,$(RELEASE_VERSION),$(IMAGE_PLATFORMS))

.PHONY: trust-manager-load
trust-manager-load:
	$(call build_trust_manager,type=docker,latest,linux/$(ARCH))

.PHONY: trust-manager-push
trust-manager-push:
	$(call build_trust_manager,type=registry,$(RELEASE_VERSION),$(IMAGE_PLATFORMS))
