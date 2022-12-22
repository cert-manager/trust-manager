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
	$(call build_trust_manager,type=docker,latest,linux/amd64)

.PHONY: trust-manager-push
trust-manager-push:
	$(call build_trust_manager,type=registry,$(RELEASE_VERSION),$(IMAGE_PLATFORMS))
