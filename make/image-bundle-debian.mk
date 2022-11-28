DEBIAN_BUNDLE_VERSION ?=
DEBIAN_BUNDLE_SUFFIX ?= .0

define build_image_bundle
	docker buildx build --builder $(BUILDX_BUILDER) \
		--platform=$(3) \
		-t $(CONTAINER_REGISTRY)/cert-manager-bundle-debian:$(2)$(DEBIAN_BUNDLE_SUFFIX) \
		--build-arg EXPECTED_VERSION=$(2) \
		--build-arg VERSION_SUFFIX=$(DEBIAN_BUNDLE_SUFFIX) \
		--output $(1) \
		-f ./bundles/debian/Containerfile \
		./bundles/debian
endef

# can't use a comma in an argument to a make function, so define a variable instead
_COMMA := ,

.PHONY: bundle-debian-save
bundle-debian-save:
ifeq ($(strip $(DEBIAN_BUNDLE_VERSION)),)
	$(error DEBIAN_BUNDLE_VERSION must be set for $@)
endif

	$(call build_image_bundle,type=local$(_COMMA)dest=$(BINDIR)/cert-manager-bundle-debian,$(DEBIAN_BUNDLE_VERSION),$(IMAGE_PLATFORMS))

.PHONY: bundle-debian-load
bundle-debian-load:
	$(call build_image_bundle,type=docker,latest,linux/amd64)

.PHONY: bundle-debian-push
bundle-debian-push:
ifeq ($(strip $(DEBIAN_BUNDLE_VERSION)),)
	$(error DEBIAN_BUNDLE_VERSION must be set for $@)
endif

	$(call build_image_bundle,type=registry,$(DEBIAN_BUNDLE_VERSION),$(IMAGE_PLATFORMS))

.PHONY: ci-update-debian-bundle
ci-update-debian-bundle:
	./hack/update-debian-ca-bundle.sh "$(CONTAINER_REGISTRY)/cert-manager-bundle-debian" $(DEBIAN_BUNDLE_SUFFIX)
