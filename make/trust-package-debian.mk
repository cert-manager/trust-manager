DEBIAN_TRUST_PACKAGE_VERSION ?=
DEBIAN_TRUST_PACKAGE_SUFFIX ?= .0

define build_debian_trust_package
	docker buildx build --builder $(BUILDX_BUILDER) \
		--platform=$(3) \
		-t $(CONTAINER_REGISTRY)/cert-manager-package-debian:$(2)$(DEBIAN_TRUST_PACKAGE_SUFFIX) \
		--build-arg GOPROXY=$(GOPROXY) \
		--build-arg EXPECTED_VERSION=$(2) \
		--build-arg VERSION_SUFFIX=$(DEBIAN_TRUST_PACKAGE_SUFFIX) \
		--output $(1) \
		-f ./trust-packages/debian/Containerfile \
		./trust-packages/debian
endef

# can't use a comma in an argument to a make function, so define a variable instead
_COMMA := ,

.PHONY: trust-package-debian-save
trust-package-debian-save:
ifeq ($(strip $(DEBIAN_TRUST_PACKAGE_VERSION)),)
	$(error DEBIAN_TRUST_PACKAGE_VERSION must be set for $@)
endif

	$(call build_debian_trust_package,type=local$(_COMMA)dest=$(BINDIR)/cert-manager-package-debian,$(DEBIAN_TRUST_PACKAGE_VERSION),$(IMAGE_PLATFORMS))

.PHONY: trust-package-debian-load
trust-package-debian-load:
	$(call build_debian_trust_package,type=docker,latest,linux/amd64)

.PHONY: trust-package-debian-push
trust-package-debian-push:
ifeq ($(strip $(DEBIAN_TRUST_PACKAGE_VERSION)),)
	$(error DEBIAN_TRUST_PACKAGE_VERSION must be set for $@)
endif

	$(call build_debian_trust_package,type=registry,$(DEBIAN_TRUST_PACKAGE_VERSION),$(IMAGE_PLATFORMS))

.PHONY: ci-update-debian-trust-package
ci-update-debian-trust-package:
	./hack/update-debian-trust-package.sh "$(CONTAINER_REGISTRY)/cert-manager-package-debian" $(DEBIAN_BUNDLE_SUFFIX)
