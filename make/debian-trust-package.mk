# Copyright 2025 The cert-manager Authors.
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

# Define targets for a Debian trust package distribution.
#
# $(1) = distro codename in lowercase (e.g., bullseye, bookworm)
# $(2) = distro variable prefix in UPPERCASE (e.g., BULLSEYE, BOOKWORM)
#
# Relies on the following variables being set before this macro is evaluated:
#   DEBIAN_$(2)_BUNDLE_VERSION
#   DEBIAN_$(2)_BUNDLE_SOURCE_IMAGE
#   debian_$(1)_package_layer
#   oci_package_debian_$(1)_image_name
#   oci_package_debian_$(1)_image_tag
#   debian_$(1)_tag_filter  (optional: pipe filter command inserted before "sort -V", e.g. "grep -v bad-tag |"; empty means no filtering)
define debian-trust-package-targets

package_name_$(1) := cert-manager-debian-$(1)

debian_$(1)_package_json := $$(debian_$(1)_package_layer)/debian-package/cert-manager-package-debian.json

$$(debian_$(1)_package_layer)/debian-package:
	mkdir -p $$@

$$(debian_$(1)_package_json): | $$(bin_dir)/bin/validate-trust-package $$(debian_$(1)_package_layer)/debian-package
	BIN_VALIDATE_TRUST_PACKAGE=$$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh $$(DEBIAN_$(2)_BUNDLE_SOURCE_IMAGE) $$@ $$(DEBIAN_$(2)_BUNDLE_VERSION) $$(package_name_$(1))

# Make sure to build the package json file when building the OCI image.
# This will ensure that the $$(debian_$(1)_package_layer) folder has the desired contents.
oci-build-package_debian_$(1): $$(debian_$(1)_package_json)
oci-build-package_debian_$(1)__local: $$(debian_$(1)_package_json)

.PHONY: scan-debian-$(1)-trust-package
## Scan the latest Debian $(1) trust package OCI image with Trivy
## @category [shared] Release
scan-debian-$(1)-trust-package: | $$(NEEDS_TRIVY) $$(NEEDS_CRANE)
	$$(eval latest_$(1)_tag := $$(shell $$(CRANE) ls --omit-digest-tags $$(oci_package_debian_$(1)_image_name) | $$(debian_$(1)_tag_filter) sort -V | tail -n1))
	@echo "Scanning latest Debian $(1) trust package: $$(oci_package_debian_$(1)_image_name):$$(latest_$(1)_tag)"
	$$(TRIVY) image --exit-code 1 $$(oci_package_debian_$(1)_image_name):$$(latest_$(1)_tag)

.PHONY: release-debian-$(1)-trust-package
## Release the Debian $(1) trust package OCI image
## @category [shared] Release
release-debian-$(1)-trust-package: | $$(NEEDS_CRANE)
	$$(MAKE) oci-maybe-push-package_debian_$(1)

	@echo "RELEASE_OCI_PACKAGE_DEBIAN_$(2)_IMAGE=$$(oci_package_debian_$(1)_image_name)" >> "$$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_PACKAGE_DEBIAN_$(2)_TAG=$$(oci_package_debian_$(1)_image_tag)" >> "$$(GITHUB_OUTPUT)"

	@echo "Release complete!"

endef

$(eval $(call debian-trust-package-targets,bullseye,BULLSEYE))
$(eval $(call debian-trust-package-targets,bookworm,BOOKWORM))
