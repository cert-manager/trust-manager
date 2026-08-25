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

# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif

# Usage: $(call debian-trust-package-targets,<RELEASE>,<release>)
# e.g.   $(call debian-trust-package-targets,BOOKWORM,bookworm)
define debian-trust-package-targets

debian_$(2)_package_json := $$(debian_$(2)_package_layer)/debian-package/cert-manager-package-debian.json

$$(debian_$(2)_package_layer)/debian-package:
	mkdir -p $$@

$$(debian_$(2)_package_json): | $$(bin_dir)/bin/validate-trust-package $$(debian_$(2)_package_layer)/debian-package
	BIN_VALIDATE_TRUST_PACKAGE=$$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh exact $$(DEBIAN_$(1)_BUNDLE_SOURCE_IMAGE) $$@ $$(DEBIAN_$(1)_BUNDLE_VERSION) cert-manager-debian-$(2)

# Make sure to build the package json file when building
# the OCI image. This will ensure that the package layer
# folder has the desired contents.
oci-build-package_debian_$(2): $$(debian_$(2)_package_json)
oci-build-package_debian_$(2)__local: $$(debian_$(2)_package_json)

.PHONY: upgrade-debian-$(2)-trust-package-version
upgrade-debian-$(2)-trust-package-version: | $$(bin_dir)/bin/validate-trust-package $$(bin_dir)/scratch
	$$(eval temp_out := $$(bin_dir)/scratch/debian-$(2)-trust-package.temp.json)
	rm -rf $$(temp_out)
	BIN_VALIDATE_TRUST_PACKAGE=$$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh latest $$(DEBIAN_$(1)_BUNDLE_SOURCE_IMAGE) $$(temp_out) $$(DEBIAN_$(1)_BUNDLE_VERSION) cert-manager-debian-$(2)
	latest_version=$$$$(jq -r '.version' $$(temp_out)); \
		$(sed_inplace) "s/DEBIAN_$(1)_BUNDLE_VERSION := .*/DEBIAN_$(1)_BUNDLE_VERSION := $$$$latest_version/" make/00_debian_$(2)_version.mk

.PHONY: _scan-debian-$(2)-trust-package
_scan-debian-$(2)-trust-package: | $$(NEEDS_TRIVY) $$(NEEDS_CRANE)
	@# Our first trust package based on Debian Bookworm was historically published with the tag "20230311.0".
	@# We explicitly exclude the tag "20230311.0" here because it breaks version comparisons with "sort -V" and compares as newer than the other tags.
	@# Even with that tag excluded, this is brittle; the current format used for the tag doesn't allow us to easily
	@# answer the question "which tag is latest" without more custom logic. For now, this works but for future trust packages it might be worth considering our own version format.
	$$(eval latest_$(2)_tag := $$(shell $$(CRANE) ls --omit-digest-tags $$(oci_package_debian_$(2)_image_name) | grep -v "20230311.0" | sort -V | tail -n1))
	@echo "Scanning latest Debian $(1) trust package: $$(oci_package_debian_$(2)_image_name):$$(latest_$(2)_tag)"
	$$(TRIVY) image --exit-code 1 $$(oci_package_debian_$(2)_image_name):$$(latest_$(2)_tag)

endef

$(eval $(call debian-trust-package-targets,BULLSEYE,bullseye))
$(eval $(call debian-trust-package-targets,BOOKWORM,bookworm))
$(eval $(call debian-trust-package-targets,TRIXIE,trixie))

## Scan the latest Debian Bullseye trust package OCI image with Trivy
## @category [shared] Release
.PHONY: scan-debian-bullseye-trust-package
scan-debian-bullseye-trust-package: _scan-debian-bullseye-trust-package

## Scan the latest Debian Bookworm trust package OCI image with Trivy
## @category [shared] Release
.PHONY: scan-debian-bookworm-trust-package
scan-debian-bookworm-trust-package: _scan-debian-bookworm-trust-package

## Scan the latest Debian Trixie trust package OCI image with Trivy
## @category [shared] Release
.PHONY: scan-debian-trixie-trust-package
scan-debian-trixie-trust-package: _scan-debian-trixie-trust-package
