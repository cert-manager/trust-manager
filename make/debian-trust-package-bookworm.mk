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

package_name_bookworm := cert-manager-debian-bookworm

debian_package_bookworm_layer := $(bin_dir)/scratch/debian-trust-package-bookworm
debian_package_bookworm_json := $(debian_package_bookworm_layer)/debian-package/cert-manager-package-debian.json

$(debian_package_bookworm_layer)/debian-package:
	mkdir -p $@

$(debian_package_bookworm_json): | $(bin_dir)/bin/validate-trust-package $(debian_package_bookworm_layer)/debian-package
	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh exact $(DEBIAN_BUNDLE_BOOKWORM_SOURCE_IMAGE) $@ $(DEBIAN_BUNDLE_BOOKWORM_VERSION) $(package_name_bookworm)

oci-build-package_debian_bookworm: $(debian_package_bookworm_json)
oci_additional_layers_package_debian_bookworm += $(debian_package_bookworm_layer)

# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif

.PHONY: upgrade-debian-trust-package-bookworm-version
upgrade-debian-trust-package-bookworm-version: | $(bin_dir)/bin/validate-trust-package $(bin_dir)/scratch
	$(eval temp_out := $(bin_dir)/scratch/debian-trust-package-bookworm.temp.json)
	rm -rf $(temp_out)

	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh latest $(DEBIAN_BUNDLE_BOOKWORM_SOURCE_IMAGE) $(temp_out) $(DEBIAN_BUNDLE_BOOKWORM_VERSION) $(package_name_bookworm)

	latest_version=$$(jq -r '.version' $(temp_out)); \
		$(sed_inplace) "s/DEBIAN_BUNDLE_BOOKWORM_VERSION := .*/DEBIAN_BUNDLE_BOOKWORM_VERSION := $$latest_version/" make/00_debian_bookworm_version.mk
