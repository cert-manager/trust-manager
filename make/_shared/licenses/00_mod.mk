# Copyright 2024 The cert-manager Authors.
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

# Utility variables
current_makefile := $(lastword $(MAKEFILE_LIST))
current_makefile_directory := $(dir $(current_makefile))

# Define default config for generating licenses
license_ignore ?=
license_template_file ?=

define license_defaults
license_layer_path_$1 := $(abspath $(bin_dir)/scratch/licenses-$(VERSION))
endef

$(foreach build_name,$(build_names),$(eval $(call license_defaults,$(build_name))))

# Calculate all the go.mod directories, build targets may share go.mod dirs so
# we use $(sort) to de-duplicate.
go_mod_dirs := $(sort $(foreach build_name,$(build_names),$(go_$(build_name)_mod_dir)))
generate_go_licenses_targets := $(addsuffix /LICENSES,$(go_mod_dirs:/=))

.PHONY: $(generate_go_licenses_targets)
$(generate_go_licenses_targets): | $$(NEEDS_GO-LICENSES)
	cd $(dir $@) && GOOS=linux GOARCH=amd64 $(GO-LICENSES) report --ignore "$(license_ignore)" ./... > LICENSES

## Generate licenses for the golang dependencies
## @category [shared] Generate/Verify
generate-go-licences: $(generate_go_licenses_targets)
shared_generate_targets += generate-go-licences

# Target to generate image layer containing license information
.PHONY: oci-license-layer-%
oci-license-layer-%: | $(bin_dir)/scratch $$(NEEDS_GO-LICENSES)
	rm -rf $(license_layer_path_$*)
	mkdir -p $(license_layer_path_$*)/licenses
	cd $(go_$*_mod_dir) && GOOS=linux GOARCH=amd64 $(GO-LICENSES) report --ignore "$(license_ignore)" $(addprefix --template=,$(license_template_file)) $(go_$*_main_dir) > $(license_layer_path_$*)/licenses/LICENCES

# Add the license layer to every image
define licences_layer_dependencies
oci-build-$1: oci-license-layer-$1
oci_$1_additional_layers += $(license_layer_path_$1)
endef
$(foreach build_name,$(build_names),$(eval $(call licences_layer_dependencies,$(build_name))))
