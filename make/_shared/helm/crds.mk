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

################
# Check Inputs #
################

ifndef helm_chart_source_dir
$(error helm_chart_source_dir is not set)
endif

ifndef helm_labels_template_name
$(error helm_labels_template_name is not set)
endif

################
# Add targets #
################

crd_template_header := $(dir $(lastword $(MAKEFILE_LIST)))/crd.template.header.yaml
crd_template_footer := $(dir $(lastword $(MAKEFILE_LIST)))/crd.template.footer.yaml

# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif

crds_dir ?= deploy/crds
crds_dir_readme := $(dir $(lastword $(MAKEFILE_LIST)))/crds_dir.README.md

$(crds_dir):
	mkdir -p $@

$(crds_dir)/README.md: $(crds_dir_readme) | $(crds_dir)
	cp $< $@

.PHONY: generate-crds
## Generate CRD manifests.
## @category [shared] Generate/ Verify
generate-crds: | $(NEEDS_CONTROLLER-GEN) $(NEEDS_YQ)
	$(eval directories := $(shell ls -d */ | grep -v -e 'make' $(shell git check-ignore -- * | sed 's/^/-e /')))

	$(CONTROLLER-GEN) crd \
		$(directories:%=paths=./%...) \
		output:crd:artifacts:config=$(crds_dir)

	echo "Updating CRDs with helm templating, writing to $(helm_chart_source_dir)/templates"

	@for i in $$(basename $(crds_dir)/*.yaml); do \
		crd_name=$$($(YQ) eval '.metadata.name' $(crds_dir)/$$i); \
		cat $(crd_template_header) > $(helm_chart_source_dir)/templates/crd-$$i; \
		echo "" >> $(helm_chart_source_dir)/templates/crd-$$i; \
		$(sed_inplace) "s/REPLACE_CRD_NAME/$$crd_name/g" $(helm_chart_source_dir)/templates/crd-$$i; \
		$(sed_inplace) "s/REPLACE_LABELS_TEMPLATE/$(helm_labels_template_name)/g" $(helm_chart_source_dir)/templates/crd-$$i; \
		$(YQ) -I2 '{"spec": .spec}' $(crds_dir)/$$i >> $(helm_chart_source_dir)/templates/crd-$$i; \
		cat $(crd_template_footer) >> $(helm_chart_source_dir)/templates/crd-$$i; \
	done

shared_generate_targets += generate-crds
