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

ifndef go_header_file
$(error go_header_file is not set)
endif

################
# Add targets #
################

.PHONY: generate-deepcopy
## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
## @category [shared] Generate/ Verify
generate-deepcopy: | $(NEEDS_CONTROLLER-GEN)
	$(eval directories := $(shell ls -d */ | grep -v '_bin' | grep -v 'make'))
	$(CONTROLLER-GEN) object:headerFile=$(go_header_file) $(directories:%=paths=./%...)

shared_generate_targets += generate-deepcopy
