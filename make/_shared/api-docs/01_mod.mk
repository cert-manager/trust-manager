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

ifndef repo_name
$(error repo_name is not set)
endif

ifndef api_docs_outfile
$(error api_docs_outfile is not set)
endif

ifndef api_docs_package
$(error api_docs_package is not set)
endif

ifndef api_docs_branch
$(error api_docs_branch is not set)
endif

##########################################

GOMARKDOC_FLAGS=--format github --repository.url "https://$(repo_name)" --repository.default-branch $(api_docs_branch) --repository.path /

.PHONY: generate-api-docs
## Generate API docs for the API types.
## @category [shared] Generate/ Verify
generate-api-docs: | $(NEEDS_GOMARKDOC)
	$(GOMARKDOC) \
		$(GOMARKDOC_FLAGS) \
		--output $(api_docs_outfile) \
		$(api_docs_package)

.PHONY: verify-generate-api-docs
## Verify that the API docs are up to date.
## @category [shared] Generate/ Verify
verify-generate-api-docs: | $(NEEDS_GOMARKDOC)
	$(GOMARKDOC) \
		--check \
		$(GOMARKDOC_FLAGS) \
		--output $(api_docs_outfile) \
		$(api_docs_package) \
		|| (echo "docs are not up to date; run 'make generate' and commit the result" && exit 1)

shared_generate_targets += generate-api-docs
