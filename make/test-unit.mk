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

.PHONY: test-unit
## Run all unit tests for trust-manager
## @category Testing
test-unit: test-unit-standard test-unit-negativeserial


.PHONY: test-unit-standard
test-unit-standard: | $(NEEDS_GOTESTSUM) $(ARTIFACTS)
## Standard unit tests. These tests are in contrast to test-unit-negativeserial,
## and do not set the x509negativeserial GODEBUG value.
## We're testing against a "standard" configuration of trust-manager.
## @category Testing
	$(GOTESTSUM) \
		--junitfile=$(ARTIFACTS)/junit-go-e2e.xml \
		-- \
		-coverprofile=$(ARTIFACTS)/filtered.cov \
		./cmd/... ./pkg/... \
		-- \
		-ldflags $(go_manager_ldflags) \
		-test.timeout 2m

.PHONY: test-unit-negativeserial
## Specialised unit tests which set the x509negativeserial GODEBUG value
## so we can test our handling of a special case introduced in Go 1.23.
## See ./pkg/compat for details
## @category Testing
test-unit-negativeserial: | $(NEEDS_GOTESTSUM) $(ARTIFACTS)
	$(GOTESTSUM) \
		--junitfile=$(ARTIFACTS)/junit-go-unit-negativeserial.xml \
		-- \
		-tags=testnegativeserialon \
		./pkg/compat/... \
		-- \
		-ldflags $(go_manager_ldflags) \
		-test.timeout 2m
