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

ifeq ($(strip $(CI)),)
	_RED=\033[0;31m
	_END=\033[0m
else
	_RED=
	_END=
endif

# Other colors:
# green="\033[0;32m"
# yel="\033[0;33m"
# cyan="\033[0;36m"
# bold="\033[0;37m"
# gray="\033[0;90m"
