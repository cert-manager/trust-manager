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
