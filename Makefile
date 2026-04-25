TA_FILE?=qsee_nongp/tas/engmode.elf
ROOTFS_DIR:=emulator/rootfs
DOCKER_ROOT:=/srv
ARGS?=
help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build run
build: ## build the docker image
	docker compose build emulator

_ROOTFS_TA_FILE:=$(ROOTFS_DIR)/$(notdir $(TA_FILE))
_ROOTFS_YML_FILE:=$(basename $(_ROOTFS_TA_FILE)).yml
_ROOTFS_SYM_FILE:=$(basename $(_ROOTFS_TA_FILE)).sym-elf

.PHONY: copy-files run-bash run-gdb symbol-file

copy-files: $(_ROOTFS_TA_FILE) $(_ROOTFS_YML_FILE)
$(_ROOTFS_TA_FILE): $(TA_FILE)
	sudo mkdir -p $(ROOTFS_DIR)
	sudo cp $< $@

$(_ROOTFS_YML_FILE): $(basename $(TA_FILE)).yml
	sudo mkdir -p $(ROOTFS_DIR)
	sudo cp $< $@

run-bash: copy-files ## run emulator, but drops into bash shell.
	docker compose run -it --rm \
		--name emu emulator \
		bash

run-interactive: copy-files ## emulate the TA. Respecets ARGS.
	docker compose run -it --rm \
		--name emu emulator \
		python3 -m emulate $(DOCKER_ROOT)/$(_ROOTFS_TA_FILE) $(ARGS)

interactive-client:
	docker compose exec -it emulator python3 -m emulate.non_gp.qsee.dummy_client

exec-bash:
	docker compose exec -it emulator bash

exec-gdb: copy-files ## connect to the gdb server. Needs a running emulator container.
	docker compose exec -it emulator gdb-multiarch \
		-ex 'set sysroot $(DOCKER_ROOT)/$(ROOTFS_DIR)' \
		-ex 'set history filename /srv/.gdb_history' \
		-ex 'add-symbol-file $(DOCKER_ROOT)/$(_ROOTFS_SYM_FILE) 0x555555554000' \
		-iex 'target remote localhost:9999' \
		$(DOCKER_ROOT)/$(_ROOTFS_TA_FILE) 

.PHONY: exec-gdb-sym exec-gdb symbol-file
exec-gdb-sym: symbol-file exec-gdb

symbol-file: $(_ROOTFS_SYM_FILE)
$(_ROOTFS_SYM_FILE): $(_ROOTFS_TA_FILE) $(_ROOTFS_YML_FILE)
	docker compose run -it --rm \
		--name sym-build \
		emulator python3 scripts/extract_symbols.py $(DOCKER_ROOT)/$(_ROOTFS_TA_FILE) --output $(DOCKER_ROOT)/$@

