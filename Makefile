
TA_FILE:=qsee_nongp/tas/engmode.elf
# We also support full path to the TA file.
YML_FILE:=$(addsuffix .yml, $(basename $(TA_FILE)))
SYM_FILE:=$(addsuffix .sym-elf, $(basename $(TA_FILE)))

ROOTFS_DIR:=emulator/rootfs

DOCKER_ROOT:=/srv
ARGS?=
help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build run
build: ## build the docker image
	docker compose build emulator

.PHONY: copy-files run-bash run-gdb symbol-file

copy-files: $(TA_FILE) $(YML_FILE) $(SYM_FILE)
	@sudo mkdir -p $(ROOTFS_DIR)
	sudo cp $^ $(ROOTFS_DIR)

run-bash: copy-files ## run emulator, but drops into bash shell.
	docker compose run -it --rm \
		--name emu emulator \
		bash

run-interactive: copy-files ## emulate the TA. Respecets ARGS.
	docker compose run -it --rm \
		--name emu emulator \
		python3 -m emulate ./rootfs/$(TA_FILE) $(ARGS)

INTERACTIVE_CLIENT?=emulate.non_gp.qsee.dummy_client
interactive-client:
	docker compose exec -it emulator python3 -m $(INTERACTIVE_CLIENT)

exec-bash:
	docker compose exec -it emulator bash

exec-gdb: copy-files ## connect to the gdb server. Needs a running emulator container.
	docker compose exec -it emulator gdb-multiarch \
		-ex 'set sysroot ./rootfs' \
		-ex 'set history filename /srv/.gdb_history' \
		-ex 'add-symbol-file ./rootfs/$(SYM_FILE) 0x555555554000' \
		-iex 'target remote localhost:9999' \
		./rootfs/$(TA_FILE) 

.PHONY: exec-gdb-sym exec-gdb symbol-file nopauth-file
exec-gdb-sym: symbol-file exec-gdb


DOCKER_RUN:=docker compose run -it --rm \
		--workdir $(DOCKER_ROOT) \
		emulator

# Same container, no TTY: for batch targets that run under make without a
# terminal (docker compose run -it fails with "stdin is not a terminal").
DOCKER_RUN_BATCH:=docker compose run --rm -T \
		--workdir $(DOCKER_ROOT) \
		emulator

json-file: $(addsuffix .json, $(basename $(YML_FILE)))
%.json: %.yml
	$(DOCKER_RUN) python3 emulator/scripts/yaml_to_json.py $< $@

symbol-file: $(SYM_FILE)
%.sym-elf: %.elf %.yml
	$(DOCKER_RUN) python3 emulator/scripts/extract_symbols.py $< --output $@

nopauth-file: $(addsuffix .nopauth.elf, $(basename $(TA_FILE))) $(addsuffix .nopauth.yml, $(basename $(YML_FILE)))

%.nopauth.elf: %.elf
# Fail if we are accidentially re-patching (if source TA_FILE  ends with .nopauth.elf)
ifeq ($(suffix $<),.nopauth.elf)
	$(error $(TA_FILE) ends with .nopauth.elf, won't re-patch)
endif
	$(DOCKER_RUN) python3 emulator/scripts/patch_aarch64_auth.py $< -o $@

%.nopauth.yml: %.yml
	sudo ln -rsf $< $@

.PHONY: test
test: ## run the emulator unit tests in the container
	$(DOCKER_RUN_BATCH) env PYTHONPATH=$(DOCKER_ROOT)/emulator \
		python3 -m pytest emulator/emulate/tests emulator/tests -q

.PHONY: nopauth-all
nopauth-all: ## generate every .nopauth.elf/.yml a harness symlink points at
	@missing=$$(find . -path ./.git -prune -o -type l -print 2>/dev/null \
	    | while read -r l; do [ -e "$$l" ] || \
	          realpath -m --relative-to=. "$$(dirname "$$l")/$$(readlink "$$l")"; done \
	    | sort -u); \
	if [ -z "$$missing" ]; then echo "nothing missing"; exit 0; fi; \
	for t in $$missing; do \
	    case "$$t" in \
	      *.nopauth.elf) src="$${t%.nopauth.elf}.elf"; \
	          [ -e "$$src" ] || { echo "no source for $$t"; exit 1; }; \
	          echo "patching $$src -> $$t"; \
	          $(DOCKER_RUN_BATCH) python3 emulator/scripts/patch_aarch64_auth.py "$$src" -o "$$t" ;; \
	      *.nopauth.yml) src="$${t%.nopauth.yml}.yml"; \
	          [ -e "$$src" ] || { echo "no source for $$t"; exit 1; }; \
	          echo "linking $$src -> $$t"; ln -rsf "$$src" "$$t" ;; \
	      *) echo "unresolved symlink target: $$t"; exit 1 ;; \
	    esac; \
	done
