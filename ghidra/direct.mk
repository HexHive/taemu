DOCKER := docker
PYTHON ?= ../.venv/bin/python
JAVA_TOOL_OPTIONS ?=
GHIDRA_DIRECT_JAVA_TOOL_OPTIONS := $(strip $(JAVA_TOOL_OPTIONS) -Dlog4j2.disableJmx=true -XX:-UseContainerSupport)
DOCKER_RUN := $(DOCKER) compose run --rm -e JAVA_TOOL_OPTIONS="$(GHIDRA_DIRECT_JAVA_TOOL_OPTIONS)" tipi

# Persist imported/analyzed Ghidra projects on the host instead of recreating
# /tmp/ghidraproj inside the container for every run.
PROJECTS_HOST_DIR := ../.ghidra-projects/qsee_nongp
STAMPS := $(PROJECTS_HOST_DIR)/stamps
PROJECTS_CONT_DIR := /mnt/.ghidra-projects/qsee_nongp
PROJECT_NAME := GhidraProject

TARGET ?= ../qsee_nongp/tas/engmode.elf
TARGET_NAME := $(notdir $(TARGET))
TARGET_STEM := $(basename $(TARGET_NAME))

TEE := qsee_nongp
TA_DIR := $(dir $(TARGET))
BBS_DIR := $(TA_DIR)/bbs

IGNORED_NAME_PARTS := template patched nopauth
ignored_stem = $(strip $(foreach part,$(IGNORED_NAME_PARTS),$(findstring $(part),$(1))))
filter_ignored_stems = $(strip $(foreach stem,$(1),$(if $(call ignored_stem,$(stem)),,$(stem))))

YML_STEMS := $(call filter_ignored_stems,$(basename $(notdir $(wildcard $(TA_DIR)/*.yml))))
JSON_STEMS := $(call filter_ignored_stems,$(basename $(notdir $(wildcard $(TA_DIR)/*.json))))
NON_GP_STEMS := $(sort $(YML_STEMS) $(JSON_STEMS))
NON_GP_BBS := $(foreach stem,$(NON_GP_STEMS),$(BBS_DIR)/bb_$(stem).elf.json)
ELF_STEMS := $(call filter_ignored_stems,$(basename $(notdir $(wildcard $(TA_DIR)/*.elf))))
ELF_IMPORTS := $(foreach stem,$(ELF_STEMS),$(PROJECTS_HOST_DIR)/$(stem).imported.stamp)
GENERATED_TA_JSONS := $(foreach stem,$(ELF_STEMS),$(TA_DIR)/$(stem).json)

.PHONY: help qsee-nongp-import-one qsee-nongp-import-all qsee-nongp-analyze-one qsee-nongp-analyze-all qsee-nongp-one qsee-nongp-all qsee-nongp-json

.SECONDARY: $(GENERATED_TA_JSONS)

help:
	@grep -E -h '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*## "}; {printf "\033[36m%-24s\033[0m %s\n", $$1, $$2}'

.PHONY: own-project
own-project:
		@sed -i -E 's|(<STATE NAME="OWNER" TYPE="string" VALUE=")[^"]*(" />)|\1root\2|' $(PROJECTS_HOST_DIR)/$(PROJECT_NAME).rep/project.prp

GHIDRA_SCRIPT := timeout --foreground 10m \
		$(DOCKER_RUN) \
		/ghidra/support/analyzeHeadless \
		"$(PROJECTS_CONT_DIR)" \
		"$(PROJECT_NAME)" \
		-scriptPath /src/ghidra_scripts/

# Import the ELF into a persistent Ghidra project without running auto-analysis.
# This leaves the imported programs ready for manual review in Ghidra.
$(STAMPS)/%.imported.stamp: $(TA_DIR)/%.elf
	@mkdir -p "$(STAMPS)"
	@sudo mkdir -p $(PROJECTS_HOST_DIR)
	$(GHIDRA_SCRIPT) \
		-import "/qsee_nongp_tas/$*.elf" \
		-noanalysis
	@touch "$@"

# Re-run only the coverage export against the already imported project.
$(BBS_DIR)/bb_%.elf.json: $(TA_DIR)/%.json # $(STAMPS)/%.imported.stamp 
	@mkdir -p "$(BBS_DIR)"
	$(GHIDRA_SCRIPT) \
		-process "$*.elf" \
	    -noanalysis \
		-postScript coverage_bbs.py \
		++tee $(TEE)

$(TA_DIR)/%.json: $(TA_DIR)/%.elf # $(STAMPS)/%.imported.stamp 
	$(GHIDRA_SCRIPT) \
		-process "$*.elf" \
		-noanalysis \
		-postScript qsee_nongp_funcs.py


qsee-nongp-import-one: $(PROJECTS_HOST_DIR)/$(TARGET_STEM).imported.stamp ## Import one qsee_nongp ELF without auto-analysis
qsee-nongp-import-all: $(ELF_IMPORTS) ## Import every qsee_nongp ELF without auto-analysis

qsee-nongp-one: $(BBS_DIR)/bb_$(TARGET_STEM).elf.json ## Build one BB export using persistent Ghidra projects
qsee-nongp-all: $(NON_GP_BBS) ## Build BB exports for every qsee_nongp target with metadata
