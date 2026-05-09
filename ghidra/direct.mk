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

TEE := qsee_nongp
TA_DIR := ../qsee_nongp/tas
BBS_DIR := $(TA_DIR)/bbs

TARGET ?= $(TA_DIR)/engmode.elf
TARGET_ELF := $(TA_DIR)/$(notdir $(TARGET))

IGNORED_NAME_PARTS := template patched nopauth
file_stem = $(basename $(notdir $(1)))
ignored_file = $(strip $(foreach part,$(IGNORED_NAME_PARTS),$(findstring $(part),$(call file_stem,$(1)))))
filter_ignored_files = $(strip $(foreach file,$(1),$(if $(call ignored_file,$(file)),,$(file))))

elf_to_json = $(TA_DIR)/$(call file_stem,$(1)).json
elf_to_import_stamp = $(STAMPS)/$(call file_stem,$(1)).imported.stamp
elf_to_analysis_stamp = $(STAMPS)/$(call file_stem,$(1)).analyzed.stamp
metadata_to_elf = $(TA_DIR)/$(call file_stem,$(1)).elf
metadata_to_bb_json = $(BBS_DIR)/bb_$(call file_stem,$(1)).elf.json

YML_FILES := $(call filter_ignored_files,$(wildcard $(TA_DIR)/*.yml))
JSON_FILES := $(call filter_ignored_files,$(wildcard $(TA_DIR)/*.json))
BUILDABLE_YML_FILES := $(foreach yml_file,$(YML_FILES),$(if $(wildcard $(call metadata_to_elf,$(yml_file))),$(yml_file)))
METADATA_FILES := $(sort $(BUILDABLE_YML_FILES) $(JSON_FILES))
BB_JSON_FILES := $(foreach metadata_file,$(METADATA_FILES),$(call metadata_to_bb_json,$(metadata_file)))
ELF_FILES := $(call filter_ignored_files,$(wildcard $(TA_DIR)/*.elf))
ELF_JSON_FILES := $(foreach elf_file,$(ELF_FILES),$(call elf_to_json,$(elf_file)))
ELF_IMPORT_STAMPS := $(foreach elf_file,$(ELF_FILES),$(call elf_to_import_stamp,$(elf_file)))
ELF_ANALYSIS_STAMPS := $(foreach elf_file,$(ELF_FILES),$(call elf_to_analysis_stamp,$(elf_file)))
TARGET_JSON := $(call elf_to_json,$(TARGET_ELF))
TARGET_IMPORT_STAMP := $(call elf_to_import_stamp,$(TARGET_ELF))
TARGET_ANALYSIS_STAMP := $(call elf_to_analysis_stamp,$(TARGET_ELF))
TARGET_BB_JSON := $(call metadata_to_bb_json,$(TARGET_JSON))

.PHONY: help qsee-nongp-import-one qsee-nongp-import-all qsee-nongp-analyze-one qsee-nongp-analyze-all qsee-nongp-one qsee-nongp-all qsee-nongp-json

.SECONDARY: $(ELF_JSON_FILES) $(TARGET_JSON) $(ELF_IMPORT_STAMPS) $(TARGET_IMPORT_STAMP) $(ELF_ANALYSIS_STAMPS) $(TARGET_ANALYSIS_STAMP)

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
$(STAMPS)/%.imported.stamp: $(TA_DIR)/%.elf own-project
	@mkdir -p "$(STAMPS)"
	@sudo mkdir -p "$(PROJECTS_HOST_DIR)"
	@$(GHIDRA_SCRIPT) \
		-import "/qsee_nongp_tas/$(notdir $<)" \
		-noanalysis
	@touch "$@"

$(STAMPS)/%.analyzed.stamp: $(TA_DIR)/%.elf $(STAMPS)/%.imported.stamp own-project
	@$(GHIDRA_SCRIPT) \
		-process "$(notdir $<)"
	@touch "$@"

# Re-run only the coverage export against the already imported project.
$(BBS_DIR)/bb_%.elf.json: $(TA_DIR)/%.json $(STAMPS)/%.imported.stamp own-project
	@mkdir -p "$(BBS_DIR)"
	@$(GHIDRA_SCRIPT) \
		-process "$(basename $(notdir $<)).elf" \
	    -noanalysis \
		-postScript coverage_bbs.py \
		++tee $(TEE)

$(TA_DIR)/%.json: $(TA_DIR)/%.elf $(STAMPS)/%.imported.stamp own-project
	@$(GHIDRA_SCRIPT) \
		-process "$(notdir $<)" \
		-noanalysis \
		-postScript qsee_nongp_funcs.py


qsee-nongp-import-one: $(TARGET_IMPORT_STAMP) ## Import one qsee_nongp ELF without auto-analysis
qsee-nongp-import-all: $(ELF_IMPORT_STAMPS) ## Import every qsee_nongp ELF without auto-analysis

qsee-nongp-analyze-one: $(TARGET_ANALYSIS_STAMP) ## Analyze one previously imported qsee_nongp ELF
qsee-nongp-analyze-all: $(ELF_ANALYSIS_STAMPS) ## Analyze every previously imported qsee_nongp ELF

qsee-nongp-json: $(TARGET_JSON) ## Build one qsee_nongp function metadata JSON
qsee-nongp-one: $(TARGET_BB_JSON) ## Build one BB export using persistent Ghidra projects
qsee-nongp-all: $(BB_JSON_FILES) ## Build BB exports for every qsee_nongp target with metadata
