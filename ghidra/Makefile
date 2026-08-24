DOCKER := docker
PYTHON ?= ../.venv/bin/python
# GHIDRA_MAXMEM ?=
# DOCKER_RUN_MEMORY := $(if $(GHIDRA_DOCKER_MEMORY),--memory $(GHIDRA_DOCKER_MEMORY),)

.PHONY: build run help

help: ## Show this help
		@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
		@$(DOCKER) compose build

DOCKER_RUN:=$(DOCKER) compose run --rm tipi 
mitee: ## Run the Docker container(s) mitee
		@$(DOCKER_RUN) /mitee-entrypoint.sh ${TARGET} 

beanpod: ## Run the Docker container(s) beanpod
		@$(DOCKER_RUN) /beanpod-entrypoint.sh ${TARGET} 

teegris: ## Run the Docker container(s) teegris 
		@$(DOCKER_RUN) /teegris-entrypoint.sh ${TARGET} 

optee: ## Run the Docker container(s) teegris 
		@$(DOCKER_RUN) /optee-entrypoint.sh ${TARGET} 

t6: ## Run the Docker container(s) t6
		@$(DOCKER_RUN) /t6-entrypoint.sh ${TARGET} 

.PHONY: qsee_nongp
qsee_nongp: ## Run the Docker container(s) qsee_nongp
		@$(DOCKER_RUN) /qsee-nongp-entrypoint.sh ${TARGET}

bbs: ## Check reachable bbs
		@$(DOCKER_RUN) /bbs-entrypoint.sh ${TARGET} ${TEE}

bbs-manual: ## Check reachable bbs
		@$(DOCKER_RUN) /bbs-manual-entrypoint.sh ${TARGET} ${TEE}


QSEE_NONGP_TAS_DIR := ../qsee_nongp/tas
TARGET_NAME := $(notdir ${TARGET})
TARGET_STEM := $(basename $(TARGET_NAME))
ifeq ($(dir $(TARGET)),./)
QSEE_NONGP_INPUT := $(QSEE_NONGP_TAS_DIR)/$(TARGET_NAME)
else
QSEE_NONGP_INPUT := $(TARGET)
endif
QSEE_NONGP_YML := $(QSEE_NONGP_TAS_DIR)/$(TARGET_STEM).yml
QSEE_NONGP_JSON := $(QSEE_NONGP_TAS_DIR)/$(TARGET_STEM).json
QSEE_NONGP_BB_JSON := $(QSEE_NONGP_TAS_DIR)/bbs/bb_$(TARGET_NAME).json

.PHONY: qsee_nongp-json bbs-qsee_nongp

$(QSEE_NONGP_JSON): $(QSEE_NONGP_YML)
		@$(PYTHON) yaml_to_json.py "$(QSEE_NONGP_YML)" "$(QSEE_NONGP_JSON)"

qsee_nongp-json: $(QSEE_NONGP_JSON) ## Materialize qsee_nongp JSON metadata from YAML for TARGET

$(QSEE_NONGP_BB_JSON): $(QSEE_NONGP_INPUT) $(QSEE_NONGP_JSON)
		@$(DOCKER_RUN) /qsee-nongp-entrypoint.sh $(TARGET_NAME) qsee_nongp

bbs-qsee_nongp: $(QSEE_NONGP_BB_JSON) ## Check reachable bbs
