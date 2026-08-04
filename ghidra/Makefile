DOCKER := docker

.PHONY: build run help

help: ## Show this help
		@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
		@$(DOCKER) compose build

mitee: ## Run the Docker container(s) mitee
		@$(DOCKER) compose run --rm tipi /mitee-entrypoint.sh ${TARGET} 

beanpod: ## Run the Docker container(s) beanpod
		@$(DOCKER) compose run --rm tipi /beanpod-entrypoint.sh ${TARGET} 

teegris: ## Run the Docker container(s) teegris 
		@$(DOCKER) compose run --rm tipi /teegris-entrypoint.sh ${TARGET} 

optee: ## Run the Docker container(s) teegris 
		@$(DOCKER) compose run --rm tipi /optee-entrypoint.sh ${TARGET} 

t6: ## Run the Docker container(s) t6
		@$(DOCKER) compose run --rm tipi /t6-entrypoint.sh ${TARGET} 

bbs: ## Check reachable bbs
		@$(DOCKER) compose run --rm tipi /bbs-entrypoint.sh ${TARGET} ${TEE}

bbs-manual: ## Check reachable bbs
		@$(DOCKER) compose run --rm tipi /bbs-manual-entrypoint.sh ${TARGET} ${TEE}


