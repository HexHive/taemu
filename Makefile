help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## build the docker image
	./build-docker.sh

run: ## emulate the TA 
	docker run --rm --name emu -it -w /srv\
	  ta_emu ./run.sh

gdb: ## emulate the TA with gdb
	docker run --rm --network host --name emu -it -w /srv\
	  ta_emu ./gdb.sh


