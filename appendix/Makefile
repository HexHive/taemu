# Get all `*.tex` files from sub dirs. Add these files as build dependency
# to trigger the target to rebuild when they change.
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PATH))
TARGET_TEXS=$(shell find $(MKFILE_DIR) -mindepth 1 -type f -name '*.tex')

PAPER=paper

DOCKER ?= sudo docker

.PHONY: all clean

all: ${PAPER}.pdf

${PAPER}.pdf: ${PAPER}.tex bibliography.bib ${TARGET_TEXS}
	rubber --unsafe --synctex --pdf ${PAPER}.tex

docker:  ## Build the PDF in Docker to avoid outdated/missing packages
	@$(DOCKER) run --rm -it -v $$(pwd):/mnt --platform=linux danteev/texlive:latest \
		bash -c "cd /mnt; latexmk -pdf -latexoption=-shell-escape $(PAPER).tex; chown -R $$(id -u):$$(id -g) ."

clean:
	rubber --clean --pdf $(PAPER).tex
	rubber --clean --pdf diff.tex
	$(RM) *.fls *.fb_latexmk *.blg *.log *.out *.aux 
	$(RM) -rf _minted-paper
