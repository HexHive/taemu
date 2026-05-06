# syntax=docker/dockerfile:latest
ARG UBUNTU_VERSION=jammy

ARG GHIDRA_VERSION=12.0.3_PUBLIC
ARG GHIDRA_SHA=90d3fffb20b00030dcef8d2a24dd0f422d3a61e432b3ad43f77233ac6d667981
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.3_build/ghidra_12.0.3_PUBLIC_20260210.zip

ARG GHIDRATHON_SHA=8be498cc42c938bd2f0db92fb95b90adc47dc2a2868b93b1d7b9791b6ab7dcbe
ARG GHIDRATHON_URL=https://codeload.github.com/mandiant/Ghidrathon/zip/refs/tags/v3.0.1

ARG MCLF_LOADER_URL=https://codeload.github.com/0ddc0de/mclf-ghidra-loader/zip/refs/heads/master

################################################################################
# Download and decompress ghidra(thon) for use in the final ghidrathon image   #
################################################################################
FROM alpine:latest as ghidra-ghidrathon-downloader
ARG GHIDRA_VERSION
ARG GHIDRA_SHA
ARG GHIDRA_URL
ARG GHIDRATHON_SHA
ARG GHIDRATHON_URL
ARG MCLF_LOADER_URL

# Download and decompress ghidra because ADD cannot (yet) do both at once
ADD --link $GHIDRA_URL /ghidra.zip

RUN echo "$GHIDRA_SHA  /ghidra.zip" | sha256sum -c - && \
    unzip /ghidra.zip && \
    mv ghidra_${GHIDRA_VERSION} /ghidra && \
    chmod +x /ghidra/ghidraRun

# Download and decompress ghidrathon because ADD cannot (yet) do both at once
# ADD --link $GHIDRATHON_URL /ghidrathon.tar.gz
ADD --link $GHIDRATHON_URL /ghidrathon.zip

ADD --link $MCLF_LOADER_URL /mclf_loader.zip

# RUN echo "$GHIDRATHON_SHA  /ghidrathon.tar.gz" | sha256sum -c - && \
#     tar -xzf /ghidrathon.tar.gz && \
#     mv Ghidrathon* /ghidrathon

RUN unzip ghidrathon.zip && \
    mv Ghidrathon* /ghidrathon

RUN unzip mclf_loader.zip && \
    mv mclf-ghidra-loader-* /mclf-loader

################################################################################
# Ghidrathon image                                                             #
################################################################################
FROM ubuntu:$UBUNTU_VERSION as ghidrathon
ARG GHIDRA_VERSION

# Enable APT package caching
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Install prerequisites
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        vim \
        wget \
        unzip \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-dev \
        python3-requests  \
        python3-ipdb \
        python3-ipython \
        python3-pip \
        python-is-python3 \
        openjdk-18-jdk-headless \
        apt-transport-https \
        software-properties-common \
        gcc-arm-linux-gnueabi \
        gcc-aarch64-linux-gnu \
        graphviz \
        graphviz-dev \
        gpg-agent \
        dirmngr && \
    add-apt-repository -y ppa:cwchien/gradle && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        gradle

# Install Python dependencies
RUN --mount=type=bind,source=docker/ghidra/requirements.txt,target=/requirements.txt \
    --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip3 install -r /requirements.txt

# Add ghidra
COPY --from=ghidra-ghidrathon-downloader --link /ghidra /ghidra
RUN sed -i 's/^MAXMEM=.*/MAXMEM=${MAXMEM:-6G}/' /ghidra/support/analyzeHeadless

## Build ghidrathon
RUN --mount=type=bind,from=ghidra-ghidrathon-downloader,source=/ghidrathon,target=/ghidrathon,readwrite \
    cd /ghidrathon && \
    gradle -PGHIDRA_INSTALL_DIR=/ghidra && \
    (/ghidra/support/analyzeHeadless --help || mkdir -p ~/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions) && \
    cd ~/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions && \
    unzip /ghidrathon/dist/ghidra_${GHIDRA_VERSION}_*_ghidrathon.zip

## Build and install mclf loader
RUN --mount=type=bind,from=ghidra-ghidrathon-downloader,source=/mclf-loader,target=/mclf-loader,readwrite \
    cd /mclf-loader && \
    gradle -PGHIDRA_INSTALL_DIR=/ghidra && \
    (/ghidra/support/analyzeHeadless --help || mkdir -p ~/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions) && \
    cd ~/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions && \
    unzip /mclf-loader/dist/ghidra_${GHIDRA_VERSION}_*_mclf-loader.zip
