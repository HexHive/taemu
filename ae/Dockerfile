# Artifact-evaluation controller image.
#
# The emulator image (ta_emu_ae, built from ../Dockerfile) runs a single TA.
# This image runs *everything else* of the artifact evaluation: the campaign
# orchestrator (swarm), the evaluation scripts in eval/, the table generators
# and the plotting code. It talks to the docker daemon of the host through the
# forwarded socket and starts emulator containers as siblings, which is why it
# only needs the docker *client*.
#
# Build:  docker build -f ae/Dockerfile -t ta_emu_ae_ctl .
# Run:    see ae/ae.sh (it forwards /var/run/docker.sock and TAEMU_ROOT)

ARG BASE_IMAGE=ta_emu_ae
FROM ${BASE_IMAGE}

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg jq bc pv patch \
        libfdt1 libslirp0 libusb-1.0-0 && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin

# Table generation and plotting (Figures 4 and 5, mitigation benchmark plot),
# plus pexpect, which drives the OP-TEE QEMU boot of the mitigation experiment.
# libfdt/libslirp/libusb are the shared libraries the OP-TEE tree's own
# qemu-system-aarch64 needs; the aarch64 toolchain comes from that tree.
RUN pip3 install --no-cache-dir \
        matplotlib==3.10.8 \
        pexpect \
        numpy \
        networkx \
        tqdm \
        aiofiles \
        cachetools \
        loguru \
        tenacity \
        pandas

ENV MPLBACKEND=Agg
ENV PYTHONUNBUFFERED=1
WORKDIR /srv
