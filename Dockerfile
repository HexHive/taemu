FROM ubuntu:jammy

RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        wget \
        file \
        vim \
        gdb-multiarch \
        python3-minimal \
        python3-pip \
        python3-dev \
        python3-ipython \
        python3-ipdb \
        git

################################################################################
# Qiling
################################################################################

COPY emulator/qiling.diff .
RUN git clone -b dev https://github.com/qilingframework/qiling.git
RUN cd qiling && git checkout 56dd77b6608698bfe54f4bde01981a40609c9532 && git apply ../qiling.diff && git submodule update --init --recursive && pip3 install . && cd ..
COPY emulator/requirements.txt .
RUN pip3 install -r requirements.txt
#RUN ./setup.sh

################################################################################
# AFL++
################################################################################

COPY --from=aflplusplus/aflplusplus:v4.21c --link /usr/local/bin /opt/afl
ENV PATH=$PATH:/opt/afl

COPY --from=aflplusplus/aflplusplus:v4.21c --link  /AFLplusplus/unicorn_mode/unicornafl/bindings/python/unicornafl /opt/afl/unicornafl
ENV PYTHONPATH=$PATH:/opt/afl

################################################################################
# Debug tools (gef, ...)
################################################################################

RUN wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh

WORKDIR /srv/
RUN useradd -u 1000 ctf
