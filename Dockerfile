FROM ubuntu:jammy

RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        python3-minimal \
        python3-pip \
        python3-dev \
        git

COPY emulator/qiling.diff .
RUN git clone -b dev https://github.com/qilingframework/qiling.git
RUN cd qiling && git checkout 56dd77b6608698bfe54f4bde01981a40609c9532 && git apply ../qiling.diff && git submodule update --init --recursive && pip3 install . && cd ..
COPY emulator/requirements.txt .
RUN pip3 install -r requirements.txt
#RUN ./setup.sh

WORKDIR /srv/

RUN useradd -u 1000 ctf 


