FROM ubuntu:22.04

RUN touch /.dockerenv
ENV PIP_BREAK_SYSTEM_PACKAGES=1

RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

#RUN sed -i 's/htt[p|ps]:\/\/archive.ubuntu.com\/ubuntu\//mirror:\/\/mirrors.ubuntu.com\/mirrors.txt/g' /etc/apt/sources.list

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

COPY --from=aflplusplus/aflplusplus:v4.32c --link /usr/local/bin /opt/afl
ENV PATH=$PATH:/opt/afl

COPY --from=aflplusplus/aflplusplus:v4.32c --link  /AFLplusplus/unicorn_mode/unicornafl/bindings/python/unicornafl /opt/afl/unicornafl
ENV PYTHONPATH=$PATH:/opt/afl

################################################################################
# Debug tools (gef, ...)
################################################################################

RUN wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh

WORKDIR /opt/src

# clone and make drcov-merge
RUN git clone https://github.com/vanhauser-thc/drcov-merge.git && cd drcov-merge && make && mv drcov-merge /opt/afl

RUN pip3 install networkx 
COPY unicornafl.py /opt/afl/unicornafl/

WORKDIR /srv/
#RUN useradd -u 1000 ctf
