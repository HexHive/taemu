FROM ubuntu:jammy

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
        git \
        curl

################################################################################
# Qiling
################################################################################

COPY emulator/qiling.diff .
RUN git clone -b dev https://github.com/qilingframework/qiling.git
RUN cd qiling && git checkout 56dd77b6608698bfe54f4bde01981a40609c9532 && git apply ../qiling.diff && git submodule update --init --recursive && pip3 install . && cd ..
COPY emulator/requirements.txt .
RUN pip3 install -r requirements.txt
RUN sed -i 's/super(ELF,self).__init__(self.mmap)/super(ELF,self).__init__(self.file)/' "$(python3 -c 'import pwnlib.elf.elf; print(pwnlib.elf.elf.__file__)')"

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

# Optional: gef makes interactive debugging of a TA nicer, but it is not needed
# to run any experiment. Its upstream installer pulls distro packages that come
# and go, so a failure here must not break the build.
RUN wget -q https://raw.githubusercontent.com/bata24/gef/dev/install-uv.sh -O- | sh \
    || echo "[!] gef install failed - continuing, debugging tools are optional"

WORKDIR /opt/src

# clone and make drcov-merge
RUN git clone https://github.com/vanhauser-thc/drcov-merge.git && cd drcov-merge && make && mv drcov-merge /opt/afl

RUN pip3 install networkx 

# WTFFFFFFFFF
COPY unicornafl.py /opt/afl/unicornafl/

WORKDIR /srv/
#RUN useradd -u 1000 ctf
