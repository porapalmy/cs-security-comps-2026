FROM ubuntu:22.04


RUN apt update && apt install -y \
    yara \
    python3 \
    python3-pip \
    libmagic-dev \
    git \
    curl \
    wget \
    parallel \
    file \
    binutils \
    strace \
    tcpdump \
    && pip3 install --no-cache-dir \
        yara-python \
        tqdm \
        numpy \
        scipy \
        scikit-learn \
        matplotlib \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /analysis


CMD ["/bin/bash"]