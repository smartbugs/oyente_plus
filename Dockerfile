FROM ubuntu:jammy
LABEL maintainer="Xiao Liang <https://github.com/yxliang01>, Luong Nguyen <luongnt.58@gmail.com>"

ARG GO_VERSION=1.24.2
# crytic-compile does not seem to work inside a container
# so we need to set the solc version manually
ARG SOLC_VERSION=0.8.29
ENV SOLC_VERSION=${SOLC_VERSION}

# Install relevant basic tools
SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    apt-get -y upgrade && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
    git \
    gnupg \
    python-is-python3 \
    python3 \
    python3-pip \
    software-properties-common \
    tzdata \
    wget && \
    rm -rf /var/lib/apt/lists/*

# Install Ethereum repository and package
RUN add-apt-repository -y ppa:ethereum/ethereum && \
    apt-get update && \
    apt-get install -y ethereum && \
    rm -rf /var/lib/apt/lists/*

# Upgrade pip, install Python wheels and required Python libraries
RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir \
    cbor2 \
    crytic-compile==0.3.8 \
    evmdasm \
    pyevmasm \
    requests \
    six \
    solc-select \
    z3-solver==4.14.1.0 && \
    pip install --no-cache-dir git+https://github.com/ZarIliv/ethutils.git@main#egg=ethutils

# set solidity version & explicitly install the specified
# version of solidity. This is needed because solc needs
# a solidity version to be set via solc-select, otherwise
# it will not work.
RUN solc-select install ${SOLC_VERSION}
ENV SOLC_VERSION=${SOLC_VERSION}

# Install Go
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

# Install geas using module-aware mode
RUN export PATH=$PATH:/usr/local/go/bin && \
    export GOBIN=/usr/local/bin && \
    export GO111MODULE=on && \
    go install github.com/fjl/geas/cmd/geas@90dd9310fef66708b9343aba8e48510d13a5e093

# Copy the Oyente code into the container
COPY . /oyente/
WORKDIR /oyente/

# Entrypoint: run Oyente
ENTRYPOINT ["python3", "/oyente/oyente/oyente.py"]
