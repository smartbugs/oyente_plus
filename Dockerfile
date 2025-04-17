FROM ubuntu:jammy
LABEL maintainer="Xiao Liang <https://github.com/yxliang01>, Luong Nguyen <luongnt.58@gmail.com>"

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
    crytic-compile==0.3.8 \
    evmdasm \
    pyevmasm \
    requests \
    six \
    solc-select \
    z3-solver==4.14.1.0

# set solidity version & explicitly install common
# solidity versions. solc needs a solidity version
# to be set via solc-select, otherwise it will not
# work.
RUN solc-select install 0.4.26 \
    && solc-select install 0.5.17 \
    && solc-select install 0.6.12 \
    && solc-select install 0.7.6 \
    && solc-select install 0.8.29
ENV SOLC_VERSION=${SOLC_VERSION}

# Copy the Oyente code into the container
COPY . /oyente/
WORKDIR /oyente/

# Entrypoint: run Oyente
ENTRYPOINT ["python3", "/oyente/oyente/oyente.py"]
