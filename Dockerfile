FROM python:3.11-slim AS base
LABEL maintainer="SmartBugs Project <https://github.com/smartbugs/oyente"

SHELL ["/bin/bash", "-c"]

# Upgrade pip, install required Python packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git && \
    pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir \
        cbor2 \
        crytic-compile==0.3.8 \
        requests \
        six \
        solc-select \
        typing_extensions \
        z3-solver==4.14.1.0 && \
    pip install --no-cache-dir git+https://github.com/gsalzer/ethutils.git@main#egg=ethutils && \
    apt-get purge -y --auto-remove git && \
    rm -rf /var/lib/apt/lists/*

# Install chosen solidity compiler version
ARG SOLC_VERSION=0.8.29
ENV SOLC_VERSION=${SOLC_VERSION}
RUN solc-select install ${SOLC_VERSION}

# Copy and initialize Oyente
COPY ./oyente /oyente/
WORKDIR /oyente
RUN python3 -O -m compileall -f /oyente

ENTRYPOINT ["python3", "/oyente/oyente.py"]
