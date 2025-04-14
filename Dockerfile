FROM ubuntu:jammy
LABEL maintainer="Xiao Liang <https://github.com/yxliang01>, Luong Nguyen <luongnt.58@gmail.com>"

# crytic-compile does not seem to work inside a container
# so we need to set the solc version manually
ARG SOLC_VERSION=0.8.29

SHELL ["/bin/bash", "-c"]
RUN apt-get update && apt-get -y upgrade
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python-is-python3
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata
RUN pip install --upgrade pip
RUN pip install wheel

# install ethereum
RUN apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt-get update
RUN apt-get install -y ethereum

# install dependencies
RUN pip install requests
RUN pip install six
RUN pip install z3-solver==4.14.1.0
RUN pip install crytic-compile==0.3.8
RUN pip install solc-select

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

# install disassembler choices & their dependencies
RUN pip install evmdasm pyevmasm

COPY . /oyente/

WORKDIR /oyente/
ENTRYPOINT ["python3", "/oyente/oyente/oyente.py"]
