ARG ETHEREUM_VERSION=alltools-v1.7.3
ARG SOLC_VERSION=0.8.10

FROM ethereum/client-go:${ETHEREUM_VERSION} as geth
FROM ethereum/solc:${SOLC_VERSION} as solc

FROM ubuntu:focal

ARG NODEREPO=node_14.x

LABEL maintainer "Xiao Liang <https://github.com/yxliang01>, Luong Nguyen <luongnt.58@gmail.com>"

SHELL ["/bin/bash", "-c", "-l"]
RUN apt-get update && apt-get -y upgrade
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y python3
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata
RUN apt-get -y install python3-pip

RUN apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:ethereum/ethereum
RUN apt-get update
RUN apt-get install -y ethereum
RUN apt-get install -y solc

RUN apt install python-is-python3
RUN pip install --upgrade pip

RUN pip install wheel


# install the packages needed by Oyente
RUN pip install six
RUN pip install z3
RUN pip install requests
RUN pip install z3-solver==4.5.1
RUN pip install crytic-compile==0.3.1


COPY . /oyente/

WORKDIR /oyente/
ENTRYPOINT ["python3", "/oyente/oyente/oyente.py"]
