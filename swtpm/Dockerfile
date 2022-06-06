FROM ubuntu:18.04

RUN apt-get update -y && apt-get install -y g++ build-essential autoconf cmake libssl-dev libtool pkg-config libgmp3-dev netcat

COPY . /app

RUN mkdir /opt/ibmtpm && tar -xzf /app/ibmtpm.tar.gz -C /opt/ibmtpm

WORKDIR /opt/ibmtpm/src
RUN make

ENTRYPOINT [ "/opt/ibmtpm/src/tpm_server" ]
