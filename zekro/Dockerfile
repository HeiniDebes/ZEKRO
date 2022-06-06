FROM ubuntu:18.04

# if ENABLE_TIMINGS=1, then the program will compute the execution time of each TPM command
ARG ENABLE_TIMINGS
# if WRITE_TIMINGS_TO_FILE=1, then the program writes (appends) the execution times to log files corresponding to each TPM command
ARG WRITE_TIMINGS_TO_FILE
# if WRITE_TIMINGS_TO_STDOUT=1, then the program writes the execution times to standard output (stdout) as they appear
ARG WRITE_TIMINGS_TO_STDOUT
# if DEBUG_TSS=1, then the program will also output detailed traces of the TSS<->TPM communication to stdout
ARG DEBUG_TSS
# if HWTPM=1, then the program will attempt to use the concrete (hardware) TPM exposed by the host instead of the software TPM
ARG HWTPM

RUN apt-get update -y && apt-get install -y g++ build-essential autoconf cmake libssl-dev libtool pkg-config libgmp3-dev

COPY . /app

RUN mkdir /opt/ibmtss && tar -xzf /app/ibmtss.tar.gz -C /opt/ibmtss

WORKDIR /opt/ibmtss
RUN autoreconf -i
RUN if [ "$HWTPM" = "1" ]; then ./configure --prefix=/usr/local --disable-tpm-1.2; else ./configure --prefix=/usr/local --disable-tpm-1.2 --disable-hwtpm; fi
RUN make
RUN make install
RUN ldconfig -v

WORKDIR /app
RUN cmake .
RUN make

ENTRYPOINT [ "/app/zekro" ]
