# ZEKRO

This repository accompanies the paper "ZEKRO: Zero-Knowledge Proof of Integrity Conformance" and provides a research implementation of the evaluated protocol.

## Contents

This repository is organized as follows:

- `swtpm`: Contains a containerized implementation of [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/).
- `zekro`: Contains a containerized implmenetation of an example execution of the ZEKRO protocol which uses [IBM's TPM 2.0 TSS](https://sourceforge.net/projects/ibmtpm20tss/).
- `docker-compose.yml`: Configuration file which spawns both `zekro` and `swtpm` and configures `zekro` to target the software TPM running inside `swtpm`.
- `docker-compose-hwtpm.yml`: Configuration file which spawns `zekro` and configures it to use a hardware TPM avilable on the host. Currently, this file assumes that the host system runs Linux and that the TPM device is exposed under `/dev/tpm0`.

## Building and executing with Docker

To quickly run the provided compose configuration files, you need [Docker](https://www.docker.com/) and `docker-compose` installed.

### Running against a software TPM

To build and run the demonstrative application against [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/) from a terminal, simply change your current working directory to the base of this repository and execute the following command:

    docker-compose -f docker-compose.yml up --abort-on-container-exit --force-recreate --build

### Running against a hardware TPM

If you have a hardware TPM available on your host system, then you can build and run the demonstrative application against your hardware TPM by executing the following command:

    docker-compose -f docker-compose-hwtpm.yml up --abort-on-container-exit --force-recreate --build

### Configuration options

Note that each of the configuration files includes environment variables and build arguments that can be adjusted to enable and disable TSS tracing (which outputs detailed information about the executed TPM commands) and control where and how timing information is logged. To enable or disable a build argument, set its value to either 1 (enabled) or 0 (disabled). These are the currently available arguments used during the build phase:

    ENABLE_TIMINGS=1 # record execution time of each TPM command (1)
    WRITE_TIMINGS_TO_FILE=1
    WRITE_TIMINGS_TO_STDOUT=1
    DEBUG_TSS=0 # output trace of TSS<->TPM communication
    HWTPM=0 # use a hardware TPM (1) or software TPM (0)

By default, timing information is written to the `/tmp/timings` directory inside a running container (as determined by the `TIMINGS_DIR` environment variable), which bridges to the `./timings/` directory on the host. If you want to change the output directory on the host, simply modify the following line in the respective configuration file:

    volumes:
      - /output/directory/on/host:/tmp/timings

## Building and executing without Docker

It is also possible to directly build and run without Docker support using either an IDE (e.g., [vscode](https://code.visualstudio.com/)) or directly in a terminal. For example, to build the demonstrative ZEKRO protocol using [CMake](https://cmake.org/) from a terminal, change your working directory to the [zekro](zekro) subdirectory of this repository (where the [zekro/CMakeLists.txt](zekro/CMakeLists.txt) file is located) and then execute [CMake](https://cmake.org/) (note here that we manually pass in the build arguments):

    cmake -DENABLE_TIMINGS=1 -DWRITE_TIMINGS_TO_FILE=1 -DWRITE_TIMINGS_TO_STDOUT=1 -DVERBOSE=0 -DHWTPM=0 . && make

Once the program has been built, you can run it by executing:

    ./zekro

*Note* that if you do not use Docker, then the `TIMINGS_DIR` environment variable (which you must set manually on your system) directly determines the output directory of the timing information (when compiled to write to files). Furthermore, you need to correctly set up [IBM's TPM 2.0 TSS](https://sourceforge.net/projects/ibmtpm20tss/) on your host system before you can build correctly. Finally, unless you have a hardware TPM and compile the program to use the hardware TPM, you need to have [IBM's Software TPM 2.0](https://sourceforge.net/projects/ibmswtpm2/) up and running before executing the program.

## Disclaimer

The implementations provided in this repository are only research prototypes.

## License

This library is licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
