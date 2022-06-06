#ifndef TIMING_H
#define TIMING_H

#include <chrono>
typedef std::chrono::system_clock Clock;

#include <iostream>
#include <cstdlib>
#ifdef TPM_POSIX
#include <unistd.h>
#include <cstring>
#include <fcntl.h>
#include <cstdio>
#elif TPM_WINDOWS
#include <fstream>
#endif

static void writeTiming(const char* caller, double timingValue) {
#ifdef WRITE_TIMINGS_TO_STDOUT
    printf("Time [ %s ]: %f ms\n", caller, timingValue);
#endif

#ifdef WRITE_TIMINGS_TO_FILE
    std::string filename = std::string(caller);
	if(const char* env_p = std::getenv("TIMINGS_DIR"))
    filename = std::string(env_p) + std::string("/") + std::string(filename);

    #ifdef TPM_POSIX
        int fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
        char buf[2048];
        snprintf(buf, sizeof(buf), "%f\n", timingValue);
        write(fd, buf, strlen(buf));
        close(fd);
    #elif TPM_WINDOWS
        std::ofstream outfile;
        outfile.open(filename.c_str(), std::ios_base::app);
        outfile << timingValue << "\n";
    #endif

#endif
}

#endif