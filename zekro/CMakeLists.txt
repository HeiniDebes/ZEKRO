cmake_minimum_required(VERSION 3.10)
project(zekro)

if (WIN32)
        add_definitions(-DTPM_WINDOWS)
        link_directories(libs)
        include_directories(C:\\opt\\ibmtss\\utils)
endif (WIN32)
if (UNIX)
        add_definitions(-DTPM_POSIX)
        include_directories(/opt/ibmtss/utils)
endif (UNIX)

if (((DEFINED ENV{ENABLE_TIMINGS}) AND ("$ENV{ENABLE_TIMINGS}" EQUAL "1")) OR ((DEFINED ENABLE_TIMINGS) AND ("${ENABLE_TIMINGS}" EQUAL "1")))
        add_definitions(-DENABLE_TIMINGS)
endif()
if (((DEFINED ENV{WRITE_TIMINGS_TO_FILE}) AND ("$ENV{WRITE_TIMINGS_TO_FILE}" EQUAL "1")) OR ((DEFINED WRITE_TIMINGS_TO_FILE) AND ("${WRITE_TIMINGS_TO_FILE}" EQUAL "1")))
        add_definitions(-DWRITE_TIMINGS_TO_FILE)
endif()
if (((DEFINED ENV{WRITE_TIMINGS_TO_STDOUT}) AND ("$ENV{WRITE_TIMINGS_TO_STDOUT}" EQUAL "1")) OR ((DEFINED WRITE_TIMINGS_TO_STDOUT) AND ("${WRITE_TIMINGS_TO_STDOUT}" EQUAL "1")))
        add_definitions(-DWRITE_TIMINGS_TO_STDOUT)
endif()
if (((DEFINED ENV{DEBUG_TSS}) AND ("$ENV{DEBUG_TSS}" EQUAL "1")) OR ((DEFINED DEBUG_TSS) AND ("${DEBUG_TSS}" EQUAL "1")))
        add_definitions(-DDEBUG_TSS)
endif()
if ((DEFINED ENV{HWTPM}) AND ("$ENV{HWTPM}" EQUAL "1") OR ((DEFINED HWTPM) AND ("${HWTPM}" EQUAL "1")))
        add_definitions(-DHWTPM)
endif()

add_definitions(-DTPM_TPM20)

set(COMPILE_FLAGS "-Wall -O3 -Wno-unused-function -Wno-array-bounds -Wno-unused-result")
set(CMAKE_CXX_FLAGS "${COMPILE_FLAGS}")
set(CPPFLAGS -stdlib=libc++ LDFLAGS)
set(CMAKE_CXX_STANDARD 14)

find_package(OpenSSL REQUIRED)

include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(zekro
        include/cryptoutils.h
        include/objecttemplates.h
        include/prover.h
        include/timing.h
        include/tpm.h
        src/cryptoutils.c
        src/prover.cpp
        src/tpm.cpp
        main.cpp)

if (WIN32)
        target_link_libraries(${PROJECT_NAME} ibmtss ${OPENSSL_LIBRARIES} wsock32 ws2_32)

        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${PROJECT_SOURCE_DIR}/libs"
                $<TARGET_FILE_DIR:${PROJECT_NAME}>)
endif ()
if (UNIX)
        target_link_libraries(${PROJECT_NAME} PRIVATE ibmtss ${OPENSSL_LIBRARIES})
endif ()
