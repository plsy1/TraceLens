cmake_minimum_required(VERSION 3.20)

project(tracelens-bpf LANGUAGES C)

option(TRACELENS_BUILD_BPF "Compile eBPF programs" OFF)
set(TRACELENS_BPF_ARCH "x86" CACHE STRING "BPF target architecture")
set(TRACELENS_BPF_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/objects" CACHE PATH "eBPF object output directory")

set(TRACELENS_BPF_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/kernel/process.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/kernel/network.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/kernel/dns.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/kernel/tcp.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/kernel/file.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/userspace/openssl.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/userspace/tls.bpf.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/userspace/plaintext.bpf.c"
)

add_custom_target(tracelens-bpf-sources SOURCES ${TRACELENS_BPF_SOURCES})

if(NOT TRACELENS_BUILD_BPF)
    message(STATUS "eBPF compilation disabled; configure with -DTRACELENS_BUILD_BPF=ON")
    return()
endif()

find_program(CLANG_EXECUTABLE clang REQUIRED)
find_path(BPF_HELPERS_INCLUDE_DIR bpf/bpf_helpers.h)
find_path(LINUX_INCLUDE_DIR linux/types.h)
find_path(LINUX_ARCH_INCLUDE_DIR asm/types.h
    PATHS "/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}")

if(NOT BPF_HELPERS_INCLUDE_DIR OR NOT LINUX_INCLUDE_DIR OR NOT LINUX_ARCH_INCLUDE_DIR)
    message(FATAL_ERROR
        "Could not find eBPF, Linux, or architecture headers. Install libbpf headers "
        "and Linux kernel headers, or leave TRACELENS_BUILD_BPF=OFF.")
endif()

file(MAKE_DIRECTORY "${TRACELENS_BPF_OUTPUT_DIR}")

set(TRACELENS_BPF_OBJECTS)
foreach(source IN LISTS TRACELENS_BPF_SOURCES)
    get_filename_component(name "${source}" NAME_WE)
    set(object "${TRACELENS_BPF_OUTPUT_DIR}/${name}.o")

    add_custom_command(
        OUTPUT "${object}"
        COMMAND "${CLANG_EXECUTABLE}"
            -target bpf
            -D__TARGET_ARCH_${TRACELENS_BPF_ARCH}
            -O2
            -g
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            -I${BPF_HELPERS_INCLUDE_DIR}
            -I${LINUX_INCLUDE_DIR}
            -I${LINUX_ARCH_INCLUDE_DIR}
            -c "${source}"
            -o "${object}"
        DEPENDS
            "${source}"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/common.h"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/events.h"
        VERBATIM
    )
    list(APPEND TRACELENS_BPF_OBJECTS "${object}")
endforeach()

add_custom_target(tracelens-bpf ALL DEPENDS ${TRACELENS_BPF_OBJECTS})
