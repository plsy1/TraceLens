cmake_minimum_required(VERSION 3.20)

project(tracelens LANGUAGES C)

option(TRACELENS_BUILD_BPF "Compile eBPF programs" OFF)

add_subdirectory(bpf)
