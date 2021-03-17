cmake_minimum_required(VERSION 3.10)

project(rackmem_examples_cpp
        VERSION 0.1
        DESCRIPTION "RackMem userspace C++ examples"
        LANGUAGES CXX)

find_library(FMT_LIBRAY NAMES fmt REQUIRED)

find_package(Boost COMPONENTS program_options REQUIRED)

add_executable(krdma_rpc_test examples_cpp/krdma_rpc_test.cpp)

target_link_libraries(krdma_rpc_test PUBLIC libkrdma Boost::program_options fmt)
