cmake_minimum_required(VERSION 3.10)

project(krdma_examples
        VERSION 0.1
        DESCRIPTION "KRDMA userspace examples"
        LANGUAGES CXX)

add_executable(remote_alloc examples/remote_alloc.cpp)

target_link_libraries(remote_alloc PUBLIC libkrdma)
