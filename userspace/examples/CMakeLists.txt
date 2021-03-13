cmake_minimum_required(VERSION 3.10)

project(krdma_examples
        VERSION 0.1
        DESCRIPTION "KRDMA userspace examples"
        LANGUAGES CXX)

find_library(FMT_LIBRAY NAMES fmt REQUIRED)

find_package(Boost COMPONENTS program_options REQUIRED)

add_executable(rack_vm_test examples/rack_vm_test.cpp)
add_executable(rack_vm_matmul examples/rack_vm_matmul.cpp)
add_executable(krdma_rpc_test examples/krdma_rpc_test.cpp)
add_executable(remote_alloc examples/remote_alloc.cpp)

target_link_libraries(krdma_rpc_test PUBLIC libkrdma Boost::program_options fmt)
target_link_libraries(remote_alloc PUBLIC libkrdma)
