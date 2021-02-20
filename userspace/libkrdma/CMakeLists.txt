cmake_minimum_required(VERSION 3.10)

project(libkrdma
        VERSION 0.1
        DESCRIPTION "KRDMA userspace library"
        LANGUAGES CXX)

set(CMAKE_STATIC_LIBRARY_PREFIX "")

find_library(IBVERBS_LIBRARY NAMES ibverbs REQUIRED)
find_library(RDMACM_LIBRARY NAMES rdmacm REQUIRED)

add_library(libkrdma libkrdma/krdma.cpp)

target_include_directories(libkrdma PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(libkrdma PUBLIC ibverbs rdmacm)
