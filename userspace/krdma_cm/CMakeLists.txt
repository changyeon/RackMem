cmake_minimum_required(VERSION 3.10)

project(krdma_cm
        VERSION 0.1
        DESCRIPTION "KRDMA cluster manager"
        LANGUAGES CXX)

find_library(FMT_LIBRAY NAMES fmt REQUIRED)

find_package(Boost COMPONENTS program_options REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -pedantic -Werror)

add_executable(krdma_server krdma_cm/krdma_server.cpp)
target_link_libraries(krdma_server PUBLIC libkrdma Boost::program_options fmt)

add_executable(krdma_client krdma_cm/krdma_client.cpp)
target_link_libraries(krdma_client PUBLIC libkrdma Boost::program_options fmt)
