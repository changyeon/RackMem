cmake_minimum_required(VERSION 3.10)

project(krdma VERSION 0.1)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -pedantic -Werror)

add_subdirectory(libkrdma)
add_subdirectory(krdma_cm)
add_subdirectory(examples)
