cmake_minimum_required(VERSION 3.10)

project(librackdm
    VERSION 0.1
    DESCRIPTION "RackDM userspace library"
    LANGUAGES C)

set(CMAKE_STATIC_LIBRARY_PREFIX "")

add_library(librackdm librackdm/rackdm.c)

target_include_directories(librackdm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
