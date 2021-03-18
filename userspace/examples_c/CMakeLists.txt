cmake_minimum_required(VERSION 3.10)

project(rackmem_examples_c
        VERSION 0.1
        DESCRIPTION "RackMem userspace C examples"
        LANGUAGES C)

add_executable(rack_vm_test examples_c/rack_vm_test.c)
add_executable(rack_vm_matmul examples_c/rack_vm_matmul.c)
add_executable(rack_dm_test examples_c/rack_dm_test.c)
add_executable(rack_dm_migrate_src examples_c/rack_dm_migrate_src.c)
add_executable(rack_dm_migrate_dst examples_c/rack_dm_migrate_dst.c)

target_link_libraries(rack_dm_test PUBLIC librackdm)
target_link_libraries(rack_dm_migrate_src PUBLIC librackdm)
target_link_libraries(rack_dm_migrate_dst PUBLIC librackdm)
