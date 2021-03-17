#!/bin/bash

sloccount \
    modules/include \
    modules/krdma \
    modules/rack_dvs \
    modules/rack_block \
    modules/rack_vm \
    modules/rack_dm \
    userspace/libkrdma/libkrdma \
    userspace/librackdm/librackdm \
    userspace/krdma_cm/krdma_cm \
    userspace/examples_c/examples_c \
    userspace/examples_cpp/examples_cpp
