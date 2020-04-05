#!/bin/bash
#
# Auto-format the code using clang-format
#

clang-format --style=file -i    \
    include/pdb.h               \
    include/pdb/dbistream.h     \
    include/pdb/gsistream.h     \
    include/pdb/msf.h           \
    include/pdb/pdbstream.h     \
    src/config.h.in             \
    src/pdb.c                   \
    src/pdbparse.c
