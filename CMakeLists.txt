cmake_minimum_required(VERSION 3.10.2)
project(libpdb
     VERSION 0.1.0
     DESCRIPTION "PDB Parsing Library"
     LANGUAGES C)

set(PDB_ENABLE_ASSERTIONS TRUE CACHE BOOL "Enable assertions in libpdb")

# Microsoft's cvinfo.h header requires c11 for anonymous struct/union
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(PDB_STRICT_COMPILE_OPTIONS -Wall -Werror -pedantic)

add_subdirectory(src)
