cmake_minimum_required(VERSION 3.10.2)
project(libpdb
     VERSION 0.1.0
     DESCRIPTION "PDB Parsing Library"
     LANGUAGES C)

set(PDB_ENABLE_ASSERTIONS TRUE CACHE BOOL "Enable assertions in libpdb")

include(GNUInstallDirs)
set(PDB_STRICT_COMPILE_OPTIONS -Wall -Wextra -pedantic)

add_subdirectory(src)
