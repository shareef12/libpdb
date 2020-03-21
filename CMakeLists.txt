cmake_minimum_required(VERSION 3.10.2)
project(libpdb)

set(PDB_ENABLE_ASSERTIONS TRUE CACHE BOOL "Enable assertions in libpdb")

add_subdirectory(src)
