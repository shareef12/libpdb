include_directories(${CMAKE_SOURCE_DIR}/include)

set(LIBPDB_SRC
    pdb.c)

set(PDBPARSE_SRC
    pdbparse.c)

add_library(pdb STATIC ${LIBPDB_SRC})

add_executable(pdbparse ${PDBPARSE_SRC})
target_link_libraries(pdbparse pdb)