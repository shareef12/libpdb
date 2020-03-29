include_directories(${CMAKE_SOURCE_DIR}/include)

set(LIBPDB_SRC
    pdb.c)

set(PDBPARSE_SRC
    pdbparse.c)

add_library(pdb STATIC ${LIBPDB_SRC})
if(PDB_ENABLE_ASSERTIONS)
    target_compile_definitions(pdb PRIVATE PDB_ENABLE_ASSERTIONS=1)
endif()

add_executable(pdbparse ${PDBPARSE_SRC})
target_link_libraries(pdbparse pdb)