set(LIBPDB_SRC
    pdb.c)

set(PDBPARSE_SRC
    pdbparse.c)

add_library(pdb_object OBJECT ${LIBPDB_SRC})
target_compile_options(pdb_object PRIVATE ${PDB_STRICT_COMPILE_OPTIONS})
target_include_directories(pdb_object PUBLIC ${PROJECT_SOURCE_DIR}/include)
set_target_properties(pdb_object
  PROPERTIES
    POSITION_INDEPENDENT_CODE 1
    C_VISIBILITY_PRESET hidden)

if(PDB_ENABLE_ASSERTIONS)
    target_compile_definitions(pdb_object PRIVATE PDB_ENABLE_ASSERTIONS=1)
endif()

add_library(pdb_shared SHARED $<TARGET_OBJECTS:pdb_object>)
set_target_properties(pdb_shared PROPERTIES OUTPUT_NAME pdb)

add_library(pdb_static STATIC $<TARGET_OBJECTS:pdb_object>)
set_target_properties(pdb_static PROPERTIES OUTPUT_NAME pdb)

# CMake 3.10.x workaround: CMake does not propagate PUBLIC or INTERFACE include
# directories unless target_link_libraries is used. Since you cannot use
# target_link_libraries with object libraries until CMake 3.12, we are stuck
# manually propagating this property until we can upgrade.
target_include_directories(pdb_shared
  PUBLIC
    $<TARGET_PROPERTY:pdb_object,INTERFACE_INCLUDE_DIRECTORIES>)
target_include_directories(pdb_static
  PUBLIC
    $<TARGET_PROPERTY:pdb_object,INTERFACE_INCLUDE_DIRECTORIES>)

add_executable(pdbparse ${PDBPARSE_SRC})
target_compile_options(pdbparse PRIVATE ${PDB_STRICT_COMPILE_OPTIONS})
target_link_libraries(pdbparse pdb_shared)

configure_file(config.h.in config.h)
target_include_directories(pdbparse PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
