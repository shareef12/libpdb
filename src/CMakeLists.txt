# Create an object library so we only have to build pdb.c once when producing
# both static and shared library configurations.
add_library(pdb_object OBJECT pdb.c)
target_compile_options(pdb_object PRIVATE ${PDB_STRICT_COMPILE_OPTIONS})
set_target_properties(pdb_object
  PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden)

if(PDB_ENABLE_ASSERTIONS)
    target_compile_definitions(pdb_object PRIVATE PDB_ENABLE_ASSERTIONS=1)
endif()

# Microsoft's cvinfo.h header requires c11 for anonymous struct/union
target_compile_features(pdb_object PUBLIC c_std_11)
target_include_directories(pdb_object PUBLIC "${PROJECT_SOURCE_DIR}/include")

# Note that cmake doesn't support specifying an object library in
# target_link_libraries until CMake 3.12, so we have to define the libpdb public
# interface in a separate interface library until we can upgrade from 3.10.2.
add_library(pdb_object_interface INTERFACE)
target_compile_features(pdb_object_interface
  INTERFACE
    $<TARGET_PROPERTY:pdb_object,INTERFACE_COMPILE_FEATURES>)
target_include_directories(pdb_object_interface
  INTERFACE
    $<TARGET_PROPERTY:pdb_object,INTERFACE_INCLUDE_DIRECTORIES>)

# Build libpdb.so and libpdb.a
add_library(pdb SHARED $<TARGET_OBJECTS:pdb_object>)
set_target_properties(pdb PROPERTIES OUTPUT_NAME pdb)
target_link_libraries(pdb PUBLIC pdb_object_interface)
set_target_properties(pdb
  PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

add_library(pdb_static STATIC $<TARGET_OBJECTS:pdb_object>)
set_target_properties(pdb_static PROPERTIES OUTPUT_NAME pdb)
target_link_libraries(pdb_static PUBLIC pdb_object_interface)

# Build pdbparse and link against libpdb.so
add_executable(pdbparse pdbparse.c)
target_compile_options(pdbparse PRIVATE ${PDB_STRICT_COMPILE_OPTIONS})
target_link_libraries(pdbparse pdb)

configure_file(config.h.in config.h)
target_include_directories(pdbparse PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

install(
    TARGETS pdb pdb_static pdbparse
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

install(
    DIRECTORY "${PROJECT_SOURCE_DIR}/include/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
