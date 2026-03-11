# Enable C++ for this provider (needed for cthread_bridge.cpp)
enable_language(CXX)

include(ExternalProject)

# Coyote root directory (relative to rdma-core/providers/scenic_ib)
# Path: scenic_ib -> providers -> rdma-core -> sw -> cyt_rdma_driver
set(COYOTE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
set(COYOTE_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/coyote-build")

# Build Coyote library automatically as an external project
ExternalProject_Add(coyote_lib
    SOURCE_DIR "${COYOTE_ROOT}/cmake"
    BINARY_DIR "${COYOTE_BUILD_DIR}"
    CMAKE_ARGS
        # -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DEN_AVX=1
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS "${COYOTE_BUILD_DIR}/libCoyote.so"
)

# Create imported target for the built Coyote library
add_library(Coyote SHARED IMPORTED)
set_target_properties(Coyote PROPERTIES
    IMPORTED_LOCATION "${COYOTE_BUILD_DIR}/libCoyote.so"
    INTERFACE_INCLUDE_DIRECTORIES "${COYOTE_ROOT}/sw/include"
)
add_dependencies(Coyote coyote_lib)

# Build the scenic_ib provider
rdma_provider(scenic_ib libscenic_ib.map
    scenic_ib.c
    cthread_bridge.cpp
)

# Link against the Coyote library
target_link_libraries(scenic_ib-rdmav${IBVERBS_PABI_VERSION} LINK_PRIVATE Coyote)

# Ensure Coyote is built before scenic_ib
add_dependencies(scenic_ib-rdmav${IBVERBS_PABI_VERSION} coyote_lib)

# Set C++ standard for C++ source files
set_source_files_properties(
    cthread_bridge.cpp
    PROPERTIES COMPILE_FLAGS "-std=c++17"
)
