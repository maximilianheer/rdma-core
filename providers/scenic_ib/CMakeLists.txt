# Enable C++ for this provider (needed for cthread_bridge.cpp and cThread.cpp)
enable_language(CXX)

# Coyote directories (relative to rdma-core/providers/scenic_ib)
set(COYOTE_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../include")
set(COYOTE_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../src")

rdma_provider(scenic_ib libscenic_ib.map
# List of all source files to be used
scenic_ib.c
cthread_bridge.cpp
# Include the Coyote cThread implementation
${COYOTE_SRC_DIR}/cThread.cpp
)

# Add Coyote include directory for the cThread headers
target_include_directories(scenic_ib-rdmav${IBVERBS_PABI_VERSION} PRIVATE ${COYOTE_INCLUDE_DIR})

# Find and link against Boost (for named_mutex used by cThread)
find_package(Boost REQUIRED COMPONENTS system)
target_link_libraries(scenic_ib-rdmav${IBVERBS_PABI_VERSION} LINK_PRIVATE Boost::boost)

# Set C++ standard for C++ source files
set_source_files_properties(
    cthread_bridge.cpp
    ${COYOTE_SRC_DIR}/cThread.cpp
    PROPERTIES COMPILE_FLAGS "-std=c++17"
)
