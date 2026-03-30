# Enable C++ for this provider (needed for cthread_bridge.cpp)
enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Coyote root directory (relative to rdma-core/providers/scenic_ib)
# Path: scenic_ib -> providers -> rdma-core -> submodules -> Coyote
set(COYOTE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../Coyote")

# Build Coyote sources as a static library (Coyote's own CMakeLists.txt is
# designed for a standalone executable, so we cannot use add_subdirectory).
set(EN_AVX "1" CACHE STRING "AVX enabled.")

file(GLOB COYOTE_SOURCES "${COYOTE_ROOT}/sw/src/*.cpp")
add_library(Coyote STATIC ${COYOTE_SOURCES})
target_include_directories(Coyote PUBLIC "${COYOTE_ROOT}/sw/include" "${COYOTE_ROOT}/sw/include/coyote")
set_target_properties(Coyote PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON POSITION_INDEPENDENT_CODE ON)

find_package(Boost COMPONENTS program_options REQUIRED)
target_link_libraries(Coyote PUBLIC ${Boost_LIBRARIES} pthread)

if(EN_AVX)
    target_compile_options(Coyote PRIVATE -pthread -mavx -march=native -O3)
else()
    target_compile_options(Coyote PRIVATE -pthread -march=native -O1)
endif()

# Build the scenic_ib provider
rdma_provider(scenic_ib libscenic_ib.map
    scenic_ib.c
    cthread_bridge.cpp
)

# Link against Coyote; include directories are propagated automatically via the target
target_link_libraries(scenic_ib-rdmav${IBVERBS_PABI_VERSION} LINK_PRIVATE Coyote)
