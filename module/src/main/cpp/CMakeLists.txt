cmake_minimum_required(VERSION 3.22.1)
project(traceless)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG_BUILD)
    set(CXX_FLAGS "${CXX_FLAGS} -O0 -g -fno-exceptions -fno-rtti")
    set(LINKER_FLAGS "-g -rdynamic -ffixed-x18 -Wl,--hash-style=both -Wl,--export-dynamic")
else ()
    set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden")
    set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")
endif ()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

add_library(${MODULE_NAME} SHARED traceless.cpp)
# The STL comes from ANDROID_STL=c++_static (see module/build.gradle.kts); we
# no longer link the external "cxx" static library or descend into external/,
# because the topjohnwu/libcxx submodule pinned there is a Magisk-minimal
# tree without the LLVM sources that external/CMakeLists.txt lists.
target_link_libraries(${MODULE_NAME} log)
