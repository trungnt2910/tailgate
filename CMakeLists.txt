cmake_minimum_required(VERSION 3.28)
project(tailgate VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Unnecessary and breaks builds on Windows hosts.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

option(TAILGATE_BUILD_TESTS "Build Tailgate tests" ON)
if(LINUX)
    set(TAILGATE_BUILD_LINUX_DEFAULT ON)
else()
    set(TAILGATE_BUILD_LINUX_DEFAULT OFF)
endif()
option(TAILGATE_BUILD_LINUX
       "Build the Tailgate Linux frontend"
       ${TAILGATE_BUILD_LINUX_DEFAULT})
if(WIN32)
    set(TAILGATE_BUILD_UWP_DEFAULT ON)
else()
    set(TAILGATE_BUILD_UWP_DEFAULT OFF)
endif()
option(TAILGATE_BUILD_UWP
       "Build the Tailgate UWP frontend"
       ${TAILGATE_BUILD_UWP_DEFAULT})

include(cmake/Architecture.cmake)
include(cmake/PDB.cmake)
include(cmake/Sanitizers.cmake)
include(cmake/Targets.cmake)
include(cmake/Tests.cmake)
include(cmake/ThirdParty.cmake)
if(TAILGATE_BUILD_UWP)
    include(cmake/UWPHostSDK.cmake)
    include(cmake/AppX.cmake)
endif()

add_subdirectory(src)
if(TAILGATE_BUILD_TESTS)
    add_subdirectory(tests)
endif()
