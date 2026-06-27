cmake_minimum_required(VERSION 3.22)
project(tailgate VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TAILGATE_BUILD_TESTS "Build Tailgate tests" ON)
if(WIN32)
    set(TAILGATE_FRONTEND_DEFAULT OFF)
else()
    set(TAILGATE_FRONTEND_DEFAULT ON)
endif()
option(TAILGATE_BUILD_FRONTEND
       "Build the platform command-line frontend"
       ${TAILGATE_FRONTEND_DEFAULT})

include(cmake/Architecture.cmake)
include(cmake/PDB.cmake)
include(cmake/Sanitizers.cmake)
include(cmake/Targets.cmake)
include(cmake/Tests.cmake)
include(cmake/ThirdParty.cmake)

add_subdirectory(src)
if(TAILGATE_BUILD_TESTS)
    add_subdirectory(tests)
endif()
