tailgate_add_library(
    tailgate_linux_event
    STATIC
    EventRegistry.cpp
)
target_include_directories(
    tailgate_linux_event
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(tailgate_linux_event PUBLIC tailgate_core_base)
