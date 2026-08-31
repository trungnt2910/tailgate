tailgate_add_test_library(
    tailgate_tests_core_wgengine
    Given_WgengineEngine.cpp
    Given_WgengineSession.cpp
)
target_link_libraries(
    tailgate_tests_core_wgengine
    PRIVATE
        tailgate_core
        tailgate_tests_core_fakes
)

add_subdirectory(magicsock)
add_subdirectory(ping)
add_subdirectory(router)
add_subdirectory(wireguard)
