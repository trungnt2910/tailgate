tailgate_add_test_library(
    tailgate_tests_core_wgengine_netstack
    Given_LwipRuntime.cpp
    Given_NetStack.cpp
    Given_TcpStream.cpp
)
target_include_directories(
    tailgate_tests_core_wgengine_netstack PRIVATE ${PROJECT_SOURCE_DIR}/src/core
)
target_link_libraries(
    tailgate_tests_core_wgengine_netstack
    PRIVATE tailgate_core tailgate_core_wgengine_netstack_impl tailgate_tests_core_fakes
)
