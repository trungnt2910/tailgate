tailgate_add_test_library(
    tailgate_tests_core_wgengine_router
    Given_RouterConfig.cpp
)
target_link_libraries(tailgate_tests_core_wgengine_router PRIVATE tailgate_core)
