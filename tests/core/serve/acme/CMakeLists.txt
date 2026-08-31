tailgate_add_test_library(
    tailgate_tests_core_serve_acme
    Given_AcmeClient.cpp
)
target_include_directories(
    tailgate_tests_core_serve_acme
    PRIVATE "${PROJECT_SOURCE_DIR}/src/core"
)
target_link_libraries(
    tailgate_tests_core_serve_acme
    PRIVATE
        tailgate_core
        tailgate_tests_core_fakes
)
