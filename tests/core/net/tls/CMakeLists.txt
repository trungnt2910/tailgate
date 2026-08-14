tailgate_add_test_library(
    tailgate_tests_core_net_tls
    Given_TlsWriteProgress.cpp
)
target_include_directories(
    tailgate_tests_core_net_tls
    PRIVATE "${PROJECT_SOURCE_DIR}/src/core/net/tls"
)
target_link_libraries(tailgate_tests_core_net_tls PRIVATE tailgate_core)
