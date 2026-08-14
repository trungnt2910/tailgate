tailgate_add_test_library(
    tailgate_tests_core_serve
    Given_FunnelConfig.cpp
    Given_HandshakeLimiter.cpp
    Given_PeerApiIngress.cpp
)
target_link_libraries(tailgate_tests_core_serve PRIVATE tailgate_core)

add_subdirectory(acme)
