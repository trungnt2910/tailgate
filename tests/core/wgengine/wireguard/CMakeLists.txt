tailgate_add_test_library(
    tailgate_tests_core_wgengine_wireguard
    Given_ReplayWindow.cpp
    Given_WireGuardRouter.cpp
    Given_WireGuardTunnel.cpp
)
target_link_libraries(tailgate_tests_core_wgengine_wireguard PRIVATE tailgate_core)
