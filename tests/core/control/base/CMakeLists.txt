tailgate_add_test_library(
    tailgate_tests_core_control_base
    Given_ControlHandshake.cpp
    Given_H2.cpp
    Given_Noise.cpp
    Given_NoiseTransport.cpp
    Given_TlsWriteProgress.cpp
)
target_link_libraries(tailgate_tests_core_control_base PRIVATE tailgate_core)
