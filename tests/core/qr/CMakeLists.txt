tailgate_add_test_library(
    tailgate_tests_core_qr
    Given_QrCode.cpp
)
target_link_libraries(tailgate_tests_core_qr PRIVATE tailgate_core)
