tailgate_add_test_library(
    tailgate_tests_core_derp
    Given_DerpClient.cpp
    Given_DerpSendQueue.cpp
)
target_link_libraries(tailgate_tests_core_derp PRIVATE tailgate_core)
