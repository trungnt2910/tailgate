tailgate_add_test_library(
    tailgate_tests_cli
    Given_Arguments.cpp
)
target_link_libraries(tailgate_tests_cli PRIVATE tailgate_cli)
