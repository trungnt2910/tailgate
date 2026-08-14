tailgate_add_test_library(
    tailgate_tests_core_di
    Given_Bindings.cpp
)
target_link_libraries(tailgate_tests_core_di PRIVATE tailgate_core)
