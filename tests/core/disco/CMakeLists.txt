tailgate_add_test_library(
    tailgate_tests_core_disco
    Given_Disco.cpp
)
target_link_libraries(tailgate_tests_core_disco PRIVATE tailgate_core)
