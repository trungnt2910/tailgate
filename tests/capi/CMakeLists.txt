tailgate_add_test_library(
    tailgate_tests_capi
    Given_CApi.cpp
)
target_link_libraries(tailgate_tests_capi PRIVATE tailgate_c)
