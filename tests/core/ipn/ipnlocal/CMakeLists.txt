tailgate_add_test_library(tailgate_tests_core_ipn_ipnlocal Given_LocalServices.cpp)
target_link_libraries(
    tailgate_tests_core_ipn_ipnlocal
    PRIVATE
        tailgate_core
        tailgate_tests_core_fakes
)
