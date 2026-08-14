tailgate_add_test_library(
    tailgate_tests_core_base
    Given_ByteStream.cpp
    Given_Logging.cpp
    Given_Strings.cpp
)
target_link_libraries(tailgate_tests_core_base PRIVATE tailgate_core)
