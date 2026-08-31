add_library(tailgate_tests_core_fakes INTERFACE)
target_include_directories(
    tailgate_tests_core_fakes
    INTERFACE
        ${PROJECT_SOURCE_DIR}/tests/core
)
target_link_libraries(tailgate_tests_core_fakes INTERFACE tailgate_core)
