if(TAILGATE_BUILD_TESTS)
    include(CTest)
    include(GoogleTest)

    function(tailgate_add_test_executable target)
        tailgate_add_executable(${target} ${ARGN})
        target_link_libraries(${target} PRIVATE GTest::gtest_main)
        gtest_discover_tests(${target} DISCOVERY_MODE PRE_TEST)
    endfunction()

    function(tailgate_add_test_library target)
        tailgate_add_library(${target} STATIC ${ARGN})
        target_include_directories(
            ${target}
            PRIVATE
                "${PROJECT_SOURCE_DIR}/tests"
        )
        target_link_libraries(${target} PRIVATE GTest::gtest)
    endfunction()

    function(tailgate_uwp_add_test_library target)
        tailgate_add_test_library(${target} ${ARGN})
        uwp_configure_target(${target})
    endfunction()
endif()
