set(TAILGATE_UWP_TEST_APPX_NAME "Tailgate.Tests")
set(TAILGATE_UWP_TEST_EXECUTABLE_NAME "Tailgate.Tests")
set(TAILGATE_UWP_TEST_MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/AppxManifest.xml")
configure_file(AppxManifest.in "${TAILGATE_UWP_TEST_MANIFEST}" @ONLY)

set(TAILGATE_UWP_TEST_CERTIFICATE "${TAILGATE_UWP_APPX_CERTIFICATE}")
if(NOT IS_ABSOLUTE "${TAILGATE_UWP_TEST_CERTIFICATE}")
    cmake_path(
        ABSOLUTE_PATH TAILGATE_UWP_TEST_CERTIFICATE
        BASE_DIRECTORY "${PROJECT_SOURCE_DIR}/src/platform/uwp"
        NORMALIZE
    )
endif()

add_subdirectory(app)
add_subdirectory(bg)

uwp_add_executable(
    tailgate_uwp_tests
    SOURCES
        App.cpp
        Given_Arguments.cpp
        Given_TestHost.cpp
        IdlingRegistry.cpp
        IdlingRegistry.h
        TestHost.cpp
        TestHost.h
        TestResult.h
        TestResultDisplay.cpp
        TestResultDisplay.h
        ViewTestInjector.h
)
target_link_libraries(
    tailgate_uwp_tests
    PRIVATE
        tailgate_tests
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_uwp_app>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_uwp_bg>"
        Boost.DI
        mapbox::pixelmatch
        Tailgate.Uwp.App.Controller.Impl
        Tailgate.Uwp.App.Ui
        Tailgate.Uwp.App.View.Impl
        Tailgate.Uwp.Background.Manager
        Tailgate.Uwp.Background.Service
        Tailgate.Uwp.Common
)
target_include_directories(
    tailgate_uwp_tests
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${PROJECT_SOURCE_DIR}/src/platform/uwp"
)
set_target_properties(
    tailgate_uwp_tests
    PROPERTIES OUTPUT_NAME "${TAILGATE_UWP_TEST_EXECUTABLE_NAME}"
)
tailgate_target_add_pdb(tailgate_uwp_tests)

uwp_add_appx(
    Tailgate.Tests
    MANIFEST "${TAILGATE_UWP_TEST_MANIFEST}"
    CERTIFICATE "${TAILGATE_UWP_TEST_CERTIFICATE}"
    RESOURCES
        tailgate_uwp_tests
        Tailgate.Strings
    FILE_RESOURCES
        SRC "${PROJECT_SOURCE_DIR}/src/platform/uwp"
        DST .
            TailgateResources.xaml
        SRC "${PROJECT_SOURCE_DIR}/src/platform/uwp/Images"
        DST Images
            *
        SRC "${CMAKE_CURRENT_SOURCE_DIR}"
        DST test
            TestTheme.xaml
        SRC "${CMAKE_CURRENT_SOURCE_DIR}/data/goldens"
        DST data/goldens
            */*.png
)

uwp_install_appx(Tailgate.Tests)

function(tailgate_uwp_tests_are_deployable output_variable)
    if(NOT CMAKE_HOST_WIN32)
        set(${output_variable} FALSE PARENT_SCOPE)
        return()
    endif()

    string(TOLOWER "${UWP_HOST_ARCH}" host_architecture)
    string(TOLOWER "${UWP_APPX_ARCH}" appx_architecture)
    set(is_deployable FALSE)
    if(host_architecture STREQUAL appx_architecture)
        set(is_deployable TRUE)
    elseif(host_architecture STREQUAL "x64" AND appx_architecture STREQUAL "x86")
        set(is_deployable TRUE)
    endif()
    set(${output_variable} ${is_deployable} PARENT_SCOPE)
endfunction()

tailgate_uwp_tests_are_deployable(TAILGATE_UWP_TESTS_DEPLOYABLE)
if(TAILGATE_UWP_TESTS_DEPLOYABLE)
    find_program(TAILGATE_UWP_POWERSHELL_EXECUTABLE NAMES powershell.exe REQUIRED)
    set(
        TAILGATE_UWP_TEST_MANIFEST_STAGED
        "${CMAKE_CURRENT_BINARY_DIR}/Tailgate.Tests-appx/AppxManifest.xml"
    )
    set(
        TAILGATE_UWP_TEST_LAUNCHER
            "${TAILGATE_UWP_POWERSHELL_EXECUTABLE}"
            -NoProfile
            -NonInteractive
            -ExecutionPolicy
            Bypass
            -File
            "${CMAKE_CURRENT_SOURCE_DIR}/RunTests.ps1"
            -ManifestPath
            "${TAILGATE_UWP_TEST_MANIFEST_STAGED}"
    )
    set_property(
        TARGET tailgate_uwp_tests
        PROPERTY CROSSCOMPILING_EMULATOR ${TAILGATE_UWP_TEST_LAUNCHER}
    )
    gtest_discover_tests(
        tailgate_uwp_tests
        DISCOVERY_MODE PRE_TEST
        DISCOVERY_TIMEOUT 999999999 # GTest does not support a genuine infinite timeout.
        PROPERTIES RUN_SERIAL TRUE
    )
    add_custom_target(
        tailgate_uwp_tests_all
        COMMAND ${TAILGATE_UWP_TEST_LAUNCHER} "$<TARGET_FILE:tailgate_uwp_tests>"
        DEPENDS Tailgate.Tests-appx
        USES_TERMINAL
    )
endif()
