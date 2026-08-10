set(TAILGATE_UWP_TEST_APPX_NAME "Tailgate.Tests")
set(TAILGATE_UWP_TEST_EXECUTABLE_NAME "Tailgate.Tests")
set(TAILGATE_UWP_TEST_MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/AppxManifest.xml")
configure_file(AppxManifest.in "${TAILGATE_UWP_TEST_MANIFEST}" @ONLY)

# LLVM-MinGW's UWP linker supports whole-archive but not the push-state/pop-state
# wrapper in CMake's default Windows-Clang definition.
set(
    CMAKE_CXX_LINK_LIBRARY_USING_WHOLE_ARCHIVE
    "LINKER:--whole-archive"
    "<LINK_ITEM>"
    "LINKER:--no-whole-archive"
)

set(TAILGATE_UWP_TEST_CERTIFICATE "${TAILGATE_UWP_APPX_CERTIFICATE}")
if(NOT IS_ABSOLUTE "${TAILGATE_UWP_TEST_CERTIFICATE}")
    cmake_path(
        ABSOLUTE_PATH TAILGATE_UWP_TEST_CERTIFICATE
        BASE_DIRECTORY "${PROJECT_SOURCE_DIR}/src/platform/uwp"
        NORMALIZE
    )
endif()

uwp_add_executable(
    tailgate_uwp_tests
    SOURCES
        App.cpp
        Given_Arguments.cpp
        Given_ScreenDiff.cpp
        Given_TestHost.cpp
        ScreenDiff.cpp
        ScreenDiff.h
        TestHost.cpp
        TestHost.h
        TestResult.h
        TestResultDisplay.cpp
        TestResultDisplay.h
        ViewTestInjector.h
        app/Given_AppResources.cpp
        app/Given_AuthorizationController.cpp
        app/Given_ContentDialogView.cpp
        app/Given_DevicePageView.cpp
        app/Given_DialogView.cpp
        app/Given_ExitNodeController.cpp
        app/Given_ExitNodeControlView.cpp
        app/Given_HomePageView.cpp
        app/Given_MainWindowController.cpp
        app/Given_NavigationController.cpp
        app/Given_NodeAuthorizationDialogView.cpp
        app/Given_PingDialogController.cpp
        app/Given_PingDialogView.cpp
        app/Given_SessionController.cpp
        app/Given_SettingsController.cpp
        app/Given_SettingsPageView.cpp
        app/Given_SetOptionsController.cpp
        app/Given_SignInDialogView.cpp
        app/Given_UiFactory.cpp
        bg/Given_DataPlaneManager.cpp
        bg/Given_ExitNodeService.cpp
        bg/Given_HostedDnsService.cpp
        bg/Given_NetworkService.cpp
        bg/Given_PingService.cpp
        bg/Given_SessionManager.cpp
        fakes/app/controller/FakeAuthorizationController.h
        fakes/app/controller/FakeClipboardController.h
        fakes/app/controller/FakeContentDialogController.h
        fakes/app/controller/FakeControlPlaneController.h
        fakes/app/controller/FakeDevicePageController.h
        fakes/app/controller/FakeExitNodeController.h
        fakes/app/controller/FakeHomePageController.h
        fakes/app/controller/FakeInteractiveAuthorizationController.h
        fakes/app/controller/FakeNavigationController.h
        fakes/app/controller/FakeNodeAuthorizationDialogController.h
        fakes/app/controller/FakePackageController.h
        fakes/app/controller/FakePingController.h
        fakes/app/controller/FakePingDialogController.h
        fakes/app/controller/FakeProfilePictureController.h
        fakes/app/controller/FakeSessionController.h
        fakes/app/controller/FakeSetOptionsController.h
        fakes/app/controller/FakeSettingsController.h
        fakes/app/controller/FakeSignInDialogController.h
        fakes/app/controller/FakeTailgateRelayController.h
        fakes/app/controller/FakeVpnProfileController.h
        fakes/app/ui/FakeResourceLoader.h
        fakes/app/view/FakeDialogViews.h
        fakes/bg/manager/FakeDataPlaneManager.h
        fakes/bg/manager/FakeSessionManager.h
        fakes/bg/service/FakeService.h
)
target_link_libraries(
    tailgate_uwp_tests
    PRIVATE
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests>"
        Boost.DI
        Tailgate.Uwp.App.Controller.Impl
        Tailgate.Uwp.App.Ui
        Tailgate.Uwp.App.View.Impl
        Tailgate.Uwp.Background.Manager
        Tailgate.Uwp.Background.Service
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
