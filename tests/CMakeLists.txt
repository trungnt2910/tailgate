add_subdirectory(capi)
add_subdirectory(cli)
add_subdirectory(core)

# LLVM-MinGW's UWP linker supports whole-archive but not the push-state/pop-state
# wrapper in CMake's default Windows-Clang definition.
if(TAILGATE_BUILD_UWP)
    set(
        CMAKE_CXX_LINK_LIBRARY_USING_WHOLE_ARCHIVE
        "LINKER:--whole-archive"
        "<LINK_ITEM>"
        "LINKER:--no-whole-archive"
    )
endif()

add_library(tailgate_tests INTERFACE)
target_link_libraries(
    tailgate_tests
    INTERFACE
        GTest::gtest
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_capi>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_cli>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_base>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_control_base>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_control_client>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_crypto>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_derp>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_disco>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_hosted>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_net_dns>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_net_packet>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_net_stun>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_qr>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_serve>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_serve_acme>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_types_netmap>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_wgengine_magicsock>"
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,tailgate_tests_core_wgengine_wireguard>"
)

if(TAILGATE_BUILD_LINUX)
    add_subdirectory(linux)
endif()

if(TAILGATE_BUILD_UWP)
    add_subdirectory(uwp)
endif()
