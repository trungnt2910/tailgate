set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TAILGATE_UWP_APPX_NAME "Tailgate" CACHE STRING "UWP AppX package identity name")
set(TAILGATE_UWP_APPX_PUBLISHER "CN=Tailgate" CACHE STRING "UWP AppX package publisher")
set(
    TAILGATE_UWP_APPX_CERTIFICATE
    "Tailgate.pfx"
    CACHE STRING
    "UWP AppX signing certificate; relative paths are resolved from this directory"
)

set(TAILGATE_UWP_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(TAILGATE_UWP_MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/AppxManifest.xml")
configure_file(AppxManifest.in "${TAILGATE_UWP_MANIFEST}" @ONLY)

add_subdirectory(strings)
add_subdirectory(common)
add_subdirectory(app)
add_subdirectory(bg)

uwp_add_executable(
    Tailgate
    SOURCES
        app/App.cpp
)
target_link_libraries(Tailgate PRIVATE Tailgate.Uwp.App tailgate_cli)
tailgate_target_add_pdb(Tailgate)

uwp_add_library(
    Tailgate.Background
    SOURCES
        bg/BackgroundWorker.cpp
        bg/BackgroundWorker.def
)
target_link_libraries(Tailgate.Background PRIVATE Tailgate.Uwp.Background)
tailgate_target_add_pdb(Tailgate.Background)

set(TAILGATE_UWP_APPX_CERTIFICATE_ABSOLUTE "${TAILGATE_UWP_APPX_CERTIFICATE}")
if(NOT IS_ABSOLUTE "${TAILGATE_UWP_APPX_CERTIFICATE_ABSOLUTE}")
    cmake_path(
        ABSOLUTE_PATH TAILGATE_UWP_APPX_CERTIFICATE_ABSOLUTE
        BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        NORMALIZE
    )
endif()
uwp_add_appx(
    Tailgate
    MANIFEST ${CMAKE_CURRENT_BINARY_DIR}/AppxManifest.xml
    CERTIFICATE "${TAILGATE_UWP_APPX_CERTIFICATE_ABSOLUTE}"
    RESOURCES
        Tailgate
        Tailgate.Background
        Tailgate.Strings
    FILE_RESOURCES
        SRC ${CMAKE_CURRENT_SOURCE_DIR}
        DST .
            TailgateResources.xaml
        SRC ${CMAKE_CURRENT_SOURCE_DIR}/Images
        DST Images
            *
)

uwp_install_appx(Tailgate)
