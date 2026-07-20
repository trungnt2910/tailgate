include(ExternalProject)

# These tools run on the build host, even when Tailgate is cross-compiled for UWP.
set(UWP_HOST_SDK_INSTALL_DIR "${CMAKE_BINARY_DIR}/third_party")

if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    set(UWP_HOST_ARCH "x64")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86|i686")
    set(UWP_HOST_ARCH "x86")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    set(UWP_HOST_ARCH "ARM64")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ARM|armv7")
    set(UWP_HOST_ARCH "ARM")
else()
    set(UWP_HOST_ARCH "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()

function(_uwp_find_windows_sdk)
    set(registry_keys
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots"
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows Kits\\Installed Roots"
    )

    foreach(registry_key IN LISTS registry_keys)
        cmake_host_system_information(
            RESULT windows_kits_root
            QUERY WINDOWS_REGISTRY "${registry_key}"
            VALUE KitsRoot10
        )
        if(IS_DIRECTORY "${windows_kits_root}")
            break()
        endif()
    endforeach()

    if(NOT IS_DIRECTORY "${windows_kits_root}")
        message(FATAL_ERROR "Failed to determine the Windows 10 SDK location.")
    endif()

    file(
        GLOB sdk_bin_directories
        LIST_DIRECTORIES TRUE
        RELATIVE "${windows_kits_root}/bin"
        "${windows_kits_root}/bin/10.*"
    )
    list(SORT sdk_bin_directories COMPARE NATURAL ORDER DESCENDING)

    foreach(sdk_version IN LISTS sdk_bin_directories)
        set(host_tool_directory
            "${windows_kits_root}/bin/${sdk_version}/${UWP_HOST_ARCH}"
        )
        if(EXISTS "${host_tool_directory}/makeappx.exe" AND
           EXISTS "${host_tool_directory}/makepri.exe")
            set(UWP_WINDOWS_SDK_HOST_TOOL_DIRECTORY "${host_tool_directory}" PARENT_SCOPE)
            return()
        endif()
    endforeach()

    message(
        FATAL_ERROR
        "Failed to find a Windows 10 SDK containing makeappx.exe and makepri.exe for "
        "the ${UWP_HOST_ARCH} host architecture."
    )
endfunction()

ExternalProject_Add(
    cppwinrt
    GIT_REPOSITORY https://github.com/microsoft/cppwinrt.git
    GIT_TAG febda5dfa1d5840096e5d94c5f317b770f4cbf86
    USES_TERMINAL_CONFIGURE TRUE
    USES_TERMINAL_BUILD TRUE
    USES_TERMINAL_INSTALL TRUE
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=${UWP_HOST_SDK_INSTALL_DIR}
        -DBUILD_TESTING=FALSE
)
ExternalProject_Add_StepTargets(cppwinrt install)
set(UWP_CPPWINRT_EXECUTABLE "${UWP_HOST_SDK_INSTALL_DIR}/bin/cppwinrt")
set(UWP_CPPWINRT_TARGET cppwinrt-install)

if(CMAKE_HOST_WIN32)
    _uwp_find_windows_sdk()

    find_program(
        UWP_MAKEAPPX_EXECUTABLE
        NAMES makeappx.exe
        HINTS "${UWP_WINDOWS_SDK_HOST_TOOL_DIRECTORY}"
        NO_DEFAULT_PATH
        REQUIRED
    )
    find_program(
        UWP_MAKEPRI_EXECUTABLE
        NAMES makepri.exe
        HINTS "${UWP_WINDOWS_SDK_HOST_TOOL_DIRECTORY}"
        NO_DEFAULT_PATH
        REQUIRED
    )
else()
    ExternalProject_Add(
        msix-packaging
        GIT_REPOSITORY https://github.com/microsoft/msix-packaging.git
        GIT_TAG efeb9dad695a200c2beaddcba54a52c8320bd135
        GIT_SUBMODULES ""
        USES_TERMINAL_CONFIGURE TRUE
        USES_TERMINAL_BUILD TRUE
        USES_TERMINAL_INSTALL TRUE
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_INSTALL_PREFIX=${UWP_HOST_SDK_INSTALL_DIR}
            -DMSIX_PACK=TRUE
            -DMSIX_SAMPLES=FALSE
            -DMSIX_TESTS=FALSE
            -DUSE_VALIDATION_PARSER=TRUE
        INSTALL_COMMAND
            ${CMAKE_COMMAND} -E copy_if_different
            "<BINARY_DIR>/bin/makemsix"
            "${UWP_HOST_SDK_INSTALL_DIR}/bin/makemsix"
    )
    ExternalProject_Add_StepTargets(msix-packaging install)
    set(UWP_MAKEAPPX_EXECUTABLE "${UWP_HOST_SDK_INSTALL_DIR}/bin/makemsix")
    set(UWP_MAKEAPPX_TARGET msix-packaging-install)

    find_program(UWP_HOST_CLANG_EXECUTABLE NAMES clang REQUIRED)
    find_program(UWP_HOST_CLANGXX_EXECUTABLE NAMES clang++ REQUIRED)
    ExternalProject_Add(
        makepri
        GIT_REPOSITORY https://github.com/trungnt2910/MakePri.git
        GIT_TAG master
        USES_TERMINAL_CONFIGURE TRUE
        USES_TERMINAL_BUILD TRUE
        USES_TERMINAL_INSTALL TRUE
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_C_COMPILER=${UWP_HOST_CLANG_EXECUTABLE}
            -DCMAKE_CXX_COMPILER=${UWP_HOST_CLANGXX_EXECUTABLE}
            -DCMAKE_CXX_FLAGS=-stdlib=libc++
            -DCMAKE_INSTALL_PREFIX=${UWP_HOST_SDK_INSTALL_DIR}
            -DBUILD_TESTING=FALSE
    )
    ExternalProject_Add_StepTargets(makepri install)
    set(UWP_MAKEPRI_EXECUTABLE "${UWP_HOST_SDK_INSTALL_DIR}/bin/makepri")
    set(UWP_MAKEPRI_TARGET makepri-install)
endif()

ExternalProject_Add(
    ccky
    GIT_REPOSITORY https://github.com/trungnt2910/SignToolPlayground.git
    GIT_TAG master
    USES_TERMINAL_CONFIGURE TRUE
    USES_TERMINAL_BUILD TRUE
    USES_TERMINAL_INSTALL TRUE
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=${UWP_HOST_SDK_INSTALL_DIR}
)
ExternalProject_Add_StepTargets(ccky install)
set(UWP_CCKY_EXECUTABLE "${UWP_HOST_SDK_INSTALL_DIR}/bin/ccky")
set(UWP_CCKY_TARGET ccky-install)

set(
    UWP_CONTRACTS_VERSION
    "10.0.17134.1000"
    CACHE STRING "The Microsoft.Windows.SDK.Contracts version used for generated C++/WinRT."
)
set(UWP_NUGET_API_BASE "https://www.nuget.org/api/v2/package")
ExternalProject_Add(
    microsoft-windows-sdk-contracts
    URL "${UWP_NUGET_API_BASE}/Microsoft.Windows.SDK.Contracts/${UWP_CONTRACTS_VERSION}"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    DEPENDS ${UWP_CPPWINRT_TARGET}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
        ${UWP_CPPWINRT_EXECUTABLE}
        -pch <BINARY_DIR>
        -input <SOURCE_DIR>/ref/netstandard2.0
        -output <BINARY_DIR>/include
    INSTALL_COMMAND
        ${CMAKE_COMMAND} -E copy_directory_if_newer
        <BINARY_DIR>/include
        ${UWP_HOST_SDK_INSTALL_DIR}/include
)
ExternalProject_Add_StepTargets(microsoft-windows-sdk-contracts install)
set(UWP_WINRT_INCLUDE_DIR "${UWP_HOST_SDK_INSTALL_DIR}/include")
set(UWP_WINRT_INCLUDE_TARGET microsoft-windows-sdk-contracts-install)
