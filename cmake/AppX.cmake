include(CMakeParseArguments)

if(NOT UWP_APPX_ARCH)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        set(UWP_APPX_ARCH "x64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86|i686")
        set(UWP_APPX_ARCH "x86")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        set(UWP_APPX_ARCH "arm64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM|armv7")
        set(UWP_APPX_ARCH "arm")
    else()
        set(UWP_APPX_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
    endif()
endif()

function(uwp_configure_target name)
    target_include_directories(${name} PRIVATE ${UWP_WINRT_INCLUDE_DIR})
    add_dependencies(${name} ${UWP_WINRT_INCLUDE_TARGET})
    target_compile_definitions(${name} PRIVATE WINVER=0x0A00 _WIN32_WINNT=0x0A00)
    target_link_libraries(${name} PRIVATE ucrtapp windowsapp winstorecompat)
    target_link_options(${name} PRIVATE -static -Wl,--appcontainer)
endfunction()

function(uwp_add_executable name)
    set(options "")
    set(one_value_args "")
    set(multi_value_args SOURCES)
    cmake_parse_arguments(ARG "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    add_executable(${name} WIN32 ${ARG_SOURCES})
    set_target_properties(${name} PROPERTIES OUTPUT_NAME "${name}")
    uwp_configure_target(${name})
    target_link_options(${name} PRIVATE -municode)
endfunction()

function(uwp_add_library name)
    set(options "")
    set(one_value_args "")
    set(multi_value_args SOURCES)
    cmake_parse_arguments(ARG "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    add_library(${name} SHARED ${ARG_SOURCES})
    set_target_properties(${name} PROPERTIES OUTPUT_NAME "${name}" PREFIX "")
    uwp_configure_target(${name})
endfunction()

function(uwp_add_appx name)
    set(options "")
    set(one_value_args MANIFEST CERTIFICATE)
    set(multi_value_args FILE_RESOURCES RESOURCES)
    cmake_parse_arguments(ARG "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})

    set(appx_base "${CMAKE_CURRENT_BINARY_DIR}/${name}-appx")
    set(appx_manifest "${appx_base}/AppxManifest.xml")
    set(appx_input_files "${ARG_MANIFEST}" "${ARG_CERTIFICATE}")
    set(appx_dependencies "${UWP_MAKEAPPX_TARGET}" "${UWP_CCKY_TARGET}")
    set(appx_stage_commands
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${appx_base}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${appx_base}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${ARG_MANIFEST}" "${appx_manifest}"
    )

    set(resource_groups "")
    set(resource_arg_type "")
    foreach(resource_arg IN LISTS ARG_FILE_RESOURCES)
        if(resource_arg_type STREQUAL "SRC")
            set(group_src "${resource_arg}")
            set(resource_arg_type "")
        elseif(resource_arg_type STREQUAL "DST")
            set(group_dst "${resource_arg}")
            set(resource_arg_type "")
            string(MAKE_C_IDENTIFIER "${group_dst}" group_name)
            list(APPEND resource_groups "${group_name}")
            set(res_src_${group_name} "${group_src}")
            set(res_dst_${group_name} "${group_dst}")
            set(res_globs_${group_name} "")
        elseif(resource_arg STREQUAL "SRC")
            set(resource_arg_type "SRC")
        elseif(resource_arg STREQUAL "DST")
            set(resource_arg_type "DST")
        else()
            if(NOT group_src OR NOT group_dst)
                message(FATAL_ERROR "uwp_add_appx: files require SRC and DST first.")
            endif()
            string(MAKE_C_IDENTIFIER "${group_dst}" group_name)
            list(APPEND res_globs_${group_name} "${resource_arg}")
        endif()
    endforeach()

    foreach(group_name IN LISTS resource_groups)
        set(group_src "${res_src_${group_name}}")
        set(group_files "")
        foreach(glob IN LISTS res_globs_${group_name})
            if(IS_ABSOLUTE "${glob}")
                set(glob_path "${glob}")
            else()
                set(glob_path "${group_src}/${glob}")
            endif()
            file(GLOB glob_items CONFIGURE_DEPENDS "${glob_path}")
            list(APPEND group_files ${glob_items})
        endforeach()
        foreach(file_path IN LISTS group_files)
            cmake_path(
                RELATIVE_PATH file_path
                BASE_DIRECTORY "${group_src}"
                OUTPUT_VARIABLE relative_path
            )
            set(file_dst "${appx_base}/${res_dst_${group_name}}/${relative_path}")
            cmake_path(GET file_dst PARENT_PATH file_dst_directory)
            list(
                APPEND
                appx_stage_commands
                COMMAND ${CMAKE_COMMAND} -E make_directory "${file_dst_directory}"
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${file_path}" "${file_dst}"
            )
            list(APPEND appx_input_files "${file_path}")
        endforeach()
    endforeach()

    set(resource_dst ".")
    set(expect_resource_dst FALSE)
    foreach(resource_target IN LISTS ARG_RESOURCES)
        if(expect_resource_dst)
            set(resource_dst "${resource_target}")
            set(expect_resource_dst FALSE)
            continue()
        endif()
        if(resource_target STREQUAL "DST")
            set(expect_resource_dst TRUE)
            continue()
        endif()
        if(resource_dst STREQUAL ".")
            set(resource_output "${appx_base}/$<TARGET_FILE_NAME:${resource_target}>")
        else()
            set(resource_output
                "${appx_base}/${resource_dst}/$<TARGET_FILE_NAME:${resource_target}>"
            )
            list(
                APPEND
                appx_stage_commands
                COMMAND ${CMAKE_COMMAND} -E make_directory "${appx_base}/${resource_dst}"
            )
        endif()
        list(
            APPEND
            appx_stage_commands
            COMMAND
                ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:${resource_target}>"
                "${resource_output}"
        )
        list(APPEND appx_dependencies "${resource_target}")
    endforeach()
    if(expect_resource_dst)
        message(FATAL_ERROR "uwp_add_appx: RESOURCES DST requires a value.")
    endif()

    set(appx_output "${CMAKE_CURRENT_BINARY_DIR}/${name}.appx")
    set(appx_cer "${CMAKE_CURRENT_BINARY_DIR}/${name}.cer")
    add_custom_target(
        ${name}-appx
        ALL
        ${appx_stage_commands}
        COMMAND ${CMAKE_COMMAND} -E rm -f "${appx_output}"
        COMMAND "${UWP_MAKEAPPX_EXECUTABLE}" pack -d "${appx_base}" -p "${appx_output}"
        COMMAND
            ${UWP_CCKY_EXECUTABLE} signtool sign
            /fd SHA256
            /f "${ARG_CERTIFICATE}"
            "${appx_output}"
        COMMAND ${UWP_CCKY_EXECUTABLE} certmgr /put /c "${appx_output}" "${appx_cer}"
        DEPENDS ${appx_dependencies} ${appx_input_files}
    )
    set_target_properties(
        ${name}-appx PROPERTIES ADDITIONAL_CLEAN_FILES "${appx_base};${appx_output};${appx_cer}"
    )
endfunction()

function(uwp_install_appx name)
    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/${name}.appx"
            "${CMAKE_CURRENT_BINARY_DIR}/${name}.cer"
        DESTINATION "."
    )
endfunction()
