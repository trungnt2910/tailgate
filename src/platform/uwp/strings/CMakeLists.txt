include(CMakeParseArguments)

set_property(GLOBAL PROPERTY TAILGATE_UWP_RESOURCE_KEYS "")

function(_tailgate_register_resource_string key arity value)
    if(NOT key MATCHES "^[A-Za-z][A-Za-z0-9]*_[A-Za-z][A-Za-z0-9]*$")
        message(
            FATAL_ERROR
            "Resource key '${key}' must contain one group separator and valid C++ identifiers."
        )
    endif()

    get_property(resource_keys GLOBAL PROPERTY TAILGATE_UWP_RESOURCE_KEYS)
    if(key IN_LIST resource_keys)
        message(FATAL_ERROR "Duplicate resource key '${key}'.")
    endif()

    if(NOT arity STREQUAL "" AND NOT arity MATCHES "^[1-9][0-9]*$")
        message(FATAL_ERROR "Resource '${key}' has invalid format arity '${arity}'.")
    endif()

    set_property(GLOBAL APPEND PROPERTY TAILGATE_UWP_RESOURCE_KEYS "${key}")
    set_property(GLOBAL PROPERTY "TAILGATE_UWP_RESOURCE_${key}_ARITY" "${arity}")
    set_property(GLOBAL PROPERTY "TAILGATE_UWP_RESOURCE_${key}_VALUE" "${value}")
endfunction()

function(tailgate_resource_string key)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "" "VALUE" "")
    if(NOT DEFINED ARG_VALUE)
        message(FATAL_ERROR "tailgate_resource_string(${key}) requires VALUE.")
    endif()

    _tailgate_register_resource_string("${key}" "" "${ARG_VALUE}")
endfunction()

function(tailgate_resource_format_string key)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "" "ARITY;VALUE" "")
    if(NOT DEFINED ARG_ARITY OR NOT DEFINED ARG_VALUE)
        message(
            FATAL_ERROR
            "tailgate_resource_format_string(${key}) requires ARITY and VALUE."
        )
    endif()

    _tailgate_register_resource_string("${key}" "${ARG_ARITY}" "${ARG_VALUE}")
endfunction()

function(_tailgate_xml_escape output value)
    string(REPLACE "&" "&amp;" escaped "${value}")
    string(REPLACE "<" "&lt;" escaped "${escaped}")
    string(REPLACE ">" "&gt;" escaped "${escaped}")
    set(${output} "${escaped}" PARENT_SCOPE)
endfunction()

function(tailgate_generate_resources)
    set(one_value_args HEADER_TEMPLATE HEADER_OUTPUT RESW_TEMPLATE RESW_OUTPUT)
    cmake_parse_arguments(PARSE_ARGV 0 ARG "" "${one_value_args}" "")
    foreach(argument IN LISTS one_value_args)
        if(NOT DEFINED ARG_${argument})
            message(FATAL_ERROR "tailgate_generate_resources requires ${argument}.")
        endif()
    endforeach()

    get_property(resource_keys GLOBAL PROPERTY TAILGATE_UWP_RESOURCE_KEYS)
    if(NOT resource_keys)
        message(FATAL_ERROR "No UWP string resources were declared.")
    endif()

    set(resource_groups "")
    set(TAILGATE_RESOURCE_RESW_ENTRIES "")
    foreach(key IN LISTS resource_keys)
        string(FIND "${key}" "_" separator)
        string(SUBSTRING "${key}" 0 ${separator} group)
        math(EXPR member_start "${separator} + 1")
        string(SUBSTRING "${key}" ${member_start} -1 member)
        if(NOT group IN_LIST resource_groups)
            list(APPEND resource_groups "${group}")
        endif()

        get_property(
            resource_arity
            GLOBAL
            PROPERTY "TAILGATE_UWP_RESOURCE_${key}_ARITY"
        )
        get_property(
            resource_value
            GLOBAL
            PROPERTY "TAILGATE_UWP_RESOURCE_${key}_VALUE"
        )
        _tailgate_xml_escape(resource_value_xml "${resource_value}")
        string(
            APPEND
            TAILGATE_RESOURCE_RESW_ENTRIES
            "  <data name=\"${key}\" xml:space=\"preserve\">\n"
            "    <value>${resource_value_xml}</value>\n"
            "  </data>\n"
        )

        if(resource_arity STREQUAL "")
            set(resource_type "ResourceKey")
        else()
            set(resource_type "ResourceFormatKey<${resource_arity}>")
        endif()
        set(group_content_variable "TAILGATE_RESOURCE_CPP_${group}")
        string(
            APPEND
            ${group_content_variable}
            "        inline static constexpr ${resource_type} ${member} { .Name = L\"${key}\" };\n"
        )
    endforeach()

    set(TAILGATE_RESOURCE_CPP_ENTRIES "")
    foreach(group IN LISTS resource_groups)
        string(
            APPEND
            TAILGATE_RESOURCE_CPP_ENTRIES
            "    struct ${group} final\n"
            "    {\n"
            "${TAILGATE_RESOURCE_CPP_${group}}"
            "    };\n\n"
        )
    endforeach()

    cmake_path(GET ARG_HEADER_OUTPUT PARENT_PATH header_output_directory)
    cmake_path(GET ARG_RESW_OUTPUT PARENT_PATH resw_output_directory)
    file(MAKE_DIRECTORY "${header_output_directory}" "${resw_output_directory}")
    configure_file("${ARG_HEADER_TEMPLATE}" "${ARG_HEADER_OUTPUT}" @ONLY)
    configure_file("${ARG_RESW_TEMPLATE}" "${ARG_RESW_OUTPUT}" @ONLY)
endfunction()

include(Resources.cmake)

set(TAILGATE_UWP_GENERATED_RESW
    "${CMAKE_CURRENT_BINARY_DIR}/pri/Strings/en-US/Resources.resw"
)
set(TAILGATE_UWP_PRI_CONFIG "${CMAKE_CURRENT_BINARY_DIR}/priconfig.xml")
set(TAILGATE_UWP_PRI "${CMAKE_CURRENT_BINARY_DIR}/resources.pri")
tailgate_generate_resources(
    HEADER_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/Resources.h.in"
    HEADER_OUTPUT "${TAILGATE_UWP_GENERATED_DIR}/strings/Resources.h"
    RESW_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/Resources.resw.in"
    RESW_OUTPUT "${TAILGATE_UWP_GENERATED_RESW}"
)
add_custom_command(
    OUTPUT "${TAILGATE_UWP_PRI}"
    BYPRODUCTS "${TAILGATE_UWP_PRI_CONFIG}"
    COMMAND
        "${UWP_MAKEPRI_EXECUTABLE}" createconfig
        -cf "${TAILGATE_UWP_PRI_CONFIG}"
        -dq en-US
        -pv 10.0.0
        -o
    COMMAND
        "${UWP_MAKEPRI_EXECUTABLE}" new
        -pr "${CMAKE_CURRENT_BINARY_DIR}/pri"
        -cf "${TAILGATE_UWP_PRI_CONFIG}"
        -mn "${TAILGATE_UWP_MANIFEST}"
        -of "${TAILGATE_UWP_PRI}"
        -o
    DEPENDS
        "${TAILGATE_UWP_GENERATED_RESW}"
        "${TAILGATE_UWP_MANIFEST}"
        ${UWP_MAKEPRI_TARGET}
    COMMENT "Compiling UWP string resources"
    VERBATIM
)
add_custom_target(Tailgate.Strings.Generated DEPENDS "${TAILGATE_UWP_PRI}")
add_library(Tailgate.Strings UNKNOWN IMPORTED GLOBAL)
set_target_properties(
    Tailgate.Strings
    PROPERTIES IMPORTED_LOCATION "${TAILGATE_UWP_PRI}"
)
add_dependencies(Tailgate.Strings Tailgate.Strings.Generated)
