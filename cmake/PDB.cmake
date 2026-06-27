function(tailgate_target_add_pdb target)
    if(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(pdb "$<TARGET_FILE_DIR:${target}>/$<TARGET_FILE_BASE_NAME:${target}>.pdb")
        target_compile_options(${target} PRIVATE -gcodeview)
        get_target_property(type ${target} TYPE)
        if(NOT type STREQUAL "STATIC_LIBRARY")
            target_link_options(${target} PRIVATE -Wl,--pdb=${pdb} -Wl,-s)
        endif()
        set_property(
            TARGET
            ${target}
            APPEND
            PROPERTY
            ADDITIONAL_CLEAN_FILES "${pdb}"
        )
    endif()
endfunction()

if(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    string(APPEND TAILGATE_THIRD_PARTY_COMPILE_FLAGS " -gcodeview")
endif()
