tailgate_add_library(
    tailgate_core_net_http
    STATIC
    Client.cpp
    Message.cpp
    MessageEncoder.cpp
    MessageParser.cpp
)

if(TAILGATE_ARCH STREQUAL "i686")
    # Post-RA machine sinking can clobber the exception pointer in MessageParser::Decode.
    # See https://github.com/llvm/llvm-project/issues/224802.
    target_compile_options(tailgate_core_net_http PRIVATE -mllvm=-disable-postra-machine-sink)
endif()

add_subdirectory(impl)
