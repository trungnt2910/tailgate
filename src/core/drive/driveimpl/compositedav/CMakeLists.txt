tailgate_add_library(
    tailgate_core_drive_driveimpl_compositedav
    STATIC
    CollectionResponse.cpp
    IfHeader.cpp
    Path.cpp
    PathMapping.cpp
    XmlRewriter.cpp
    XmlRewriterFactoryImpl.cpp
    XmlRewriterImpl.cpp
)
target_link_libraries(
    tailgate_core_drive_driveimpl_compositedav
    PUBLIC tailgate_core_crypto
    PRIVATE Boost::url expat::expat
)
