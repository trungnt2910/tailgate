tailgate_add_test_library(
    tailgate_tests_core_drive
    Given_CollectionReader.cpp
    Given_DavIfHeader.cpp
    Given_DavPath.cpp
    Given_DavXmlRewriter.cpp
    Given_DirectoryFileSystem.cpp
    Given_DriveFileSystem.cpp
    Given_DriveRemotes.cpp
    Given_XmlRewriterFactory.cpp
)
target_link_libraries(tailgate_tests_core_drive PRIVATE tailgate_core tailgate_tests_core_fakes)
target_include_directories(tailgate_tests_core_drive PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
