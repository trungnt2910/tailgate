tailgate_add_library(
    tailgate_core_qr
    STATIC
    QrCode.cpp
)
target_link_libraries(tailgate_core_qr PRIVATE zint-static)
