tailgate_add_library(tailgate_cli STATIC Application.cpp Arguments.cpp)
target_link_libraries(tailgate_cli PRIVATE CLI11::CLI11 nlohmann_json::nlohmann_json)
