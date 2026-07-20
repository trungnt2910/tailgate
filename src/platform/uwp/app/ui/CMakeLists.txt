tailgate_uwp_add_library(
    Tailgate.Uwp.App.Ui
    STATIC
    AppResources.cpp
    AppResources.h
    ButtonFactory.cpp
    ButtonFactory.h
    Glyphs.h
    ResourceLoader.cpp
    ResourceLoader.h
    UiFactory.cpp
    UiFactory.h
)
target_link_libraries(Tailgate.Uwp.App.Ui PUBLIC Tailgate.Uwp.Common)
