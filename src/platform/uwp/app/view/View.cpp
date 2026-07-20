#include "app/view/View.h"

namespace tailgate::uwp
{

void View::Initialize()
{
    Render();
    OnStateChange("");
}

} // namespace tailgate::uwp
