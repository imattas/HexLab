#pragma once

#include <wx/display.h>
#include <wx/toplevel.h>

// Keep interactive GUI tests on the secondary display and avoid activating
// their top-level windows over the user's current application.
template <typename Window>
void show_test_window(Window *window) {
    if (wxDisplay::GetCount() > 1) {
        wxDisplay display(1);
        const auto area = display.GetClientArea();
        window->SetPosition({area.x + 16, area.y + 16});
    }
    window->ShowWithoutActivating();
}
