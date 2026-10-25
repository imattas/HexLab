#pragma once

#include <wx/panel.h>
#include <wx/timer.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <cstdint>
#include <string>
#include <utility>

class wxButton;
class wxTextCtrl;

namespace hexlab::desktop {

class PythonConsolePanel final : public wxPanel {
public:
    using ActiveProjectBinding = std::pair<std::filesystem::path, std::uint64_t>;
    using ActiveProjectProvider = std::function<std::optional<ActiveProjectBinding>()>;

    PythonConsolePanel(wxWindow *parent, ActiveProjectProvider active_project_provider);
    ~PythonConsolePanel() override;

private:
    struct Worker;
    void run_input();
    void cancel_input();
    void poll_worker(wxTimerEvent &);
    void append_output(const std::string &text);

    ActiveProjectProvider active_project_provider_;
    std::unique_ptr<Worker> worker_;
    wxTextCtrl *output_ = nullptr;
    wxTextCtrl *input_ = nullptr;
    wxButton *run_ = nullptr;
    wxButton *cancel_ = nullptr;
    wxTimer timer_;
    std::optional<ActiveProjectBinding> bound_project_;
    wxString output_cache_;
};

} // namespace hexlab::desktop
