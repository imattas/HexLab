#include "python_console.hpp"
#include "python_internal.hpp"
#include "facade.hpp"

#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <stop_token>
#include <thread>
#include <utility>
#include <vector>

namespace hexlab::desktop {
namespace {
constexpr std::size_t max_input_bytes = 1024 * 1024;
constexpr std::size_t max_queued_commands = 32;
constexpr std::size_t max_queued_output_bytes = 512 * 1024;
constexpr std::size_t max_visible_output_chars = 256 * 1024;
constexpr const char *trace_capsule_name = "hexlab.desktop.PythonConsoleInterrupt";

struct InterruptState {
    std::atomic<bool> canceled{false};
    std::atomic<bool> shutting_down{false};
};

constexpr const char *bootstrap = R"PY(
import ast
import sys
class _HexLabConsoleWriter:
    def __init__(self, limit):
        self.limit = limit
        self.reset()
    def reset(self):
        self.parts = []
        self.size = 0
        self.dropped = 0
    def write(self, value):
        value = str(value)
        encoded = value.encode('utf-8', 'replace')
        room = max(0, self.limit - self.size)
        if room:
            part = encoded[:room].decode('utf-8', 'ignore')
            self.parts.append(part)
            used = len(part.encode('utf-8'))
            self.size += used
        else:
            used = 0
        self.dropped += len(encoded) - used
        return len(value)
    def flush(self):
        pass
    def getvalue(self):
        value = ''.join(self.parts)
        if self.dropped:
            value += '\n[HexLab truncated ' + str(self.dropped) + ' output bytes]\n'
        return value
_hexlab_console_writer = _HexLabConsoleWriter(262000)
project = None
def _hexlab_console_execute(source):
    tree = ast.parse(source, '<HexLab Console>', 'exec')
    if tree.body and isinstance(tree.body[-1], ast.Expr):
        expression = tree.body.pop()
        if tree.body:
            body = ast.fix_missing_locations(ast.Module(body=tree.body, type_ignores=tree.type_ignores))
            exec(compile(body, '<HexLab Console>', 'exec'), globals(), globals())
        value = eval(compile(ast.Expression(body=expression.value), '<HexLab Console>', 'eval'), globals(), globals())
        if value is not None:
            print(repr(value))
    else:
        exec(compile(tree, '<HexLab Console>', 'exec'), globals(), globals())
)PY";

struct Command {
    enum class Kind { execute, bind_project } kind = Kind::execute;
    std::string source;
    std::optional<std::pair<std::filesystem::path, std::uint64_t>> project_binding;
};

std::string to_utf8(const wxString &value) {
    const auto buffer = value.utf8_str();
    return buffer ? std::string(buffer.data(), buffer.length()) : std::string{};
}

std::string path_utf8(const std::filesystem::path &path) {
    const auto value = path.u8string();
    return std::string(reinterpret_cast<const char *>(value.data()), value.size());
}

int interrupt_trace(PyObject *capsule, PyFrameObject *, int, PyObject *) {
    auto *state = static_cast<InterruptState *>(PyCapsule_GetPointer(capsule, trace_capsule_name));
    if (!state) {
        PyErr_Clear();
        return 0;
    }
    if (state->canceled.load(std::memory_order_relaxed) ||
        state->shutting_down.load(std::memory_order_relaxed)) {
        PyErr_SetString(PyExc_KeyboardInterrupt, "HexLab Python operation canceled");
        return -1;
    }
    return 0;
}

void discard_python_error() {
    if (PyErr_Occurred()) PyErr_Clear();
}

PyObject *call_no_args(PyObject *instance, const char *name) {
    PyObject *method = PyObject_GetAttrString(instance, name);
    if (!method) return nullptr;
    PyObject *result = PyObject_CallNoArgs(method);
    Py_DECREF(method);
    return result;
}

} // namespace

struct PythonConsolePanel::Worker {
    std::mutex mutex;
    std::condition_variable_any ready;
    std::deque<Command> commands;
    std::deque<std::string> output;
    std::size_t queued_output_bytes = 0;
    std::jthread thread;
    InterruptState interruption;
    std::atomic<bool> running{false};
    std::shared_ptr<std::stop_source> current_stop_source;

    Worker() : thread([this](std::stop_token stop) { run(stop); }) {}

    ~Worker() {
        interruption.shutting_down.store(true, std::memory_order_relaxed);
        interruption.canceled.store(true, std::memory_order_relaxed);
        request_native_stop();
        thread.request_stop();
        ready.notify_all();
        if (thread.joinable()) thread.join();
    }

    void post(Command command) {
        std::string rejection;
        {
            std::lock_guard lock(mutex);
            if (commands.size() >= max_queued_commands)
                rejection = "Console command queue is full; wait for the running command to finish.\n";
            else if (command.kind == Command::Kind::execute && command.source.size() > max_input_bytes)
                rejection = "Console input exceeds the 1 MiB command limit.\n";
            else {
                commands.push_back(std::move(command));
                ready.notify_one();
            }
        }
        if (!rejection.empty()) queue_output(std::move(rejection));
    }

    void bind_project(std::optional<std::pair<std::filesystem::path, std::uint64_t>> binding) {
        post(Command{Command::Kind::bind_project, {}, std::move(binding)});
    }

    void submit(std::string source) {
        post(Command{Command::Kind::execute, std::move(source), {}});
    }

    void cancel() {
        if (!running.load(std::memory_order_relaxed)) return;
        interruption.canceled.store(true, std::memory_order_relaxed);
        request_native_stop();
    }

    void request_native_stop() {
        std::shared_ptr<std::stop_source> source;
        {
            std::lock_guard lock(mutex);
            source = current_stop_source;
        }
        if (source) source->request_stop();
    }

    std::vector<std::string> drain_output() {
        std::lock_guard lock(mutex);
        std::vector<std::string> result;
        result.reserve(output.size());
        while (!output.empty()) {
            queued_output_bytes -= output.front().size();
            result.push_back(std::move(output.front()));
            output.pop_front();
        }
        return result;
    }

    void queue_output(std::string value) {
        std::lock_guard lock(mutex);
        if (value.size() > max_queued_output_bytes) {
            value.erase(0, value.size() - max_queued_output_bytes);
            while (!value.empty() &&
                   (static_cast<unsigned char>(value.front()) & 0xc0u) == 0x80u)
                value.erase(value.begin());
        }
        while (!output.empty() && queued_output_bytes + value.size() > max_queued_output_bytes) {
            queued_output_bytes -= output.front().size();
            output.pop_front();
        }
        queued_output_bytes += value.size();
        output.push_back(std::move(value));
    }

    bool initialize_python(PyObject *&globals, PyObject *&writer,
                           PyObject *&saved_stdout, PyObject *&saved_stderr) {
        static std::once_flag module_registration;
        static bool registered = false;
        std::call_once(module_registration, [] { registered = PyImport_AppendInittab("_hexlab", PyInit__hexlab) == 0; });
        if (!registered) {
            queue_output("Could not register HexLab's native Python module.\n");
            return false;
        }

        PyConfig config;
        PyConfig_InitPythonConfig(&config);
        config.parse_argv = 0;
        config.write_bytecode = 0;
        config.install_signal_handlers = 0;
        const auto status = Py_InitializeFromConfig(&config);
        PyConfig_Clear(&config);
        if (PyStatus_Exception(status)) {
            queue_output(std::string("Python initialization failed: ") +
                         (status.err_msg ? status.err_msg : "unknown error") + "\n");
            return false;
        }

        PyObject *native = PyImport_ImportModule("_hexlab");
        if (!native) {
            PyErr_Print();
            queue_output("Could not import HexLab's native Python module.\n");
            return false;
        }
        Py_DECREF(native);

        PyObject *module = PyModule_New("hexlab");
        if (!module || PyDict_SetItemString(PyImport_GetModuleDict(), "hexlab", module) < 0) {
            Py_XDECREF(module);
            PyErr_Print();
            queue_output("Could not initialize the HexLab Python facade.\n");
            return false;
        }
        PyObject *facade = PyRun_String(hexlab_python_facade, Py_file_input,
                                        PyModule_GetDict(module), PyModule_GetDict(module));
        Py_XDECREF(facade);
        Py_DECREF(module);
        if (!facade) {
            PyErr_Print();
            queue_output("Could not load the HexLab Python facade.\n");
            return false;
        }

        PyObject *main_module = PyImport_AddModule("__main__");
        if (!main_module) return false;
        globals = PyModule_GetDict(main_module);
        Py_INCREF(globals);
        PyObject *initialized = PyRun_String(bootstrap, Py_file_input, globals, globals);
        if (!initialized) {
            PyErr_Print();
            queue_output("Could not initialize the bounded Python console.\n");
            return false;
        }
        Py_DECREF(initialized);
        writer = PyDict_GetItemString(globals, "_hexlab_console_writer");
        Py_XINCREF(writer);
        saved_stdout = PySys_GetObject("stdout");
        saved_stderr = PySys_GetObject("stderr");
        Py_XINCREF(saved_stdout);
        Py_XINCREF(saved_stderr);
        queue_output("HexLab Python console ready. `project` is read-only; edit through the desktop.\n");
        return writer && saved_stdout && saved_stderr;
    }

    void bind_project_on_worker(const std::optional<std::pair<std::filesystem::path, std::uint64_t>> &binding,
                                PyObject *globals, PyObject *&bound_project,
                                std::optional<std::pair<std::filesystem::path, std::uint64_t>> &bound_binding) {
        if (bound_binding == binding) return;
        if (bound_project) {
            PyObject *closed = call_no_args(bound_project, "close");
            Py_XDECREF(closed);
            discard_python_error();
            Py_DECREF(bound_project);
            bound_project = nullptr;
        }
        bound_binding = binding;
        if (!binding) {
            PyDict_SetItemString(globals, "project", Py_None);
            queue_output("No saved project is active; `project` is None.\n");
            return;
        }

        PyObject *module = PyImport_ImportModule("hexlab");
        PyObject *project_type = module ? PyObject_GetAttrString(module, "Project") : nullptr;
        PyObject *open = project_type ? PyObject_GetAttrString(project_type, "open") : nullptr;
        const auto &path = binding->first;
        const auto path_text = path_utf8(path);
        PyObject *path_value = PyUnicode_DecodeUTF8(path_text.data(),
                                                     static_cast<Py_ssize_t>(path_text.size()), "strict");
        PyObject *args = path_value ? PyTuple_Pack(1, path_value) : nullptr;
        PyObject *kwargs = Py_BuildValue("{s:O}", "readonly", Py_True);
        PyObject *opened = open && args && kwargs ? PyObject_Call(open, args, kwargs) : nullptr;
        Py_XDECREF(kwargs);
        Py_XDECREF(args);
        Py_XDECREF(path_value);
        Py_XDECREF(open);
        Py_XDECREF(project_type);
        Py_XDECREF(module);
        if (!opened) {
            PyErr_Print();
            PyDict_SetItemString(globals, "project", Py_None);
            queue_output("Could not attach the read-only automation facade to the active project.\n");
            return;
        }
        bound_project = opened;
        PyDict_SetItemString(globals, "project", bound_project);
        queue_output("Attached to the last saved project snapshot (read-only): " + path_utf8(path) + ". Save project edits to refresh this view.\n");
    }

    void execute_on_worker(const std::string &source, PyObject *globals, PyObject *writer,
                           PyObject *saved_stdout, PyObject *saved_stderr) {
        PyObject *reset = call_no_args(writer, "reset");
        if (!reset) {
            PyErr_Print();
            queue_output("Could not prepare console output capture.\n");
            return;
        }
        Py_DECREF(reset);
        PySys_SetObject("stdout", writer);
        PySys_SetObject("stderr", writer);

        auto native_stop = std::make_shared<std::stop_source>();
        {
            std::lock_guard lock(mutex);
            current_stop_source = native_stop;
        }
        PyObject *native_capsule = hexlab::automation::python::make_stop_source_capsule(native_stop);
        PyObject *hexlab_module = PyImport_ImportModule("hexlab");
        PyObject *token_type = hexlab_module ? PyObject_GetAttrString(hexlab_module, "CancellationToken") : nullptr;
        PyObject *from_handle = token_type ? PyObject_GetAttrString(token_type, "_from_handle") : nullptr;
        PyObject *token = nullptr;
        if (native_capsule && from_handle)
            token = PyObject_CallFunctionObjArgs(from_handle, native_capsule, nullptr);
        Py_XDECREF(native_capsule);
        Py_XDECREF(from_handle);
        Py_XDECREF(token_type);
        if (!token || !hexlab_module || PyObject_SetAttrString(
                hexlab_module, "_hexlab_console_cancellation_token", token) < 0) {
            PyErr_Print();
            Py_XDECREF(token);
            Py_XDECREF(hexlab_module);
            {
                std::lock_guard lock(mutex);
                if (current_stop_source == native_stop) current_stop_source.reset();
            }
            PySys_SetObject("stdout", saved_stdout);
            PySys_SetObject("stderr", saved_stderr);
            queue_output("Could not create the command cancellation token.\n");
            return;
        }
        PyDict_SetItemString(globals, "_hexlab_console_cancellation_token", token);

        PyObject *trace_token = PyCapsule_New(&interruption, trace_capsule_name, nullptr);
        if (trace_token) PyEval_SetTrace(interrupt_trace, trace_token);
        interruption.canceled.store(false, std::memory_order_relaxed);
        running.store(true, std::memory_order_relaxed);
        PyObject *source_value = PyUnicode_DecodeUTF8(source.data(),
            static_cast<Py_ssize_t>(source.size()), "strict");
        PyObject *execute = PyDict_GetItemString(globals, "_hexlab_console_execute");
        PyObject *result = source_value && execute
            ? PyObject_CallFunctionObjArgs(execute, source_value, nullptr) : nullptr;
        Py_XDECREF(source_value);
        running.store(false, std::memory_order_relaxed);
        PyEval_SetTrace(nullptr, nullptr);
        Py_XDECREF(trace_token);
        if (result) Py_DECREF(result);
        else PyErr_PrintEx(0);
        interruption.canceled.store(false, std::memory_order_relaxed);
        {
            std::lock_guard lock(mutex);
            if (current_stop_source == native_stop) current_stop_source.reset();
        }

        PySys_SetObject("stdout", saved_stdout);
        PySys_SetObject("stderr", saved_stderr);
        PyObject *value = call_no_args(writer, "getvalue");
        if (!value) {
            PyErr_Print();
            queue_output("Could not collect console output.\n");
            return;
        }
        if (PyUnicode_Check(value)) {
            Py_ssize_t length = 0;
            const char *data = PyUnicode_AsUTF8AndSize(value, &length);
            if (data && length > 0) queue_output(std::string(data, static_cast<std::size_t>(length)));
        }
        Py_XDECREF(value);
        Py_XDECREF(token);
        Py_XDECREF(hexlab_module);
    }

    void run(std::stop_token stop) {
        PyObject *globals = nullptr, *writer = nullptr, *saved_stdout = nullptr, *saved_stderr = nullptr;
        bool initialized = initialize_python(globals, writer, saved_stdout, saved_stderr);
        std::optional<std::pair<std::filesystem::path, std::uint64_t>> bound_binding;
        PyObject *bound_project = nullptr;
        while (!stop.stop_requested()) {
            Command command;
            {
                std::unique_lock lock(mutex);
                ready.wait(lock, stop, [&] { return !commands.empty(); });
                if (stop.stop_requested()) break;
                if (commands.empty()) continue;
                command = std::move(commands.front());
                commands.pop_front();
            }
            if (!initialized) continue;
            if (command.kind == Command::Kind::bind_project)
                bind_project_on_worker(command.project_binding, globals, bound_project, bound_binding);
            else
                execute_on_worker(command.source, globals, writer, saved_stdout, saved_stderr);
        }
        if (initialized) {
            interruption.canceled.store(false, std::memory_order_relaxed);
            if (bound_project) {
                PyObject *closed = call_no_args(bound_project, "close");
                Py_XDECREF(closed);
                discard_python_error();
                Py_DECREF(bound_project);
            }
            Py_XDECREF(writer);
            Py_XDECREF(saved_stdout);
            Py_XDECREF(saved_stderr);
            Py_XDECREF(globals);
            Py_FinalizeEx();
        } else if (Py_IsInitialized()) {
            Py_FinalizeEx();
        }
    }
};

PythonConsolePanel::PythonConsolePanel(wxWindow *parent, ActiveProjectProvider active_project_provider)
    : wxPanel(parent), active_project_provider_(std::move(active_project_provider)),
      worker_(std::make_unique<Worker>()), timer_(this) {
    auto *layout = new wxBoxSizer(wxVERTICAL);
    output_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                             wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    output_->SetName("python-console-output");
    input_ = new wxTextCtrl(this, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize,
                            wxTE_MULTILINE | wxTE_PROCESS_TAB);
    input_->SetName("python-console-input");
    input_->SetHint("Enter Python; use Ctrl+Enter to run a multiline block");
    auto *controls = new wxBoxSizer(wxHORIZONTAL);
    controls->Add(new wxStaticText(this, wxID_ANY, "Python"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(6));
    controls->Add(input_, 1, wxEXPAND | wxRIGHT, FromDIP(6));
    run_ = new wxButton(this, wxID_ANY, "Run");
    cancel_ = new wxButton(this, wxID_ANY, "Cancel");
    cancel_->Disable();
    controls->Add(run_, 0, wxRIGHT, FromDIP(4));
    controls->Add(cancel_, 0);
    layout->Add(output_, 1, wxEXPAND | wxALL, FromDIP(4));
    layout->Add(controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(4));
    SetSizer(layout);

    run_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { run_input(); });
    cancel_->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { cancel_input(); });
    input_->Bind(wxEVT_CHAR_HOOK, [this](wxKeyEvent &event) {
        if (event.GetKeyCode() == WXK_RETURN && event.ControlDown()) {
            run_input();
            return;
        }
        event.Skip();
    });
    Bind(wxEVT_TIMER, &PythonConsolePanel::poll_worker, this);
    timer_.Start(75);
}

PythonConsolePanel::~PythonConsolePanel() {
    timer_.Stop();
    worker_.reset();
}

void PythonConsolePanel::run_input() {
    const auto text = input_->GetValue();
    const auto source = to_utf8(text);
    if (source.empty()) return;
    append_output(">>> " + source + (source.back() == '\n' ? "" : "\n"));
    worker_->submit(source);
    input_->Clear();
    cancel_->Enable();
}

void PythonConsolePanel::cancel_input() {
    worker_->cancel();
}

void PythonConsolePanel::poll_worker(wxTimerEvent &) {
    if (active_project_provider_) {
        auto current_binding = active_project_provider_();
        if (current_binding != bound_project_) {
            bound_project_ = current_binding;
            worker_->bind_project(std::move(current_binding));
        }
    }
    const auto pending = worker_->drain_output();
    for (const auto &part : pending) append_output(part);
    cancel_->Enable(worker_->running.load(std::memory_order_relaxed));
}

void PythonConsolePanel::append_output(const std::string &text) {
    if (text.empty()) return;
    output_cache_ += wxString::FromUTF8(text.data(), text.size());
    if (output_cache_.length() > max_visible_output_chars)
        output_cache_.erase(0, output_cache_.length() - max_visible_output_chars);
    output_->ChangeValue(output_cache_);
    output_->ShowPosition(output_->GetLastPosition());
}

} // namespace hexlab::desktop

