#include "edge-gamma-core.h"

constexpr wchar_t title[] = L"Fuck sRGB";
constexpr wchar_t windowClass[] = L"Codex.SdrGamma.Tray.1";
constexpr UINT trayId = 1;
constexpr UINT iconMessage = WM_APP + 1;
constexpr UINT doneMessage = WM_APP + 2;
constexpr UINT firstMode = 100;
constexpr UINT exitCommand = 110;
constexpr UINT iconResource = 101;
constexpr const wchar_t* modes[] = {
    L"Native", L"Gamma2.2", L"Gamma2.4", L"Linear"
};
static_assert(ARRAYSIZE(modes) == selectableCount);

enum class HdrState { Unavailable, Inactive, Active };

HdrState detectHdr() noexcept {
    try {
        return allActiveDisplaysHdr() ? HdrState::Active : HdrState::Inactive;
    } catch (...) {
        return HdrState::Unavailable;
    }
}

std::wstring errorText(Failure failure) {
    wchar_t code[32];
    swprintf_s(code, L"\nError code 0x%08lX", failure.code);
    return std::wstring(failure.operation) + code;
}

class Tray {
public:
    explicit Tray(HINSTANCE instance) : icon_(LoadIconW(instance, MAKEINTRESOURCEW(iconResource))) {
        if (!icon_) fail(L"Load tray icon");
    }

    int run(HINSTANCE instance) {
        taskbarCreated_ = RegisterWindowMessageW(L"TaskbarCreated");
        if (!taskbarCreated_) fail(L"Register taskbar message");

        WNDCLASSW wc{};
        wc.hInstance = instance;
        wc.lpfnWndProc = procedure;
        wc.lpszClassName = windowClass;
        wc.hIcon = icon_;
        if (!RegisterClassW(&wc)) fail(L"Register tray window class");
        hwnd_ = CreateWindowExW(WS_EX_TOOLWINDOW, windowClass, title, WS_POPUP,
                                0, 0, 0, 0, nullptr, nullptr, instance, this);
        if (!hwnd_) fail(L"Create tray window");

        if (!ChangeWindowMessageFilterEx(hwnd_, iconMessage, MSGFLT_ALLOW, nullptr) ||
            !ChangeWindowMessageFilterEx(hwnd_, taskbarCreated_, MSGFLT_ALLOW, nullptr))
            fail(L"Connect to the Windows taskbar");
        hdr_ = detectHdr();
        if (!refresh() && hdr_ == HdrState::Active)
            MessageBoxW(nullptr, error_.c_str(), title, MB_OK | MB_ICONWARNING);
        if (!addIcon()) fail(L"Add tray icon");
        if (!SetTimer(hwnd_, 1, 2000, nullptr)) fail(L"Start display monitoring");
        startWork(current_.mode, false);

        MSG msg{};
        int status;
        while ((status = GetMessageW(&msg, nullptr, 0, 0)) > 0) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (status < 0) fail(L"Read window messages");
        return 0;
    }

    ~Tray() {
        if (worker_.joinable()) worker_.join();
        if (hwnd_ && IsWindow(hwnd_)) DestroyWindow(hwnd_);
    }

private:
    HWND hwnd_{};
    HICON icon_{};
    UINT taskbarCreated_{};
    Patcher patcher_;
    EdgeSync edge_{patcher_.session};
    Current current_{};
    Current result_{};
    HdrState hdr_ = HdrState::Unavailable;
    bool busy_ = false;
    bool switching_ = false;
    EdgeSyncStatus edgeStatus_{};
    EdgeSyncStatus edgeResult_{};
    bool edgeError_ = false, edgeResultError_ = false;
    std::wstring error_, workerError_;
    std::thread worker_;

    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
        if (message == WM_NCCREATE) {
            const auto creation = reinterpret_cast<CREATESTRUCTW*>(lp);
            auto* tray = static_cast<Tray*>(creation->lpCreateParams);
            tray->hwnd_ = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(tray));
        }
        auto* tray = reinterpret_cast<Tray*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        return tray ? tray->onMessage(message, wp, lp) : DefWindowProcW(hwnd, message, wp, lp);
    }

    NOTIFYICONDATAW data() const {
        NOTIFYICONDATAW info{};
        info.cbSize = sizeof(info);
        info.hWnd = hwnd_;
        info.uID = trayId;
        return info;
    }

    void tooltip(NOTIFYICONDATAW& info) const {
        const wchar_t* status = L"Checking DWM";
        if (hdr_ == HdrState::Inactive) status = L"HDR inactive";
        else if (hdr_ == HdrState::Unavailable) status = L"HDR status unavailable";
        else if (switching_) status = L"Applying gamma";
        else if (!error_.empty()) status = L"DWM verification failed";
        else if (index(current_.mode) < selectableCount) status = modes[index(current_.mode)];
        else if (current_.mode == Mode::LegacyGamma26) status = L"Legacy gamma active";
        const wchar_t* edge = L"";
        if (hdr_ == HdrState::Active) {
            if (edgeError_ || edgeStatus_.skipped) edge = L" | Edge sync incomplete";
            else if (edgeStatus_.synced) edge = L" | Edge synced";
            else if (edgeStatus_.waiting) edge = L" | Waiting for Edge GPU";
        }
        swprintf_s(info.szTip, L"%ls · %ls%ls", title, status, edge);
    }

    bool addIcon() const {
        auto info = data();
        info.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        info.uCallbackMessage = iconMessage;
        info.hIcon = icon_;
        tooltip(info);
        if (!Shell_NotifyIconW(NIM_ADD, &info)) return false;
        info.uVersion = NOTIFYICON_VERSION_4;
        return Shell_NotifyIconW(NIM_SETVERSION, &info);
    }

    void updateTooltip() const {
        auto info = data();
        info.uFlags = NIF_TIP | NIF_SHOWTIP;
        tooltip(info);
        Shell_NotifyIconW(NIM_MODIFY, &info);
    }

    void refreshHdr() {
        const auto state = detectHdr();
        if (hdr_ == state) return;
        hdr_ = state;
        updateTooltip();
    }

    bool refresh() {
        try {
            current_ = patcher_.inspect();
            error_.clear();
            if (current_.mode == Mode::Unknown)
                error_ = L"DWM shaders do not match a supported gamma mode.";
        } catch (const Failure& error) {
            current_ = {};
            error_ = errorText(error);
        } catch (...) {
            current_ = {};
            error_ = L"Could not read DWM state.";
        }
        return error_.empty();
    }

    void menu(POINT where) {
        refreshHdr();
        const bool active = hdr_ == HdrState::Active;
        if (active && !busy_ && current_.mode == Mode::Unknown) { refresh(); updateTooltip(); }
        HMENU popup = CreatePopupMenu();
        if (!popup) return;
        UINT flags = MF_STRING;
        if (!active || busy_ || current_.mode == Mode::Unknown) flags |= MF_GRAYED;
        for (UINT i = 0; i < selectableCount; ++i) AppendMenuW(popup, flags, firstMode + i, modes[i]);
        if (active && index(current_.mode) < selectableCount) {
            CheckMenuRadioItem(popup, firstMode, firstMode + selectableCount - 1,
                              firstMode + index(current_.mode), MF_BYCOMMAND);
        }
        if (active && (busy_ || !error_.empty() || current_.mode == Mode::LegacyGamma26)) {
            AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(popup, MF_STRING | MF_GRAYED, 0, busy_ ? L"Updating..." :
                        !error_.empty() ? L"DWM verification failed" : L"Select a mode to replace legacy gamma");
        }
        AppendMenuW(popup, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(popup, MF_STRING, exitCommand, L"Exit");
        SetForegroundWindow(hwnd_);
        auto command = TrackPopupMenuEx(popup, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                                        where.x, where.y, hwnd_, nullptr);
        DestroyMenu(popup);
        PostMessageW(hwnd_, WM_NULL, 0, 0);
        if (command) PostMessageW(hwnd_, WM_COMMAND, command, 0);
    }

    void startWork(Mode mode, bool changeDwm) {
        if (busy_) return;
        const auto before = current_;
        busy_ = true;
        switching_ = changeDwm;
        workerError_.clear();
        if (changeDwm) updateTooltip();
        try {
            worker_ = std::thread([this, mode, before, changeDwm] {
                result_ = before;
                edgeResult_ = {};
                edgeResultError_ = false;
                if (changeDwm && detectHdr() == HdrState::Active) {
                    try {
                        result_ = patcher_.set(mode);
                    } catch (const Failure& error) {
                        workerError_ = errorText(error);
                    } catch (...) {
                        workerError_ = L"Could not apply the gamma mode.";
                    }
                }
                if (workerError_.empty()) {
                    try {
                        edgeResult_ = edge_.sync(detectHdr() == HdrState::Active ? result_.mode : Mode::Srgb);
                    } catch (...) {
                        edgeResultError_ = true;
                    }
                }
                PostMessageW(hwnd_, doneMessage, 0, 0);
            });
        } catch (...) {
            busy_ = switching_ = false;
            updateTooltip();
            if (changeDwm) MessageBoxW(nullptr, L"Could not start the gamma change.", title, MB_OK | MB_ICONERROR);
        }
    }

    void select(Mode mode) {
        refreshHdr();
        if (hdr_ != HdrState::Active || mode == current_.mode || current_.mode == Mode::Unknown) return;
        startWork(mode, true);
    }

    LRESULT onMessage(UINT message, WPARAM wp, LPARAM lp) {
        if (message == taskbarCreated_ && taskbarCreated_) {
            addIcon();
            return 0;
        }
        switch (message) {
        case iconMessage:
            if (LOWORD(lp) == WM_CONTEXTMENU && HIWORD(lp) == trayId) {
                POINT where{GET_X_LPARAM(wp), GET_Y_LPARAM(wp)};
                menu(where);
            }
            return 0;
        case WM_COMMAND: {
            const auto command = LOWORD(wp);
            if (command >= firstMode && command < firstMode + selectableCount)
                select(static_cast<Mode>(command - firstMode));
            else if (command == exitCommand)
                DestroyWindow(hwnd_);
            return 0;
        }
        case doneMessage:
            if (!worker_.joinable()) return 0;
            worker_.join();
            busy_ = switching_ = false;
            edgeStatus_ = edgeResult_;
            edgeError_ = edgeResultError_;
            if (workerError_.empty()) {
                current_ = result_;
                if (current_.mode != Mode::Unknown) error_.clear();
                updateTooltip();
            } else {
                refresh();
                updateTooltip();
                MessageBoxW(nullptr, workerError_.c_str(), title, MB_OK | MB_ICONERROR);
            }
            return 0;
        case WM_TIMER:
            refreshHdr();
            if (!busy_) {
                if (currentDwm(patcher_.session) != current_.pid) {
                    refresh();
                    updateTooltip();
                }
                startWork(current_.mode, false);
            }
            return 0;
        case WM_DISPLAYCHANGE:
            refreshHdr();
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd_);
            return 0;
        case WM_DESTROY: {
            KillTimer(hwnd_, 1);
            auto info = data();
            Shell_NotifyIconW(NIM_DELETE, &info);
            PostQuitMessage(0);
            return 0;
        }
        default:
            return DefWindowProcW(hwnd_, message, wp, lp);
        }
    }
};

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    try {
        Handle singleton(CreateMutexW(nullptr, FALSE, L"Local\\Codex.SdrGamma.Tray.1"));
        if (!singleton.value) fail(L"Create tray instance lock");
        if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;
        Tray tray(instance);
        return tray.run(instance);
    } catch (const Failure& error) {
        MessageBoxW(nullptr, errorText(error).c_str(), title, MB_OK | MB_ICONERROR);
    } catch (...) {
        MessageBoxW(nullptr, L"Could not start the tray application.", title, MB_OK | MB_ICONERROR);
    }
    return 1;
}




