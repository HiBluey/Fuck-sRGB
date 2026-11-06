#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <windowsx.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <thread>

using Byte = unsigned char;
using Digest = std::array<Byte, 32>;

enum class Mode : unsigned { Srgb, Gamma22, Gamma24, Gamma10, LegacyGamma26, Unknown };
constexpr unsigned modeCount = static_cast<unsigned>(Mode::Unknown);
constexpr unsigned selectableCount = static_cast<unsigned>(Mode::LegacyGamma26);
constexpr unsigned index(Mode mode) { return static_cast<unsigned>(mode); }
struct Region { DWORD offset, size; std::array<Digest, modeCount> hash; };
struct Edit { DWORD offset; std::array<Byte, selectableCount> value; };
#include "tray-patch-plan.h"

struct Failure { const wchar_t* operation; DWORD code; };
[[noreturn]] void fail(const wchar_t* operation, DWORD code = GetLastError()) {
    throw Failure{operation, code};
}

struct Handle {
    HANDLE value;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    operator HANDLE() const { return value; }
};

using NtProc = LONG (NTAPI *)(HANDLE);
struct Suspension {
    HANDLE process;
    NtProc resume;
    bool restartOnFailure;
    Suspension(HANDLE p, NtProc stop, NtProc start, bool restart = true) : process(p), resume(start), restartOnFailure(restart) {
        LONG status = stop(process);
        if (status < 0) fail(L"Suspend DWM", status);
    }
    void finish() {
        LONG status = resume(process);
        if (status < 0) fail(L"Resume DWM", status);
        process = nullptr;
    }
    ~Suspension() {
        if (process && resume(process) < 0 && restartOnFailure)
            TerminateProcess(process, 0);
    }
};

struct Sha256 {
    BCRYPT_ALG_HANDLE algo{};
    Sha256() {
        auto status = BCryptOpenAlgorithmProvider(&algo, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status < 0) fail(L"Open SHA256", status);
    }
    ~Sha256() { BCryptCloseAlgorithmProvider(algo, 0); }
    Digest operator()(std::vector<Byte>& data) const {
        Digest d{};
        auto status = BCryptHash(algo, nullptr, 0, data.data(), static_cast<ULONG>(data.size()), d.data(), static_cast<ULONG>(d.size()));
        if (status < 0) fail(L"SHA256", status);
        return d;
    }
};

struct Module {
    ULONG_PTR address{};
    DWORD size{};
};

struct ProcessEntry { DWORD pid, parent; };

std::vector<ProcessEntry> processesNamed(const wchar_t* name) {
    using Query = LONG (NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
#pragma warning(suppress: 4191)
    auto query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));
    std::vector<ProcessEntry> result;
    if (query) {
        constexpr LONG lengthMismatch=static_cast<LONG>(0xC0000004u);
        constexpr ULONG maxSize=8*1024*1024;
        std::vector<Byte> buffer(64*1024);
        while (buffer.size()<=maxSize) {
            ULONG length=0;
            const LONG status=query(SystemBasicProcessInformation,buffer.data(),static_cast<ULONG>(buffer.size()),&length);
            if (status==lengthMismatch) {
                buffer.resize(std::max<size_t>(length,buffer.size()*2));
                continue;
            }
            if (status<0 || length>buffer.size()) break;
            const auto base=reinterpret_cast<ULONG_PTR>(buffer.data());
            const auto nameLength=wcslen(name);
            for (size_t offset=0;offset+sizeof(SYSTEM_BASICPROCESS_INFORMATION)<=length;) {
                const auto* entry=reinterpret_cast<const SYSTEM_BASICPROCESS_INFORMATION*>(buffer.data()+offset);
                const auto address=reinterpret_cast<ULONG_PTR>(entry->ImageName.Buffer);
                if (entry->ImageName.Length==nameLength*sizeof(wchar_t) && address>=base &&
                    address-base<=length && entry->ImageName.Length<=length-(address-base) &&
                    _wcsnicmp(entry->ImageName.Buffer,name,nameLength)==0) {
                    result.push_back({static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(entry->UniqueProcessId)),
                                      static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(entry->InheritedFromUniqueProcessId))});
                }
                if (!entry->NextEntryOffset) return result;
                if (entry->NextEntryOffset<sizeof(*entry) || entry->NextEntryOffset>length-offset) break;
                offset+=entry->NextEntryOffset;
            }
            result.clear();
            break;
        }
    }

    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if (snapshot.value==INVALID_HANDLE_VALUE) return result;
    PROCESSENTRY32W item{};
    item.dwSize=sizeof(item);
    if (!Process32FirstW(snapshot,&item)) return result;
    do {
        if (_wcsicmp(item.szExeFile,name)==0) result.push_back({item.th32ProcessID,item.th32ParentProcessID});
    } while (Process32NextW(snapshot,&item));
    return result;
}

DWORD currentDwm(DWORD session) {
    for (const auto& item:processesNamed(L"dwm.exe")) {
        DWORD targetSession=0;
        if (ProcessIdToSessionId(item.pid,&targetSession) && targetSession==session) return item.pid;
    }
    return 0;
}

Module findModule(DWORD pid, const std::wstring& dllPath) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
    if (snapshot.value == INVALID_HANDLE_VALUE) return {};
    MODULEENTRY32W item{};
    item.dwSize = sizeof(item);
    if (!Module32FirstW(snapshot, &item)) return {};
    do {
        if (_wcsicmp(item.szExePath, dllPath.c_str()) == 0)
            return {reinterpret_cast<ULONG_PTR>(item.modBaseAddr), item.modBaseSize};
    } while (Module32NextW(snapshot, &item));
    return {};
}


struct DebugPrivilege {
    static HANDLE openToken() {
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw))
            fail(L"Read process token");
        return raw;
    }
    Handle token{openToken()};
    TOKEN_PRIVILEGES previous{};
    DebugPrivilege() {
        TOKEN_PRIVILEGES requested{};
        requested.PrivilegeCount = 1;
        if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &requested.Privileges[0].Luid))
            fail(L"Find debug privilege");
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD returned = 0;
        if (!AdjustTokenPrivileges(token, FALSE, &requested, sizeof(previous), &previous, &returned) ||
            GetLastError() != ERROR_SUCCESS)
            fail(L"Enable debug privilege");
    }
    ~DebugPrivilege() { AdjustTokenPrivileges(token, FALSE, &previous, 0, nullptr, nullptr); }
};

void verifyImage(HANDLE process, const std::wstring& expected) {
    wchar_t path[32768];
    DWORD n = ARRAYSIZE(path);
    if (!QueryFullProcessImageNameW(process, 0, path, &n)) fail(L"Get DWM executable path");
    if (_wcsicmp(path, expected.c_str()) != 0) fail(L"DWM executable path check", ERROR_INVALID_DATA);
}

bool readMemory(HANDLE p, ULONG_PTR address, void* target, SIZE_T size) {
    SIZE_T received = 0;
    return ReadProcessMemory(p, reinterpret_cast<const void*>(address), target, size, &received) && received == size;
}


Mode stateOf(HANDLE process, Module module, const Sha256& sha) {
    const auto& last = regions[ARRAYSIZE(regions)-1];
    if (!module.address || module.size < last.offset + last.size)
        return Mode::Unknown;
    std::array<bool, modeCount> matches;
    matches.fill(true);
    for (const auto& region : regions) {
        std::vector<Byte> bytes(region.size);
        if (!readMemory(process, module.address + region.offset, bytes.data(), bytes.size()))
            fail(L"Read DWM shader library");
        const auto digest = sha(bytes);
        for (unsigned i = 0; i < modeCount; ++i)
            matches[i] &= digest == region.hash[i];
    }
    for (unsigned i = 0; i < modeCount; ++i)
        if (matches[i]) return static_cast<Mode>(i);
    return Mode::Unknown;
}

struct Page {
    ULONG_PTR address;
    DWORD protection;
    bool writable = false;
};
struct Span {
    ULONG_PTR address;
    std::vector<Byte> before, after;
};

void patch(HANDLE process, Module m, const Sha256& sha, Mode mode) {
    if (stateOf(process, m, sha) != Mode::Srgb) fail(L"Original shader library check", ERROR_INVALID_DATA);
    SYSTEM_INFO sys{};
    GetSystemInfo(&sys);
    const auto pageSize = static_cast<ULONG_PTR>(sys.dwPageSize);
    std::vector<Page> pages;
    std::vector<Span> spans;
    for (const auto& edit : edits) {
        if (edit.value[0] == edit.value[index(mode)]) continue;
        const auto address = m.address + edit.offset;
        const auto page = address - address % pageSize;
        if (pages.empty() || pages.back().address != page) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(process, reinterpret_cast<void*>(page), &mbi, sizeof(mbi)) ||
                mbi.AllocationBase != reinterpret_cast<void*>(m.address) || mbi.State != MEM_COMMIT ||
                mbi.Type != MEM_IMAGE || mbi.Protect != PAGE_READONLY)
                fail(L"DWM shader memory page check", ERROR_INVALID_DATA);
            pages.push_back({page, mbi.Protect});
        }
        if (spans.empty() || spans.back().address + spans.back().before.size() != address ||
            page == address)
            spans.push_back({address, {}, {}});
        spans.back().before.push_back(edit.value[0]);
        spans.back().after.push_back(edit.value[index(mode)]);
    }

    auto restoreProtection = [&]() {
        bool ok = true;
        for (auto& page : pages) {
            if (!page.writable) continue;
            DWORD ignored;
            if (VirtualProtectEx(process, reinterpret_cast<void*>(page.address), pageSize, page.protection, &ignored))
                page.writable = false;
            else
                ok = false;
        }
        return ok;
    };
    auto write = [&](ULONG_PTR address, const std::vector<Byte>& bytes) {
        SIZE_T written = 0;
        return WriteProcessMemory(process, reinterpret_cast<void*>(address), bytes.data(), bytes.size(), &written) &&
               written == bytes.size();
    };

    size_t attempted = 0;
    try {
        for (auto& page : pages) {
            DWORD old;
            if (!VirtualProtectEx(process, reinterpret_cast<void*>(page.address), pageSize, PAGE_WRITECOPY, &old))
                fail(L"Make shader page copy-on-write");
            page.writable = true;
        }
        for (const auto& span : spans) {
            ++attempted;
            if (!write(span.address, span.after)) fail(L"Write shader bytes");
        }
        if (stateOf(process, m, sha) != mode) fail(L"Patched shader library verification", ERROR_INVALID_DATA);
    } catch (...) {
        bool restored = true;
        for (size_t i = 0; i < attempted; ++i) restored &= write(spans[i].address, spans[i].before);
        restored &= restoreProtection();
        if (!restored && !TerminateProcess(process, 0))
            fail(L"Roll back the patch and recover DWM");
        throw;
    }
    if (!restoreProtection()) {
        TerminateProcess(process, 0);
        fail(L"Restore page protection");
    }
}


struct Current {
    DWORD pid{};
    Mode mode = Mode::Unknown;
};

struct Patcher {
    std::wstring exe;
    std::wstring dll;
    DWORD session{};
    static constexpr DWORD readRights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    static constexpr DWORD writeRights = readRights | PROCESS_TERMINATE | PROCESS_VM_WRITE |
                                         PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME;

    Patcher() {
        wchar_t sys[MAX_PATH];
        const UINT len = GetSystemDirectoryW(sys, ARRAYSIZE(sys));
        if (!len || len >= ARRAYSIZE(sys)) fail(L"Read the system directory");
        exe = std::wstring(sys) + L"\\dwm.exe";
        dll = std::wstring(sys) + L"\\dwmcore.dll";
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || !session)
            fail(L"Identify the current desktop session");
    }

    void verifyFile(const Sha256& sha) const {
        std::ifstream file(std::filesystem::path{dll}, std::ios::binary);
        if (!file) fail(L"Open dwmcore.dll", ERROR_FILE_NOT_FOUND);
        std::vector<Byte> disk((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        if (sha(disk) != expectedDll)
            fail(L"Unsupported dwmcore.dll build. Expected 10.0.26100.9949.", ERROR_REVISION_MISMATCH);
    }

    Current inspect() const {
        Sha256 sha;
        verifyFile(sha);
        DebugPrivilege debug;
        DWORD pid = currentDwm(session);
        if (!pid) fail(L"Find DWM for the current session", ERROR_NOT_FOUND);
        Handle process(OpenProcess(readRights, FALSE, pid));
        if (!process.value) fail(L"Open DWM");
        verifyImage(process, exe);
        return {pid, stateOf(process, findModule(pid, dll), sha)};
    }

    Current set(Mode mode) const {
        if (index(mode) >= selectableCount) fail(L"Invalid gamma mode", ERROR_INVALID_PARAMETER);
        Sha256 sha;
        verifyFile(sha);
        DebugPrivilege debug;
        DWORD old = currentDwm(session);
        if (!old) fail(L"Find DWM for the current session", ERROR_NOT_FOUND);
        Handle process(OpenProcess(writeRights, FALSE, old));
        if (!process.value) fail(L"Open DWM");
        verifyImage(process, exe);
        Mode current = stateOf(process, findModule(old, dll), sha);
        if (current == Mode::Unknown) fail(L"DWM shaders do not match a supported gamma mode", ERROR_INVALID_DATA);
        if (current == mode) return {old, mode};

        auto ntdll = GetModuleHandleW(L"ntdll.dll");
#pragma warning(suppress: 4191)
        const auto suspend = reinterpret_cast<NtProc>(GetProcAddress(ntdll, "NtSuspendProcess"));
#pragma warning(suppress: 4191)
        const auto resume = reinterpret_cast<NtProc>(GetProcAddress(ntdll, "NtResumeProcess"));
        if (!suspend || !resume) fail(L"Locate DWM suspend and resume functions");
        if (!TerminateProcess(process, 0)) fail(L"Restart DWM");

        const ULONGLONG deadline = GetTickCount64() + 5000;
        while (GetTickCount64() < deadline) {
            DWORD pid = currentDwm(session);
            if (pid && pid != old) {
                if (Module module = findModule(pid, dll); module.address) {
                    Handle replacement(OpenProcess(writeRights, FALSE, pid));
                    if (!replacement.value) fail(L"Open the restarted DWM process");
                    verifyImage(replacement, exe);
                    if (mode == Mode::Srgb) {
                        if (stateOf(replacement, module, sha) != Mode::Srgb)
                            fail(L"Verify the restored native shaders", ERROR_INVALID_DATA);
                    } else {
                        Suspension suspended(replacement, suspend, resume);
                        patch(replacement, module, sha, mode);
                        suspended.finish();
                    }
                    return {pid, mode};
                }
            }
            Sleep(1);
        }
        fail(L"Wait for DWM to restart", ERROR_TIMEOUT);
    }
};

