#pragma once
#include "tray-core.h"
#include <shellapi.h>

#include <unordered_map>

struct EdgeCheck { DWORD rva; unsigned size; std::array<Byte,128> bytes; };
struct EdgeWrite { DWORD rva; unsigned size; bool gpu; std::array<std::array<Byte,16>,selectableCount> bytes; };
struct EdgeBuild {
    const wchar_t* version;
    Digest hash;
    DWORD singleton;
    const EdgeCheck* checks;
    size_t checkCount;
    const EdgeWrite* writes;
    size_t writeCount;
};
#include "edge-gamma-plan.h"

enum class EdgeRole { None, Browser, Gpu };
struct EdgeProcess {
    DWORD pid, parent;
    ULONGLONG created;
    EdgeRole role;
};
struct EdgeChange {
    HANDLE process;
    ULONG_PTR address;
    std::vector<Byte> before, after;
};

struct EdgeSyncStatus {
    unsigned synced{};
    unsigned waiting{};
    unsigned skipped{};
    DWORD lastError{};
    const wchar_t* lastOperation{};
};

class EdgeSync {
public:
    explicit EdgeSync(DWORD session) : session_(session) {}

    EdgeSyncStatus sync(Mode mode,DWORD onlyBrowser = 0) {
        if (index(mode) >= selectableCount) return {};
        const auto processes = discover();
        EdgeSyncStatus status;
        for (const auto& browser : processes) {
            if (browser.role != EdgeRole::Browser || (onlyBrowser && browser.pid != onlyBrowser)) continue;
            auto gpu = std::find_if(processes.begin(), processes.end(), [&](const EdgeProcess& p) {
                return p.role == EdgeRole::Gpu && p.parent == browser.pid && p.created >= browser.created;
            });
            if (gpu == processes.end()) { ++status.waiting; continue; }
            auto& state = pairs_[browser.pid];
            if (state.browserCreated == browser.created && state.gpuCreated == gpu->created && state.mode == mode) {
                if (state.synced) ++status.synced;
            else { ++status.skipped; status.lastError=state.error; status.lastOperation=state.operation; }
                continue;
            }
            state = {browser.created, gpu->created, mode, false};
            try {
                state.synced = apply(browser, *gpu, mode);
            } catch (const Failure& error) {
                state.error = error.code;
                state.operation = error.operation;
                if (error.code == ERROR_MOD_NOT_FOUND || error.code == ERROR_RETRY) {
                    state.mode = Mode::Unknown;
                    ++status.waiting;
                    continue;
                }
            }
            if (state.synced) ++status.synced;
            else { ++status.skipped; status.lastError=state.error; status.lastOperation=state.operation; }
        }
        for (auto i=pairs_.begin(); i!=pairs_.end();) {
            if (std::none_of(processes.begin(), processes.end(), [&](const EdgeProcess& p) { return p.pid == i->first; }))
                i=pairs_.erase(i);
            else
                ++i;
        }
        return status;
    }

private:
    struct PairState {
        ULONGLONG browserCreated{}, gpuCreated{};
        Mode mode = Mode::Unknown;
        bool synced{};
        DWORD error{};
        const wchar_t* operation{};
    };
    struct Loaded {
        std::wstring dll;
        Module module;
        const EdgeBuild* plan{};
    };
    DWORD session_;
    std::unordered_map<DWORD, PairState> pairs_;
    std::unordered_map<std::wstring, bool> verifiedFiles_;

    static constexpr DWORD queryRights = PROCESS_QUERY_LIMITED_INFORMATION;
    static constexpr DWORD patchRights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE;

    static ULONGLONG creationTime(HANDLE process) {
        FILETIME created, exited, kernel, user;
        if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
        ULARGE_INTEGER value{};
        value.LowPart = created.dwLowDateTime;
        value.HighPart = created.dwHighDateTime;
        return value.QuadPart;
    }

    static std::vector<Byte> tokenUser(HANDLE process) {
        HANDLE raw=nullptr;
        if (!OpenProcessToken(process,TOKEN_QUERY,&raw)) return {};
        Handle token(raw);
        DWORD size=0;
        GetTokenInformation(token,TokenUser,nullptr,0,&size);
        std::vector<Byte> bytes(size);
        if (!size || !GetTokenInformation(token,TokenUser,bytes.data(),size,&size)) return {};
        return bytes;
    }

    static bool sameUser(HANDLE process) {
        static const auto own=tokenUser(GetCurrentProcess());
        auto user=tokenUser(process);
        return !own.empty() && !user.empty() &&
            EqualSid(reinterpret_cast<const TOKEN_USER*>(own.data())->User.Sid,
                     reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid);
    }

    static bool standardEdge(HANDLE process) {
        if (!sameUser(process)) return false;
        wchar_t exe[MAX_PATH];
        DWORD n=ARRAYSIZE(exe);
        if (!QueryFullProcessImageNameW(process,0,exe,&n)) return false;
        const wchar_t* roots[]{L"%ProgramFiles(x86)%",L"%ProgramW6432%",L"%ProgramFiles%"};
        for (auto root : roots) {
            wchar_t expected[MAX_PATH];
            const DWORD count=ExpandEnvironmentStringsW(
                (std::wstring(root)+L"\\Microsoft\\Edge\\Application\\msedge.exe").c_str(),
                expected,ARRAYSIZE(expected));
            if (count && count<=ARRAYSIZE(expected) && _wcsicmp(exe,expected)==0) return true;
        }
        return false;
    }

    static EdgeRole getRole(HANDLE process) {
        using Query = LONG (NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
#pragma warning(suppress: 4191)
        auto query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));
        if (!query) return EdgeRole::None;
        struct CommandLine { USHORT length, capacity; PWSTR buffer; };
        ULONG size=0;
        query(process,60,nullptr,0,&size);
        if (size<sizeof(CommandLine) || size>131072) return EdgeRole::None;
        std::vector<Byte> buffer(size);
        if (query(process,60,buffer.data(),size,&size)<0) return EdgeRole::None;
        const auto* line=reinterpret_cast<const CommandLine*>(buffer.data());
        const auto start=reinterpret_cast<ULONG_PTR>(buffer.data());
        const auto address=reinterpret_cast<ULONG_PTR>(line->buffer);
        if (address<start || address-start>buffer.size() ||
            line->length>buffer.size()-(address-start) || line->length%sizeof(wchar_t))
            return EdgeRole::None;
        std::wstring text(line->buffer,line->length/sizeof(wchar_t));
        int n=0;
        auto argv=CommandLineToArgvW(text.c_str(),&n);
        if (!argv) return EdgeRole::None;
        auto role=EdgeRole::Browser;
        for (int i=1;i<n;++i) {
            if (wcscmp(argv[i],L"--")==0) break;
            if (wcsncmp(argv[i],L"--type=",7)==0) {
                role=wcscmp(argv[i],L"--type=gpu-process")==0 ? EdgeRole::Gpu : EdgeRole::None;
                break;
            }
        }
        LocalFree(argv);
        return role;
    }

    std::vector<EdgeProcess> discover() const {
        std::vector<EdgeProcess> result;
        for (const auto& p:processesNamed(L"msedge.exe")) {
            DWORD session=0;
            if (!ProcessIdToSessionId(p.pid,&session) || session!=session_) continue;
            Handle proc(OpenProcess(queryRights,FALSE,p.pid));
            if (!proc.value || !standardEdge(proc)) continue;
            EdgeRole role=getRole(proc);
            if (role==EdgeRole::None) continue;
            ULONGLONG created=creationTime(proc);
            if (created) result.push_back({p.pid,p.parent,created,role});
        }
        return result;
    }

    static Loaded locate(HANDLE process,DWORD pid) {
        wchar_t path[MAX_PATH];
        DWORD n=ARRAYSIZE(path);
        if (!QueryFullProcessImageNameW(process,0,path,&n)) fail(L"Read the Edge executable path");
        const auto parent=std::filesystem::path(path).parent_path();
        for (const auto& build : edgeBuilds) {
            auto dll=(parent/build.version/L"msedge.dll").wstring();
            if (auto module=findModule(pid,dll); module.address) return {std::move(dll),module,&build};
        }
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid));
        MODULEENTRY32W entry{};
        entry.dwSize=sizeof(entry);
        if (snapshot.value==INVALID_HANDLE_VALUE || !Module32FirstW(snapshot,&entry))
            fail(L"Wait for Edge to load its graphics module",ERROR_MOD_NOT_FOUND);
        do {
            if (_wcsicmp(entry.szModule,L"msedge.dll")==0) return {};
        } while (Module32NextW(snapshot,&entry));
        fail(L"Wait for Edge to load its graphics module",ERROR_MOD_NOT_FOUND);
    }

    bool verifyFile(const Loaded& image) {
        if (auto known=verifiedFiles_.find(image.dll);known!=verifiedFiles_.end()) return known->second;
        Handle file(CreateFileW(image.dll.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,
                                nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));
        if (file.value==INVALID_HANDLE_VALUE) fail(L"Open the Edge DLL for verification");
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file,&size) || size.QuadPart<=0 || size.QuadPart>MAXDWORD)
            fail(L"Check the Edge DLL size",ERROR_INVALID_DATA);
        Handle mapping(CreateFileMappingW(file,nullptr,PAGE_READONLY,0,0,nullptr));
        if (!mapping.value) fail(L"Map the Edge DLL");
        const auto view=MapViewOfFile(mapping,FILE_MAP_READ,0,0,0);
        if (!view) fail(L"Read the Edge DLL image");
        Digest hash{};
        BCRYPT_ALG_HANDLE algo{};
        LONG result=BCryptOpenAlgorithmProvider(&algo,BCRYPT_SHA256_ALGORITHM,nullptr,0);
        if (result>=0) {
            result=BCryptHash(algo,nullptr,0,static_cast<Byte*>(view),static_cast<ULONG>(size.QuadPart),
                              hash.data(),static_cast<ULONG>(hash.size()));
            BCryptCloseAlgorithmProvider(algo,0);
        }
        UnmapViewOfFile(view);
        if (result<0) fail(L"Compute the Edge DLL SHA-256",result);
        return verifiedFiles_.emplace(image.dll,hash==image.plan->hash).first->second;
    }

    static void collect(HANDLE process,const Loaded& image,bool gpu,Mode desired,std::vector<EdgeChange>& changes) {
        const auto base=image.module.address;
        const auto& plan=*image.plan;
        const auto mode=index(desired);
        for (size_t i=0;i<plan.checkCount;++i) {
            const auto& item=plan.checks[i];
            std::array<Byte,128> current{};
            if (item.rva>image.module.size || item.size>image.module.size-item.rva ||
                !readMemory(process,base+item.rva,current.data(),item.size) ||
                !std::equal(current.begin(),current.begin()+item.size,item.bytes.begin()))
                fail(L"Edge DLL anchor bytes",ERROR_INVALID_DATA);
        }

        bool initializersPatched=false;
        auto append=[&](const EdgeWrite& item) {
            std::vector<Byte> current(item.size);
            if (item.rva>image.module.size || item.size>image.module.size-item.rva ||
                !readMemory(process,base+item.rva,current.data(),current.size()))
                fail(L"Read the Edge patch location");
            auto matches=[&](unsigned i) { return std::equal(current.begin(),current.end(),item.bytes[i].begin()); };
            const bool known = std::any_of(item.bytes.begin()+1,item.bytes.end(),
                [&](const auto& bytes) { return std::equal(current.begin(),current.end(),bytes.begin()); });
            if (!matches(0) && (item.gpu!=gpu || !known))
                fail(L"Edge instructions differ from all known states",ERROR_INVALID_DATA);
            if (gpu && item.gpu && !matches(0)) initializersPatched=true;
            if (item.gpu==gpu && !matches(mode)) {
                changes.push_back({process,base+item.rva,std::move(current),
                                   {item.bytes[mode].begin(),item.bytes[mode].begin()+item.size}});
            }
        };
        if (mode==0 && !gpu) {
            for (size_t i=plan.writeCount;i>0;--i) append(plan.writes[i-1]);
        } else {
            for (size_t i=0;i<plan.writeCount;++i) append(plan.writes[i]);
        }
        if (!gpu || (mode==0 && !initializersPatched)) return;

        ULONG_PTR singleton{};
        if (!readMemory(process,base+plan.singleton,&singleton,sizeof(singleton)))
            fail(L"Read the Edge SDR color space");
        if (!singleton) return;
        // SkColorSpace stores the transfer tuple after its pointer and reference count.
        constexpr size_t offset=12;
        constexpr size_t tfSize=edgeTransfer[0].size();
        std::array<Byte,tfSize+edgeGamut.size()> current{};
        MEMORY_BASIC_INFORMATION mem{};
        if (!VirtualQueryEx(process,reinterpret_cast<void*>(singleton),&mem,sizeof(mem)) ||
            mem.Type!=MEM_PRIVATE || mem.State!=MEM_COMMIT || mem.Protect!=PAGE_READWRITE ||
            !readMemory(process,singleton+offset,current.data(),current.size()) ||
            !std::equal(edgeGamut.begin(),edgeGamut.end(),current.begin()+tfSize))
            fail(L"Edge SDR cached object",ERROR_INVALID_DATA);
        const auto match=std::find_if(edgeTransfer.begin(),edgeTransfer.end(),
            [&](const auto& tf) { return std::equal(tf.begin(),tf.end(),current.begin()); });
        if (match==edgeTransfer.end()) fail(L"Edge SDR cached transfer unknown",ERROR_INVALID_DATA);
        if (match!=edgeTransfer.begin()+mode) {
            changes.push_back({process,singleton+offset,{current.begin(),current.begin()+tfSize},
                               {edgeTransfer[mode].begin(),edgeTransfer[mode].end()}});
        }
    }

    static bool write(const EdgeChange& edit,const std::vector<Byte>& bytes) {
        auto address=reinterpret_cast<void*>(edit.address);
        MEMORY_BASIC_INFORMATION mem{};
        if (!VirtualQueryEx(edit.process,address,&mem,sizeof(mem)) || mem.State!=MEM_COMMIT ||
            edit.address-reinterpret_cast<ULONG_PTR>(mem.BaseAddress)+bytes.size()>mem.RegionSize)
            return false;
        DWORD old=0;
        const bool protect=mem.Protect!=PAGE_READWRITE && mem.Protect!=PAGE_EXECUTE_READWRITE;
        if (protect && !VirtualProtectEx(edit.process,address,bytes.size(),PAGE_EXECUTE_READWRITE,&old))
            return false;
        SIZE_T length=0;
        const bool written=WriteProcessMemory(edit.process,address,bytes.data(),bytes.size(),&length) &&
                           length==bytes.size();
        DWORD ignored=0;
        const bool restored=!protect || VirtualProtectEx(edit.process,address,bytes.size(),old,&ignored);
        std::array<Byte,28> check{};
        return written && restored && bytes.size()<=check.size() &&
               readMemory(edit.process,edit.address,check.data(),bytes.size()) &&
               std::equal(bytes.begin(),bytes.end(),check.begin());
    }

    static void refreshWindow(DWORD pid) {
        EnumWindows([](HWND hwnd,LPARAM id) -> BOOL {
            DWORD owner=0;
            GetWindowThreadProcessId(hwnd,&owner);
            if (owner==static_cast<DWORD>(id)) PostMessageW(hwnd,WM_DISPLAYCHANGE,32,MAKELPARAM(GetSystemMetrics(SM_CXSCREEN),GetSystemMetrics(SM_CYSCREEN)));
            return TRUE;
        },pid);
        HWND hwnd=nullptr;
        while ((hwnd=FindWindowExW(HWND_MESSAGE,hwnd,nullptr,nullptr))) {
            DWORD owner=0;
            GetWindowThreadProcessId(hwnd,&owner);
            if (owner==pid) PostMessageW(hwnd,WM_DISPLAYCHANGE,32,MAKELPARAM(GetSystemMetrics(SM_CXSCREEN),GetSystemMetrics(SM_CYSCREEN)));
        }
    }

    bool apply(const EdgeProcess& browser,const EdgeProcess& gpu,Mode mode) {
        Handle app(OpenProcess(patchRights,FALSE,browser.pid));
        Handle graphics(OpenProcess(patchRights,FALSE,gpu.pid));
        if (!app.value || !graphics.value) fail(L"Open the Edge graphics process");
        if (creationTime(app)!=browser.created || creationTime(graphics)!=gpu.created ||
            !standardEdge(app) || !standardEdge(graphics) || getRole(app)!=EdgeRole::Browser ||
            getRole(graphics)!=EdgeRole::Gpu)
            fail(L"Edge process changed during verification",ERROR_RETRY);
        BOOL debugging=FALSE;
        if (!CheckRemoteDebuggerPresent(app,&debugging) || debugging ||
            !CheckRemoteDebuggerPresent(graphics,&debugging) || debugging)
            fail(L"Edge is attached to a native debugger",ERROR_BUSY);
        const auto appImage=locate(app,browser.pid);
        const auto gpuImage=locate(graphics,gpu.pid);
        if (!appImage.plan || appImage.plan!=gpuImage.plan || !verifyFile(appImage) ||
            !verifyFile(gpuImage)) return false;
        auto ntdll=GetModuleHandleW(L"ntdll.dll");
#pragma warning(suppress: 4191)
        auto suspend=reinterpret_cast<NtProc>(GetProcAddress(ntdll,"NtSuspendProcess"));
#pragma warning(suppress: 4191)
        auto resume=reinterpret_cast<NtProc>(GetProcAddress(ntdll,"NtResumeProcess"));
        if (!suspend || !resume) fail(L"Locate Edge suspend and resume functions");
        std::vector<EdgeChange> changes;
        {
            Suspension stopApp(app,suspend,resume,false);
            Suspension stopGpu(graphics,suspend,resume,false);
            if (mode==Mode::Srgb) {
                collect(app,appImage,false,mode,changes);
                collect(graphics,gpuImage,true,mode,changes);
            } else {
                collect(graphics,gpuImage,true,mode,changes);
                collect(app,appImage,false,mode,changes);
            }
            size_t attempted=0;
            try {
                for (const auto& edit:changes) {
                    ++attempted;
                    if (!write(edit,edit.after)) fail(L"Write the Edge SDR curve");
                }
                if (!changes.empty() && (!FlushInstructionCache(app,nullptr,0) ||
                                         !FlushInstructionCache(graphics,nullptr,0)))
                    fail(L"Flush the Edge instruction cache");
            } catch (...) {
                bool restored=true;
                while (attempted>0) {
                    const auto& edit=changes[--attempted];
                    restored &= write(edit,edit.before);
                }
                FlushInstructionCache(app,nullptr,0);
                FlushInstructionCache(graphics,nullptr,0);
                if (!restored) fail(L"Edge patch rollback failed. Restart Edge.",ERROR_WRITE_FAULT);
                throw;
            }
            stopGpu.finish();
            stopApp.finish();
        }
        if (!changes.empty()) {
            refreshWindow(browser.pid);
            refreshWindow(gpu.pid);
        }
        return true;
    }
};

inline bool allActiveDisplaysHdr() {
    constexpr UINT32 flags=QDC_ONLY_ACTIVE_PATHS;
    UINT32 count=0,modesCount=0;
    LONG error=GetDisplayConfigBufferSizes(flags,&count,&modesCount);
    if (error) fail(L"Read active displays",error);
    std::vector<DISPLAYCONFIG_PATH_INFO> paths(count);
    std::vector<DISPLAYCONFIG_MODE_INFO> modes(modesCount);
    error=QueryDisplayConfig(flags,&count,paths.data(),&modesCount,modes.data(),nullptr);
    if (error) fail(L"Read active displays",error);
    for (UINT32 i=0;i<count;++i) {
        const auto& target=paths[i].targetInfo;
        DISPLAYCONFIG_GET_ADVANCED_COLOR_INFO_2 info{};
        info.header={DISPLAYCONFIG_DEVICE_INFO_GET_ADVANCED_COLOR_INFO_2,sizeof(info),target.adapterId,target.id};
        error=DisplayConfigGetDeviceInfo(&info.header);
        if (error) fail(L"Read display HDR status",error);
        if (info.activeColorMode!=DISPLAYCONFIG_ADVANCED_COLOR_MODE_HDR) return false;
    }
    return count!=0;
}

