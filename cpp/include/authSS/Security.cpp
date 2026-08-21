// =============================================================================
// SANTET SENTINEL — C++ SDK SECURITY MODULE (authSS)
// =============================================================================
#include "Security.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include <intrin.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <set>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace Authss {

// ── Static Members ───────────────────────────────────────────────────────
std::atomic<bool> Security::_running{false};
std::thread Security::_monitor_thread;
std::function<void(const std::string&)> Security::_on_violation;

// ── Blocked Processes (Debuggers, Injectors, Analyzers) ──────────────────
static const wchar_t* BLOCKED_PROCESSES[] = {
    // Debuggers
    L"x64dbg", L"x32dbg", L"ollydbg", L"ImmunityDebugger",
    L"windbg", L"WinDbgX", L"ida", L"ida64", L"idaq64",
    L"dnSpy", L"ReClass.NET",
    // Injectors
    L"Extreme Injector", L"Xenos", L"GH Injector",
    L"ProcessHacker", L"Process Hacker",
    // Analyzers
    L"Cheat Engine", L"cheatengine", L"cheatengine-x86_64",
    L"KsDumper", L"Dump-Fixer", L"kdstinker",
    L"HTTPDebugger", L"Fiddler", L"Wireshark", L"dumpcap",
    L"tcpview", L"procmon", L"procexp", L"autoruns",
    L"HookExplorer", L"ImportREC", L"PETools", L"LordPE",
    L"SysInspector", L"sysAnalyzer", L"sniff_hit",
    L"joeboxcontrol", L"joeboxserver",
    L"MugenJinFuu", L"Mugen JinFuu",
    // VM Tools (optional — uncomment if needed)
    // L"vmtoolsd", L"vmwaretray", L"vmwareuser",
    // L"vboxservice", L"vboxtray",
    L"cmd",
    nullptr
};

// ── Helper: Check if debugger is attached ────────────────────────────────
static bool check_debugger_present() {
    return IsDebuggerPresent() != 0;
}

static bool check_remote_debugger() {
    BOOL is_debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_debugger);
    return is_debugger != FALSE;
}

static bool check_hardware_breakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
    }
    return false;
}

static bool check_timing() {
    auto start = std::chrono::high_resolution_clock::now();
    // Simulate some work
    volatile int x = 0;
    for (int i = 0; i < 100000; i++) x += i;
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    // If execution took too long, likely single-stepping
    return duration.count() > 500000; // > 500ms for simple loop
}

static bool check_ntdbg() {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto NtQIP = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return false;

    DWORD debug_port = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr);
    return (status == 0 && debug_port != 0);
}

// ── Helper: Check process list ───────────────────────────────────────────
static bool is_blocked_process(const std::wstring& name) {
    for (int i = 0; BLOCKED_PROCESSES[i] != nullptr; i++) {
        std::wstring blocked(BLOCKED_PROCESSES[i]);
        // Case-insensitive contains
        std::wstring lower_name = name;
        std::wstring lower_blocked = blocked;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::towlower);
        std::transform(lower_blocked.begin(), lower_blocked.end(), lower_blocked.begin(), ::towlower);
        if (lower_name.find(lower_blocked) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

// ── Helper: SHA256 hash of file ──────────────────────────────────────────
static std::string sha256_file(const std::string& filepath) {
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return "";
    }

    BYTE buffer[8192];
    DWORD bytes_read = 0;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, nullptr) && bytes_read > 0) {
        CryptHashData(hHash, buffer, bytes_read, 0);
    }

    BYTE hash[32];
    DWORD hash_len = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len);

    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return ss.str();
}

// ── Helper: Get current EXE path ────────────────────────────────────────
static std::string get_exe_path() {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    return std::string(path);
}

// ── Security Implementation ─────────────────────────────────────────────

void Security::start_all(int check_interval_ms) {
    if (_running.exchange(true)) return;

    // Run initial checks
    if (anti_debug()) {
        handle_violation("Debugger detected at startup");
        return;
    }

    if (anti_hook()) {
        handle_violation("API hooking detected at startup");
        return;
    }

    anti_dump();
    anti_memory_scan();

    // Start monitoring thread
    _monitor_thread = std::thread(monitor_loop, check_interval_ms);
    _monitor_thread.detach();
}

bool Security::anti_debug() {
    bool detected = false;

    if (check_debugger_present()) {
        detected = true;
    }
    if (check_remote_debugger()) {
        detected = true;
    }
    if (check_hardware_breakpoints()) {
        detected = true;
    }
    if (check_ntdbg()) {
        detected = true;
    }

    return detected;
}

void Security::anti_dump() {
    // Get current module
    HMODULE hModule = GetModuleHandleA(nullptr);
    if (!hModule) return;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dos->e_lfanew);

    // Make .text section read-only (prevent memory dumping)
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD old_protect = 0;
            VirtualProtect(
                (BYTE*)hModule + section->VirtualAddress,
                section->Misc.VirtualSize,
                PAGE_EXECUTE_READ,
                &old_protect
            );
        }
    }

    // Erase DOS header signature (anti-PE-header-dump)
    dos->e_magic = 0;
}

bool Security::anti_hook() {
    // Check if critical functions are hooked by comparing first bytes
    auto check_hook = [](const char* module, const char* func) -> bool {
        HMODULE hMod = GetModuleHandleA(module);
        if (!hMod) return false;
        FARPROC proc = GetProcAddress(hMod, func);
        if (!proc) return false;

        BYTE* bytes = (BYTE*)proc;
        // Common hook patterns: JMP (0xE9), PUSH+RET, MOV RAX+JMP RAX
        if (bytes[0] == 0xE9 || bytes[0] == 0xEA) return true; // JMP rel
        if (bytes[0] == 0xFF && bytes[1] == 0x25) return true; // JMP [addr]
        if (bytes[0] == 0x68) return true; // PUSH imm32
        if (bytes[0] == 0x48 && bytes[1] == 0xB8) return true; // MOV RAX, imm64

        return false;
    };

    // Check common API functions
    if (check_hook("kernel32.dll", "IsDebuggerPresent")) return true;
    if (check_hook("kernel32.dll", "CheckRemoteDebuggerPresent")) return true;
    if (check_hook("ntdll.dll", "NtQueryInformationProcess")) return true;
    if (check_hook("kernel32.dll", "WriteProcessMemory")) return true;
    if (check_hook("kernel32.dll", "ReadProcessMemory")) return true;

    return false;
}

bool Security::anti_vm() {
    // Check for VM artifacts
    auto check_vm_reg = [](const char* key, const char* val) -> bool {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256] = {};
            DWORD size = sizeof(buffer);
            DWORD type = 0;
            if (RegQueryValueExA(hKey, val, nullptr, &type, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                std::string str(buffer);
                std::transform(str.begin(), str.end(), str.begin(), ::tolower);
                return str.find("vmware") != std::string::npos ||
                       str.find("virtualbox") != std::string::npos ||
                       str.find("virtual") != std::string::npos ||
                       str.find("qemu") != std::string::npos ||
                       str.find("hyper-v") != std::string::npos;
            }
            RegCloseKey(hKey);
        }
        return false;
    };

    // Check system manufacturer/model
    if (check_vm_reg("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemManufacturer"))
        return true;
    if (check_vm_reg("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName"))
        return true;

    // Check VM-specific registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    // Check CPUID for hypervisor bit
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    bool hypervisor = (cpuInfo[2] & (1 << 31)) != 0;
    if (hypervisor) return true;

    return false;
}

void Security::anti_memory_scan() {
    // Make sensitive memory regions no-access when not in use
    // This prevents Cheat Engine-style scanning
    HMODULE hModule = GetModuleHandleA(nullptr);
    if (!hModule) return;

    // Add guard pages to stack
    MEMORY_BASIC_INFORMATION mbi = {};
    VirtualQuery(&mbi, &mbi, sizeof(mbi));

    // Seal the PE header to prevent memory reads
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hModule;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        // Re-erase DOS header after anti_dump
        dos->e_magic = 0;
        dos->e_cblp = 0;
        dos->e_cp = 0;
    }
}

bool Security::integrity_check(const std::string& expected_hash) {
    if (expected_hash.empty()) return true; // Skip if no hash provided

    std::string exe_path = get_exe_path();
    std::string actual_hash = sha256_file(exe_path);

    if (actual_hash.empty()) return false; // Can't verify
    return actual_hash == expected_hash;
}

void Security::stop_all() {
    _running.exchange(false);
}

bool Security::is_running() {
    return _running.load();
}

void Security::set_on_violation(std::function<void(const std::string&)> callback) {
    _on_violation = callback;
}

void Security::monitor_loop(int interval_ms) {
    while (_running.load()) {
        // Check blocked processes
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {};
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (is_blocked_process(pe.szExeFile)) {
                        handle_violation(
                            std::string("Blocked process detected: ") +
                            std::string(pe.szExeFile, pe.szExeFile + wcslen(pe.szExeFile))
                        );
                        // Try to kill the process
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hProc) {
                            TerminateProcess(hProc, 1);
                            CloseHandle(hProc);
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        // Periodic anti-debug check
        if (anti_debug()) {
            handle_violation("Debugger detected during runtime");
        }

        // Periodic hook check
        if (anti_hook()) {
            handle_violation("API hooking detected during runtime");
        }

        Sleep(interval_ms);
    }
}

void Security::handle_violation(const std::string& reason) {
    if (_on_violation) {
        _on_violation(reason);
    }
    // Default: exit immediately
    ExitProcess(1);
}

} // namespace Authss
