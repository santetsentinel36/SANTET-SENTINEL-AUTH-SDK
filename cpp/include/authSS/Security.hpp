#pragma once
// =============================================================================
// SANTET SENTINEL — C++ SDK SECURITY MODULE (authSS)
// =============================================================================
// Proteksi anti-reverse-engineering, anti-debug, anti-dump, anti-hook, anti-VM.
// Dipanggil setelah Authss::Api berhasil init() untuk melindungi aplikasi.
//
// Contoh penggunaan:
//   Authss::Security::start_all();   // aktifkan semua proteksi
//   Authss::Security::anti_debug();  // cek debugger
//   Authss::Security::anti_dump();   // proteksi memory dump
//   Authss::Security::anti_vm();     // deteksi VM
//   Authss::Security::integrity_check(); // verifikasi hash file
//
// =============================================================================
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <functional>

namespace Authss {

class Security {
public:
    // ── Initialize All Protections ────────────────────────────────────────
    // Aktifkan semua proteksi sekaligus. Panggil sekali setelah login.
    static void start_all(int check_interval_ms = 2000);

    // ── Individual Protections ────────────────────────────────────────────

    // Anti-Debug: deteksi debugger (IsDebuggerPresent, NtQueryInformationProcess,
    // remote debugger, hardware breakpoints, timing check)
    static bool anti_debug();

    // Anti-Dump: proteksi memory dump (mprotect section .text, encrypt headers)
    static void anti_dump();

    // Anti-Hook: deteksi API hooking (IAT check, inline hook detection)
    static bool anti_hook();

    // Anti-VM: deteksi virtual machine (VMware, VirtualBox, Hyper-V, QEMU)
    static bool anti_vm();

    // Anti-Memory Scan: proteksi dari Cheat Engine / scanner
    static void anti_memory_scan();

    // Integrity Check: verifikasi hash file EXE
    static bool integrity_check(const std::string& expected_hash = "");

    // ── Control ───────────────────────────────────────────────────────────
    static void stop_all();
    static bool is_running();

    // ── Callbacks ─────────────────────────────────────────────────────────
    // Dipanggil saat pelanggaran terdeteksi
    static void set_on_violation(std::function<void(const std::string&)> callback);

private:
    static std::atomic<bool> _running;
    static std::thread _monitor_thread;
    static std::function<void(const std::string&)> _on_violation;

    static void monitor_loop(int interval_ms);
    static void handle_violation(const std::string& reason);
};

} // namespace Authss
