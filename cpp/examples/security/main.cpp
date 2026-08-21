// =============================================================================
// Santet Sentinel AuthSS — Security Example
// =============================================================================
#include "authSS/authSS.hpp"
#include "authSS/skCrypter.h"
#include <iostream>

int main() {
    std::cout << "=== Santet Sentinel AuthSS — Security ===" << std::endl;

    // 1. Init SDK
    std::string name    = skCrypt("your_app_name").decrypt();
    std::string ownerid = skCrypt("your_owner_id").decrypt();
    std::string secret  = skCrypt("your_app_secret").decrypt();
    std::string version = skCrypt("1.0").decrypt();
    std::string url     = skCrypt("https://santetsentinel.web.id/api/v1/client/").decrypt();

    Authss::Api authssapp(name, ownerid, version, secret, "", url);
    if (!authssapp.initialized) {
        std::cerr << "Init failed: " << authssapp.last_message << std::endl;
        return 1;
    }

    // 2. Individual security checks
    std::cout << "\n--- Individual Checks ---" << std::endl;
    std::cout << (Authss::Security::anti_debug() ? "[WARN] Debugger detected!" : "[OK] Anti-Debug pass") << std::endl;
    std::cout << (Authss::Security::anti_hook()  ? "[WARN] Hook detected!"     : "[OK] Anti-Hook pass")  << std::endl;
    std::cout << (Authss::Security::anti_vm()    ? "[WARN] VM detected!"       : "[OK] Anti-VM pass")    << std::endl;
    Authss::Security::anti_dump();
    std::cout << "[OK] Anti-Dump active" << std::endl;
    Authss::Security::anti_memory_scan();
    std::cout << "[OK] Anti-Memory-Scan active" << std::endl;

    // 3. Start all security with custom handler
    Authss::Security::set_on_violation([](const std::string& reason) {
        std::cerr << "\n[SECURITY VIOLATION] " << reason << std::endl;
        std::cerr << "Exiting..." << std::endl;
    });
    Authss::Security::start_all(2000);
    std::cout << "\n[OK] All security started (2s interval)" << std::endl;

    // 4. Integrity check (optional)
    std::string hash = Authss::Others::get_checksum();
    std::cout << "EXE Hash: " << hash.substr(0, 32) << "..." << std::endl;

    // 5. Login
    std::string user, pass;
    std::cout << "\nUsername: "; std::getline(std::cin, user);
    std::cout << "Password: "; std::getline(std::cin, pass);

    if (authssapp.login(user, pass)) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "  LOGIN OK — ALL PROTECTIONS ACTIVE" << std::endl;
        std::cout << "  User: " << authssapp.user_data.username << std::endl;
        std::cout << "  Plan: " << authssapp.user_data.subscription << std::endl;
        std::cout << "========================================" << std::endl;
        authssapp.start_ban_monitor(60);
        std::cout << "\nPress Enter to exit..." << std::endl;
        std::cin.get();
        Authss::Security::stop_all();
        authssapp.logout();
    } else {
        std::cerr << "Login failed: " << authssapp.last_message << std::endl;
    }
    return 0;
}
