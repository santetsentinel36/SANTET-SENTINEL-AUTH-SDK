// =============================================================================
// Santet Sentinel AuthSS — Login Example (all auth methods)
// =============================================================================
#include "authSS/authSS.hpp"
#include "authSS/skCrypter.h"
#include <iostream>

void menu() {
    std::cout << "\n=== MENU ===" << std::endl;
    std::cout << "  [1] Login (user+pass)" << std::endl;
    std::cout << "  [2] Register (license key)" << std::endl;
    std::cout << "  [3] Web Login (no HWID)" << std::endl;
    std::cout << "  [4] Upgrade" << std::endl;
    std::cout << "  [5] Check Session" << std::endl;
    std::cout << "  [0] Exit" << std::endl;
    std::cout << "  > ";
}

int main() {
    std::cout << "=== Santet Sentinel AuthSS — Login ===" << std::endl;

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
    Authss::Security::start_all();

    bool logged_in = false;
    while (true) {
        if (logged_in) {
            std::cout << "\n--- Logged In: " << authssapp.user_data.username
                      << " (" << authssapp.user_data.subscription << ") ---" << std::endl;
            std::cout << "  [1] Check Session  [2] Change Username  [3] Logout  [0] Exit\n  > ";
            std::string c; std::getline(std::cin, c);
            if (c == "1") {
                std::cout << (authssapp.check() ? "[OK] Session valid" : "[ERR] " + authssapp.last_message) << std::endl;
            } else if (c == "2") {
                std::cout << "New username: "; std::string nu; std::getline(std::cin, nu);
                std::cout << (authssapp.changeUsername(nu) ? "[OK] Changed" : "[ERR] " + authssapp.last_message) << std::endl;
            } else if (c == "3") { authssapp.logout(); logged_in = false; }
            else if (c == "0") break;
        } else {
            menu();
            std::string c; std::getline(std::cin, c);
            if (c == "1") {
                std::string u, p;
                std::cout << "Username: "; std::getline(std::cin, u);
                std::cout << "Password: "; std::getline(std::cin, p);
                logged_in = authssapp.login(u, p);
                std::cout << (logged_in ? "[OK] Login success" : "[ERR] " + authssapp.last_message) << std::endl;
                if (logged_in) authssapp.start_ban_monitor(120);
            } else if (c == "2") {
                std::string u, e, p, k;
                std::cout << "Username: "; std::getline(std::cin, u);
                std::cout << "Email: ";    std::getline(std::cin, e);
                std::cout << "Password: "; std::getline(std::cin, p);
                std::cout << "License Key: "; std::getline(std::cin, k);
                std::cout << (authssapp.registerAccount(u, e, p, k) ? "[OK] Registered" : "[ERR] " + authssapp.last_message) << std::endl;
            } else if (c == "3") {
                std::string u, p;
                std::cout << "Username: "; std::getline(std::cin, u);
                std::cout << "Password: "; std::getline(std::cin, p);
                logged_in = authssapp.webLogin(u, p);
                std::cout << (logged_in ? "[OK] Web login success" : "[ERR] " + authssapp.last_message) << std::endl;
                if (logged_in) authssapp.start_ban_monitor(120);
            } else if (c == "4") {
                std::string u, k;
                std::cout << "Username: "; std::getline(std::cin, u);
                std::cout << "New License Key: "; std::getline(std::cin, k);
                std::cout << (authssapp.upgrade(u, k) ? "[OK] Upgraded" : "[ERR] " + authssapp.last_message) << std::endl;
            } else if (c == "5") {
                std::string t;
                std::cout << "Token: "; std::getline(std::cin, t);
                std::cout << (authssapp.verifyToken(t) ? "[OK] Token valid" : "[ERR] " + authssapp.last_message) << std::endl;
            } else if (c == "0") break;
        }
    }
    std::cout << "Goodbye!" << std::endl;
    return 0;
}
