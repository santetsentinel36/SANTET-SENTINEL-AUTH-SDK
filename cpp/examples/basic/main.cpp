// =============================================================================
// Santet Sentinel AuthSS — Basic Example
// =============================================================================
#include "authSS/authSS.hpp"
#include "authSS/skCrypter.h"
#include <iostream>

int main() {
    std::cout << "=== Santet Sentinel AuthSS — Basic ===" << std::endl;

    // 1. Credentials
    std::string name    = skCrypt("your_app_name").decrypt();
    std::string ownerid = skCrypt("your_owner_id").decrypt();
    std::string secret  = skCrypt("your_app_secret").decrypt();
    std::string version = skCrypt("1.0").decrypt();
    std::string url     = skCrypt("https://santetsentinel.web.id/api/v1/client/").decrypt();

    // 2. Checksum
    std::string my_hash = Authss::Others::get_checksum();

    // 3. Init
    Authss::Api authssapp(name, ownerid, version, secret, my_hash, url);
    if (!authssapp.initialized) {
        std::cerr << "Init failed: " << authssapp.last_message << std::endl;
        return 1;
    }
    std::cout << "[OK] SDK initialized" << std::endl;

    // 4. Security
    Authss::Security::start_all();
    std::cout << "[OK] Security active" << std::endl;

    // 5. Login
    std::string user, pass;
    std::cout << "Username: "; std::getline(std::cin, user);
    std::cout << "Password: "; std::getline(std::cin, pass);

    if (authssapp.login(user, pass)) {
        std::cout << "[OK] Logged in: " << authssapp.user_data.username << std::endl;
        std::cout << "    Plan: " << authssapp.user_data.subscription << std::endl;
        std::cout << "    Expires: " << authssapp.user_data.expires << std::endl;
        authssapp.start_ban_monitor(120);
        std::cout << "Tekan Enter untuk logout..." << std::endl;
        std::cin.get();
        authssapp.logout();
    } else {
        std::cerr << "Login failed: " << authssapp.last_message << std::endl;
    }

    return 0;
}
