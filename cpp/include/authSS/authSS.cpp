// =============================================================================
// SANTET SENTINEL — C++ SDK IMPLEMENTATION (authSS)
// =============================================================================
// Pola API 100% sama dengan AuthLX. Semua request ke backend Santet Sentinel.
// Server default: https://santetsentinel.web.id/api/v1/client/
// =============================================================================
#include "authSS.hpp"
#include "Logger.hpp"
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <sddl.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace Authss {

// ── Helper: Convert string to wstring ───────────────────────────────────────
static std::wstring to_wstring(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// ── Helper: Convert wstring to string ───────────────────────────────────────
static std::string to_string(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// ── Helper: Null-safe JSON string getter ────────────────────────────────────
static std::string safe_json_string(const nlohmann::json& j, const std::string& key, const std::string& fallback = "") {
    if (!j.is_object() || !j.contains(key) || j[key].is_null()) return fallback;
    try {
        if (j[key].is_string()) return j[key].get<std::string>();
    } catch (...) {}
    return fallback;
}

// ── Helper: Parse URL into host and path prefix ────────────────────────────
static void parse_url(const std::string& url, std::wstring& host, std::wstring& path_prefix, INTERNET_PORT& port) {
    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);
    std::wstring wurl = to_wstring(url);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    if (WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        host = std::wstring(urlComp.lpszHostName, urlComp.dwHostNameLength);
        path_prefix = std::wstring(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        port = urlComp.nPort;
    } else {
        // Default fallback — Santet Sentinel
        host = L"santetsentinel.web.id";
        path_prefix = L"/api/v1/client";
        port = INTERNET_DEFAULT_HTTPS_PORT;
    }
}

static void fatal_error(const std::string& msg) {
    std::cerr << "\n[ERROR] " << msg << std::endl;
    std::cerr << "Press Enter to exit..." << std::endl;
    std::cin.clear();
    std::cin.sync();
    std::cin.get();
    ExitProcess(1);
}

// ── Helper: Generate random hex string of size ─────────────────────────────
static std::string generate_nonce(size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, 15);
    std::string nonce;
    nonce.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        nonce += hex_chars[distribution(generator)];
    }
    return nonce;
}

// ── Helper: HMAC-SHA256 using Windows CNG (BCrypt) ────────────────────────
static std::string hmac_sha256(const std::string& key, const std::string& msg) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;
    DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) return "";
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);

    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, (PUCHAR)key.c_str(), (ULONG)key.length(), 0);
    if (status >= 0) {
        status = BCryptHashData(hHash, (PUCHAR)msg.c_str(), (ULONG)msg.length(), 0);
        if (status >= 0) {
            status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        }
        BCryptDestroyHash(hHash);
    }

    std::stringstream ss;
    if (status >= 0) {
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
        }
    }

    HeapFree(GetProcessHeap(), 0, pbHashObject);
    HeapFree(GetProcessHeap(), 0, pbHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ss.str();
}

// ── Helper: SHA256 of data using CNG ───────────────────────────────────────
static std::string sha256(const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;
    DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) return "";
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (status < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);

    status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
    if (status >= 0) {
        status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        if (status >= 0) {
            status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        }
        BCryptDestroyHash(hHash);
    }

    std::stringstream ss;
    if (status >= 0) {
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)pbHash[i];
        }
    }

    HeapFree(GetProcessHeap(), 0, pbHashObject);
    HeapFree(GetProcessHeap(), 0, pbHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ss.str();
}

// ─── Constructor & Destructor ───────────────────────────────────────────────

Api::Api(std::string name, std::string ownerid, std::string version,
         std::string client_secret, std::string hash_to_check, std::string api_url)
    : name(name), ownerid(ownerid), version(version),
      client_secret(client_secret), api_url(api_url) {

    // Default ke Santet Sentinel API endpoint (sama seperti AuthLX default ke api.authlx.com)
    if (this->api_url.empty()) {
        this->api_url = "https://santetsentinel.web.id/api/v1/client";
    }

    // Strip trailing slash
    while (!this->api_url.empty() && this->api_url.back() == '/') {
        this->api_url.pop_back();
    }

    if (hash_to_check.empty()) {
        this->hash_to_check = Others::get_checksum();
    } else {
        this->hash_to_check = hash_to_check;
    }

    // Default host whitelist — blocks DNS redirect attacks.
    // Only santetsentinel.web.id is ever a valid destination.
    if (allowed_hosts.empty()) {
        allowed_hosts = {"santetsentinel.web.id"};
    }

    // Initialize WinHTTP Session with direct access (ignores system proxy - Anti-MITM)
    hSession = WinHttpOpen(
        L"SANTET-SENTINEL-CPP/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) {
        std::cerr << "AuthSS: Failed to initialize WinHTTP session." << std::endl;
        ExitProcess(1);
    }

    // Set reasonable timeouts (5s each)
    WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);

    // Auto-initialize SDK (sama seperti AuthLX)
    init();
}

Api::~Api() {
    stop_ban_monitor();
    if (hSession) {
        WinHttpCloseHandle(hSession);
    }
}

// ─── Core lifecycle ─────────────────────────────────────────────────────────

void Api::init() {
    // Intercept --authss-update-finish stage before anything else
    handle_update_stage();

    // Cleanup previous .old backup if it exists
    std::wstring current_exe = get_current_executable_path();
    if (!current_exe.empty()) {
        std::wstring old_backup = current_exe + L".old";
        DWORD dwAttrib = GetFileAttributesW(old_backup.c_str());
        if (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
            if (!DeleteFileW(old_backup.c_str())) {
                MoveFileExW(old_backup.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
        }
    }

    Others::anti_debug();

    // SECURITY: client_secret is intentionally NOT included in the /init payload.
    // It lives exclusively in this compiled binary for local HMAC response verification.
    nlohmann::json payload = {
        {"app_id", ownerid},
        {"name", name},
        {"version", version}
    };

    nlohmann::json response = do_request("/init", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        auto app_info = response.value("app_info", nlohmann::json::object());
        std::string server_version = app_info.value("version", version);
        std::string server_name = app_info.value("name", name);

        if (server_name != name) {
            LOG_ERROR("[SECURITY] Application name mismatch! Expected: " << name << " | Server reports: " << server_name);
            last_message = "Application name mismatch! Expected: " + name + " | Server reports: " + server_name;
            initialized = false;
            return;
        }

        auto clean_ver = [](std::string v) -> std::string {
            size_t start = v.find_first_not_of(" \t\r\n");
            if (start != std::string::npos) v = v.substr(start);
            if (!v.empty() && (v[0] == 'v' || v[0] == 'V')) {
                v = v.substr(1);
            }
            return v;
        };

        if (clean_ver(server_version) != clean_ver(version)) {
            LOG_ERROR("[UPDATE REQUIRED] Application version is outdated! Current: " << version << " | Required: " << server_version);
            last_message = "Application version is outdated! Current: " + version + " | Required: " + server_version;
            if (auto_update_enabled) {
                LOG_INFO("[AUTO-UPDATE] Initiating auto-update to " << server_version << "...");
                UpdateInfo info = check_for_updates();
                info.update_available = true;
                perform_update(info);
            }
            initialized = false;
            return;
        }

        initialized = true;
        hwid_method = app_info.value("hwid_method", "windows_user");
        LOG_INFO("SDK Initialized successfully. Name: " << name << ", Version: " << version << ", HWID Method: " << hwid_method);
        if (debug) {
            LOG_DEBUG("Hash mode: " << (client_secret.empty() ? "OFF" : "SECURE"));
        }
    } else {
        std::string err_msg = "Failed to initialise. Check ownerid and network connectivity.";
        if (!response.is_null() && response.contains("message")) {
            err_msg = response.value("message", "");
        }
        LOG_ERROR("Initialization failed: " << err_msg);
        last_message = err_msg;
        initialized = false;
    }
}

// ─── HMAC helper ────────────────────────────────────────────────────────────

std::tuple<std::string, std::string, std::string> Api::compute_hash_signature() {
    std::string timestamp = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    std::string nonce = generate_nonce(32);
    std::string data_to_sign = hash_to_check + ":" + timestamp + ":" + nonce;
    std::string signature = hmac_sha256(client_secret, data_to_sign);
    return { signature, timestamp, nonce };
}

nlohmann::json Api::build_hash_payload() {
    nlohmann::json payload;
    payload["hash"] = hash_to_check;
    if (!client_secret.empty()) {
        std::string sig, ts, nonce;
        std::tie(sig, ts, nonce) = compute_hash_signature();
        payload["hash_signature"] = sig;
        payload["hash_timestamp"] = ts;
        payload["hash_nonce"] = nonce;
    }
    return payload;
}

// ─── Signed Response Protocol (SRP) ────────────────────────────────────────
//
// Every SDK request embeds a random `request_nonce`.
// The server echoes this nonce back in X-Response-Nonce and includes
// X-Response-Sig = HMAC_SHA256(canonical_body + ":" + nonce, client_secret).
//
// The SDK verifies:
// 1. X-Response-Nonce == the nonce we sent → prevents stored-response replay
// 2. HMAC locally recomputed == X-Response-Sig → proves the server holds client_secret
//
// Result: HTTP Debugger/Fiddler cannot spoof responses without knowing client_secret.

std::string Api::generate_request_nonce() {
    return generate_nonce(32);
}

bool Api::verify_response_signature(
    const std::string& response_body,
    const std::string& request_nonce,
    const std::string& sig_header,
    const std::string& nonce_header
) {
    if (sig_header.empty() || nonce_header.empty()) {
        if (!client_secret.empty()) {
            LOG_ERROR("[SRP] *** CRITICAL: Signature headers missing on secret-enabled app. "
                      "Possible header-stripping MITM attack. ***");
            return false;
        }
        if (debug) {
            LOG_DEBUG("[SRP] No signature headers and no secret — unsigned mode, skipping.");
        }
        return true;
    }

    // 1. Verify nonce echo — prevents stored-response replay attacks.
    if (nonce_header != request_nonce) {
        LOG_ERROR("[SRP] *** NONCE MISMATCH! Expected: " << request_nonce
                  << " | Got: " << nonce_header << " ***");
        LOG_ERROR("[SRP] Response replay or spoofing attempt DETECTED.");
        return false;
    }

    // 2. Recompute expected HMAC locally.
    std::string canonical_body;
    try {
        canonical_body = nlohmann::json::parse(response_body).dump();
    } catch (...) {
        canonical_body = response_body;
    }

    std::string payload = canonical_body + ":" + request_nonce;
    std::string expected_sig = hmac_sha256(client_secret, payload);

    if (expected_sig.empty()) {
        LOG_ERROR("[SRP] Failed to compute local HMAC — BCrypt error.");
        return false;
    }

    // 3. Constant-time comparison — prevents timing side-channel attacks.
    if (expected_sig.size() != sig_header.size()) {
        LOG_ERROR("[SRP] *** SIGNATURE LENGTH MISMATCH — spoofing attempt. ***");
        return false;
    }

    int diff = 0;
    for (size_t i = 0; i < expected_sig.size(); ++i) {
        diff |= (expected_sig[i] ^ sig_header[i]);
    }

    if (diff != 0) {
        LOG_ERROR("[SRP] *** SIGNATURE MISMATCH! Response has been tampered or spoofed. ***");
        return false;
    }

    if (debug) {
        LOG_DEBUG("[SRP] Response signature verified OK. Nonce: " << request_nonce.substr(0, 8) << "...");
    }
    return true;
}

// ─── Authentication (sama seperti AuthLX) ───────────────────────────────────

bool Api::login(std::string user, std::string password, std::string hwid) {
    if (!checkinit()) return false;
    if (hwid.empty()) {
        hwid = Others::get_hwid(hwid_method);
    }

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"username", user},
        {"password", password},
        {"hwid", hwid},
        {"version", version}
    };

    nlohmann::json hash_payload = build_hash_payload();
    for (auto& el : hash_payload.items()) {
        payload[el.key()] = el.value();
    }

    nlohmann::json response = do_request("/login", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        auto data = response.value("data", nlohmann::json::object());
        session_token = data.value("token", "");
        load_user_data(data.value("user", nlohmann::json::object()));

        if (!has_active_subscription()) {
            std::cerr << "Login Failed: Subscription has expired or is paused." << std::endl;
            session_token = "";
            user_data.is_authenticated = false;
            return false;
        }

        mark_authenticated();

        if (!check()) {
            session_token = "";
            user_data.is_authenticated = false;
            std::cerr << "Login Failed: Immediate session verification failed." << std::endl;
            return false;
        }

        std::cout << "Successfully logged in as '" << user_data.username << "'!" << std::endl;
        return true;
    }

    std::string msg = response.is_null() ? "No server response." : response.value("message", "Login failed.");
    parse_ban_info(msg);
    std::cerr << "Login Failed: " << msg << std::endl;
    login_hint(msg);
    return false;
}

bool Api::registerAccount(std::string user, std::string email, std::string password,
                          std::string license_key, std::string hwid) {
    if (!checkinit()) return false;
    if (hwid.empty()) {
        hwid = Others::get_hwid(hwid_method);
    }

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"username", user},
        {"email", email},
        {"password", password},
        {"license_key", license_key},
        {"hwid", hwid}
    };

    nlohmann::json hash_payload = build_hash_payload();
    for (auto& el : hash_payload.items()) {
        payload[el.key()] = el.value();
    }

    nlohmann::json response = do_request("/register", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        std::cout << response.value("message", "Registration successful!") << std::endl;
        return true;
    }

    std::string msg = response.is_null() ? "No server response." : response.value("message", "Registration failed.");
    parse_ban_info(msg);
    std::cerr << "Registration Failed: " << msg << std::endl;
    login_hint(msg);
    return false;
}

bool Api::webLogin(std::string user, std::string password) {
    if (!checkinit()) return false;
    if (lockout_active()) {
        long long secs = lockout_remaining_ms() / 1000;
        std::cerr << "Locked out due to multiple failed attempts. Try again in " << secs << "s." << std::endl;
        return false;
    }

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"username", user},
        {"password", password}
    };

    nlohmann::json response = do_request("/web-login", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        auto data = response.value("data", nlohmann::json::object());
        session_token = data.value("token", "");
        load_user_data(data.value("user", nlohmann::json::object()));
        reset_lockout();

        if (!has_active_subscription()) {
            std::cerr << "Web Login Failed: Subscription has expired or is paused." << std::endl;
            session_token = "";
            user_data.is_authenticated = false;
            return false;
        }

        mark_authenticated();
        std::cout << "Successfully logged in (Web)!" << std::endl;
        return true;
    }

    record_login_fail();
    Sleep(2000);
    std::string msg = response.is_null() ? "No server response." : response.value("message", "Web login failed.");
    parse_ban_info(msg);
    std::cerr << "Web Login Failed: " << msg << std::endl;
    return false;
}

bool Api::registerWeb(std::string user, std::string email, std::string password, std::string license_key) {
    return registerAccount(user, email, password, license_key, "WEB_REGISTRATION");
}

bool Api::logout() {
    if (!checkinit()) return false;
    if (session_token.empty()) {
        std::cerr << "Not logged in." << std::endl;
        return false;
    }

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"session_token", session_token}
    };

    nlohmann::json response = do_request("/logout", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        std::cout << response.value("message", "Logged out.") << std::endl;
        session_token = "";
        user_data = UserData();
        return true;
    }

    std::string msg = response.is_null() ? "No server response." : response.value("message", "Logout failed.");
    std::cerr << msg << std::endl;
    return false;
}

// ─── License operations ─────────────────────────────────────────────────────

bool Api::upgrade(std::string user, std::string license_key) {
    if (!checkinit()) return false;

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"username", user},
        {"license_key", license_key}
    };

    nlohmann::json response = do_request("/upgrade", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        std::cout << response.value("message", "License successfully applied!") << std::endl;
        return true;
    }

    std::string msg = response.is_null() ? "No response." : response.value("message", "Upgrade failed.");
    parse_ban_info(msg);
    std::cerr << "Upgrade Failed: " << msg << std::endl;
    return false;
}

// ─── Verification ───────────────────────────────────────────────────────────

bool Api::check() {
    if (!checkinit()) return false;
    if (session_token.empty()) return false;

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"token", session_token}
    };

    nlohmann::json response = do_request("/verify-session", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        auto sess = response.value("session", nlohmann::json::object());
        if (!sess.empty()) {
            std::string fresh_expiry = sess.value("expiry", "");
            std::string fresh_sub = sess.value("subscription", "");
            std::string acct_status = sess.value("account_status", "active");

            if (!fresh_expiry.empty()) user_data.expires = fresh_expiry;
            if (!fresh_sub.empty()) user_data.subscription = fresh_sub;

            if (acct_status == "banned" || acct_status == "paused" ||
                acct_status == "expired" || acct_status == "deleted") {
                LOG_ERROR("[SECURITY] Session check: account status is '" << acct_status << "'. Terminating.");
                user_data.is_authenticated = false;
                session_token = "";
                return false;
            }
        }
        return true;
    }
    return false;
}

bool Api::verifyToken(std::string standalone_token) {
    if (!checkinit()) return false;

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"token", standalone_token}
    };

    nlohmann::json response = do_request("/verify-token", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        std::cout << "Token is valid!" << std::endl;
        return true;
    }

    std::string msg = response.is_null() ? "No response." : response.value("message", "Invalid or banned token.");
    parse_ban_info(msg);
    std::cerr << msg << std::endl;
    return false;
}

// ─── Account management ─────────────────────────────────────────────────────

bool Api::changeUsername(std::string new_username) {
    if (!checkinit()) return false;
    if (session_token.empty()) {
        std::cerr << "Must be logged in to change username." << std::endl;
        return false;
    }

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"session_token", session_token},
        {"new_username", new_username}
    };

    nlohmann::json response = do_request("/change-username", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        std::cout << response.value("message", "Username changed!") << std::endl;
        user_data.username = new_username;
        return true;
    }

    std::string msg = response.is_null() ? "No response." : response.value("message", "Failed.");
    std::cerr << "changeUsername Failed: " << msg << std::endl;
    return false;
}

bool Api::forgot(std::string user, std::string new_password, std::string hwid) {
    if (!checkinit()) return false;
    if (hwid.empty()) {
        hwid = Others::get_hwid(hwid_method);
    }

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"username", user},
        {"hwid", hwid},
        {"new_password", new_password}
    };

    nlohmann::json response = do_request("/forgot", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        std::cout << response.value("message", "Password reset!") << std::endl;
        return true;
    }

    std::string msg = response.is_null() ? "No response." : response.value("message", "Failed.");
    std::cerr << "forgot Failed: " << msg << std::endl;
    return false;
}

// ─── Variable Management ────────────────────────────────────────────────────

std::string Api::var(std::string name) {
    if (!checkinit()) return "";
    if (session_token.empty()) return "";

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"token", session_token},
        {"var_name", name}
    };

    nlohmann::json response = do_request("/var", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        return response.value("data", nlohmann::json::object()).value("value", "");
    }
    return "";
}

std::string Api::get_user_var(std::string key) {
    if (!checkinit()) return "";
    if (session_token.empty()) return "";

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"token", session_token},
        {"key", key}
    };

    nlohmann::json response = do_request("/user-var", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        return response.value("data", nlohmann::json::object()).value("value", "");
    }
    return "";
}

bool Api::set_user_var(std::string key, std::string value) {
    if (!checkinit()) return false;
    if (session_token.empty()) return false;

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"token", session_token},
        {"key", key},
        {"value", value}
    };

    nlohmann::json response = do_request("/user-var/set", payload);

    return !response.is_null() && response.value("status", "") == "success";
}

// ─── Subscription & Expiry helpers ──────────────────────────────────────────

bool Api::has_active_subscription() {
    return expiry_remaining() > 0.0;
}

double Api::expiry_remaining() {
    if (user_data.expires.empty()) {
        return 0.0;
    }

    std::string s = user_data.expires;
    if (s.back() == 'Z') {
        s.pop_back();
    } else {
        size_t plus_pos = s.find('+');
        if (plus_pos != std::string::npos) {
            s = s.substr(0, plus_pos);
        }
    }

    std::tm t = {};
    std::stringstream ss(s);
    char sep;
    ss >> t.tm_year >> sep >> t.tm_mon >> sep >> t.tm_mday >> sep
       >> t.tm_hour >> sep >> t.tm_min >> sep >> t.tm_sec;
    t.tm_year -= 1900;
    t.tm_mon -= 1;
    t.tm_isdst = -1;

    time_t exp_time = _mkgmtime(&t);
    time_t now = time(nullptr);
    double diff = difftime(exp_time, now);
    return diff > 0.0 ? diff : 0.0;
}

// ─── Auth runtime state ─────────────────────────────────────────────────────

void Api::mark_authenticated() {
    user_data.is_authenticated = true;
    user_data.auth_runtime_start = (double)time(nullptr);
}

void Api::refresh_auth_runtime() {
    user_data.auth_runtime_start = (double)time(nullptr);
}

void Api::reset_auth_runtime() {
    refresh_auth_runtime();
}

// ─── Host Locking & Key Pinning ─────────────────────────────────────────────

void Api::set_allowed_hosts(std::vector<std::string> hosts) {
    allowed_hosts = hosts;
}

void Api::add_allowed_host(std::string host) {
    if (std::find(allowed_hosts.begin(), allowed_hosts.end(), host) == allowed_hosts.end()) {
        allowed_hosts.push_back(host);
    }
}

void Api::clear_allowed_hosts() {
    allowed_hosts.clear();
}

void Api::set_pinned_public_keys(std::vector<std::string> keys) {
    pinned_public_keys = keys;
}

void Api::add_pinned_public_key(std::string key) {
    if (std::find(pinned_public_keys.begin(), pinned_public_keys.end(), key) == pinned_public_keys.end()) {
        pinned_public_keys.push_back(key);
    }
}

void Api::clear_pinned_public_keys() {
    pinned_public_keys.clear();
}

// ─── Secure Cryptography (XOR / Seal) ──────────────────────────────────────

void Api::enable_secure_strings() {
    secure_strings_enabled = true;
}

void Api::derive_secure_key(std::string material) {
    std::vector<uint8_t> bytes(material.begin(), material.end());
    std::string hex_hash = sha256(bytes);
    secure_key.resize(32);
    for (size_t i = 0; i < 32; ++i) {
        std::string hex_byte = hex_hash.substr(i * 2, 2);
        secure_key[i] = (uint8_t)std::stoul(hex_byte, nullptr, 16);
    }
}

std::string Api::xor_crypt_field(std::string data, std::string key) {
    std::string result = data;
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

std::string Api::compute_auth_seal(std::string payload) {
    if (secure_key.empty()) return "";
    std::string key_str(secure_key.begin(), secure_key.end());
    return hmac_sha256(key_str, payload);
}

// ─── Ban monitor ────────────────────────────────────────────────────────────

void Api::start_ban_monitor(int interval_seconds) {
    if (ban_monitor_active) return;
    ban_monitor_active = true;
    ban_monitor_thread = std::thread(&Api::ban_monitor_loop, this, interval_seconds);
    if (debug) {
        std::cout << "[DEBUG] Ban monitor started." << std::endl;
    }
}

void Api::stop_ban_monitor() {
    if (ban_monitor_active) {
        ban_monitor_active = false;
        if (ban_monitor_thread.joinable()) {
            ban_monitor_thread.join();
        }
        if (debug) {
            std::cout << "[DEBUG] Ban monitor stopped." << std::endl;
        }
    }
}

bool Api::ban_monitor_running() {
    return ban_monitor_active;
}

void Api::ban_monitor_loop(int interval) {
    const int max_interval = 20;
    const int effective_interval = (interval > max_interval) ? max_interval : interval;

    while (ban_monitor_active) {
        if (session_token.empty()) {
            Sleep(1000);
            continue;
        }

        if (debug) {
            std::cout << "[DEBUG] Ban monitor: checking session (interval=" << effective_interval << "s)..." << std::endl;
        }

        if (!check() || !has_active_subscription()) {
            LOG_ERROR("[SECURITY] Session revoked, user deleted, subscription expired, or account banned.");
            LOG_ERROR("[SECURITY] Terminating application. No bypass possible.");
            user_data.is_authenticated = false;
            session_token = "";

#ifdef _WIN32
            HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
            if (hInput != INVALID_HANDLE_VALUE && hInput != nullptr) {
                INPUT_RECORD ir[2] = { 0 };
                ir[0].EventType = KEY_EVENT;
                ir[0].Event.KeyEvent.bKeyDown = TRUE;
                ir[0].Event.KeyEvent.wRepeatCount = 1;
                ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
                ir[0].Event.KeyEvent.wVirtualScanCode = (WORD)MapVirtualKey(VK_RETURN, 0);
                ir[0].Event.KeyEvent.uChar.UnicodeChar = L'\r';
                ir[1] = ir[0];
                ir[1].Event.KeyEvent.bKeyDown = FALSE;
                DWORD written = 0;
                WriteConsoleInput(hInput, ir, 2, &written);
            }
#endif
            ExitProcess(1);
        }

        for (int i = 0; i < effective_interval && ban_monitor_active; ++i) {
            Sleep(1000);
        }
    }
}

// ─── Rate limiting & lockouts ───────────────────────────────────────────────

void Api::record_login_fail() {
    login_fails++;
    if (login_fails >= 3) {
        lockout_end = (double)time(nullptr) + 300.0; // 5-minute lockout
    }
}

bool Api::lockout_active() {
    double now = (double)time(nullptr);
    if (now < lockout_end) return true;
    if (lockout_end > 0.0 && now >= lockout_end) reset_lockout();
    return false;
}

long long Api::lockout_remaining_ms() {
    if (!lockout_active()) return 0;
    double now = (double)time(nullptr);
    double diff = lockout_end - now;
    return diff > 0.0 ? (long long)(diff * 1000.0) : 0;
}

void Api::reset_lockout() {
    login_fails = 0;
    lockout_end = 0.0;
}

// ─── Debug helpers ──────────────────────────────────────────────────────────

void Api::setDebug(bool enable) {
    debug = enable;
}

void Api::add_pinned_cert(std::string sha256_hash) {
    std::transform(sha256_hash.begin(), sha256_hash.end(), sha256_hash.begin(), ::tolower);
    this->pinned_cert_hashes.push_back(sha256_hash);
}

std::map<std::string, std::string> Api::debugInfo() {
    std::map<std::string, std::string> info;
    info["debug_enabled"] = debug ? "true" : "false";
    info["name"] = name;
    info["ownerid"] = ownerid;
    info["version"] = version;
    info["api_url"] = api_url;
    info["hwid_method"] = hwid_method;
    info["initialized"] = initialized ? "true" : "false";
    info["session_token"] = session_token.empty() ? "(none)" : session_token.substr(0, 16) + "...";
    info["client_secret_mode"] = client_secret.empty() ? "OFF" : "SECURE";
    info["hash_to_check"] = hash_to_check.empty() ? "(none)" : hash_to_check.substr(0, 24) + "...";
    info["auto_update_enabled"] = auto_update_enabled ? "true" : "false";
    info["ban_monitor_active"] = ban_monitor_active ? "true" : "false";
    info["secure_strings_enabled"] = secure_strings_enabled ? "true" : "false";
    info["allowed_hosts_count"] = std::to_string(allowed_hosts.size());
    info["pinned_certs_count"] = std::to_string(pinned_cert_hashes.size());
    return info;
}

// ─── Internal: HTTP request via WinHTTP ─────────────────────────────────────

nlohmann::json Api::do_request(std::string endpoint, nlohmann::json post_data) {
    if (!hSession) {
        LOG_ERROR("[HTTP] WinHTTP session not initialized.");
        return nullptr;
    }

    // Host whitelist check
    std::wstring host, path_prefix;
    INTERNET_PORT port;
    parse_url(api_url, host, path_prefix, port);

    bool host_allowed = false;
    std::string host_utf8 = to_string(host);
    for (const auto& allowed : allowed_hosts) {
        if (host_utf8 == allowed) { host_allowed = true; break; }
    }
    if (!host_allowed && !allowed_hosts.empty()) {
        LOG_ERROR("[SECURITY] Host '" << host_utf8 << "' is NOT in the allowed hosts whitelist!");
        last_message = "DNS redirect / spoofing detected. Host not allowed.";
        return nullptr;
    }

    // Add request nonce for SRP
    std::string request_nonce = generate_request_nonce();
    post_data["request_nonce"] = request_nonce;

    // Serialize JSON body
    std::string body = post_data.dump();
    std::wstring wbody(body.begin(), body.end());

    std::wstring full_path = path_prefix + std::wstring(endpoint.begin(), endpoint.end());

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        LOG_ERROR("[HTTP] WinHttpConnect failed. Error: " << GetLastError());
        return nullptr;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", full_path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hRequest) {
        LOG_ERROR("[HTTP] WinHttpOpenRequest failed. Error: " << GetLastError());
        WinHttpCloseHandle(hConnect);
        return nullptr;
    }

    // Set timeouts
    WinHttpSetTimeouts(hRequest, 10000, 10000, 30000, 30000);

    // Set SSL options
    DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                           SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                           SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));

    // Add headers
    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    headers += L"X-Request-Nonce: " + std::wstring(request_nonce.begin(), request_nonce.end()) + L"\r\n";

    BOOL bResults = WinHttpSendRequest(hRequest,
        headers.c_str(), (DWORD)headers.length(),
        (LPVOID)wbody.c_str(), (DWORD)wbody.length(),
        (DWORD)wbody.length(), 0);

    if (!bResults) {
        LOG_ERROR("[HTTP] WinHttpSendRequest failed. Error: " << GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return nullptr;
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        LOG_ERROR("[HTTP] WinHttpReceiveResponse failed. Error: " << GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        return nullptr;
    }

    // Read response
    std::string response_body;
    DWORD bytes_available = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytes_available) && bytes_available > 0) {
        std::vector<char> buffer(bytes_available + 1, 0);
        DWORD bytes_read = 0;
        if (WinHttpReadData(hRequest, buffer.data(), bytes_available, &bytes_read)) {
            response_body.append(buffer.data(), bytes_read);
        }
        bytes_available = 0;
    }

    // Read response headers for SRP verification
    std::string sig_header;
    std::string nonce_header;
    {
        DWORD header_size = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM | WINHTTP_QUERY_FLAG_REQUEST_HEADERS,
            L"X-Response-Sig", WINHTTP_NO_OUTPUT_INDEX, &header_size);
        if (header_size > 0) {
            std::vector<wchar_t> header_buf(header_size / sizeof(wchar_t) + 1, 0);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM | WINHTTP_QUERY_FLAG_REQUEST_HEADERS,
                L"X-Response-Sig", header_buf.data(), &header_size);
            sig_header = to_string(std::wstring(header_buf.data()));
        }
    }
    {
        DWORD header_size = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM | WINHTTP_QUERY_FLAG_REQUEST_HEADERS,
            L"X-Response-Nonce", WINHTTP_NO_OUTPUT_INDEX, &header_size);
        if (header_size > 0) {
            std::vector<wchar_t> header_buf(header_size / sizeof(wchar_t) + 1, 0);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM | WINHTTP_QUERY_FLAG_REQUEST_HEADERS,
                L"X-Response-Nonce", header_buf.data(), &header_size);
            nonce_header = to_string(std::wstring(header_buf.data()));
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);

    // Verify SRP signature
    if (!client_secret.empty()) {
        if (!verify_response_signature(response_body, request_nonce, sig_header, nonce_header)) {
            LOG_ERROR("[SECURITY] Response signature verification FAILED. Possible spoofing/MITM attack.");
            last_message = "Security verification failed. Possible tampering detected.";
            return nullptr;
        }
    }

    // Parse JSON response
    try {
        return nlohmann::json::parse(response_body);
    } catch (const std::exception& e) {
        LOG_ERROR("[HTTP] Failed to parse JSON response: " << e.what());
        return nullptr;
    }
}

// ─── Internal: checkinit ────────────────────────────────────────────────────

bool Api::checkinit() {
    if (!initialized) {
        LOG_ERROR("[SDK] SDK not initialized. Call init() first.");
        last_message = "SDK not initialized.";
        return false;
    }
    return true;
}

// ─── Internal: load_user_data ───────────────────────────────────────────────

void Api::load_user_data(nlohmann::json data) {
    if (data.is_null() || !data.is_object()) return;

    user_data.username = safe_json_string(data, "username", user_data.username);
    user_data.hwid = safe_json_string(data, "hwid", user_data.hwid);
    user_data.expires = safe_json_string(data, "expires", user_data.expires);
    user_data.createdate = safe_json_string(data, "createdate", user_data.createdate);
    user_data.lastlogin = safe_json_string(data, "lastlogin", user_data.lastlogin);
    user_data.subscription = safe_json_string(data, "subscription", user_data.subscription);

    // Parse subscriptions array
    if (data.contains("subscriptions") && data["subscriptions"].is_array()) {
        user_data.subscriptions.clear();
        for (const auto& sub : data["subscriptions"]) {
            SubscriptionInfo si;
            si.subscription = safe_json_string(sub, "subscription");
            si.expiry = safe_json_string(sub, "expiry");
            user_data.subscriptions.push_back(si);
        }
    }
}

// ─── Internal: parse_ban_info ───────────────────────────────────────────────

void Api::parse_ban_info(std::string msg) {
    ban_reason = "";
    ban_revoke_date = "";

    size_t ban_pos = msg.find("[BANNED]");
    if (ban_pos != std::string::npos) {
        ban_reason = msg.substr(ban_pos + 8);
        // Trim
        size_t start = ban_reason.find_first_not_of(" \t\r\n");
        if (start != std::string::npos) ban_reason = ban_reason.substr(start);
    }

    size_t revoke_pos = msg.find("revoke_date:");
    if (revoke_pos != std::string::npos) {
        ban_revoke_date = msg.substr(revoke_pos + 12);
        size_t end = ban_revoke_date.find_first_of(" \t\r\n]");
        if (end != std::string::npos) ban_revoke_date = ban_revoke_date.substr(0, end);
    }
}

// ─── Internal: login_hint ───────────────────────────────────────────────────

void Api::login_hint(std::string msg) {
    if (msg.find("HWID") != std::string::npos) {
        LOG_INFO("[HINT] This account is bound to a different Hardware ID.");
        LOG_INFO("[HINT] Use 'forgot' to reset, or contact support.");
    }
}

// ─── Internal: download_file_winhttp ────────────────────────────────────────

bool Api::download_file_winhttp(const std::string& url, const std::wstring& target_path) {
    // Parse download URL
    std::wstring dl_host, dl_path;
    INTERNET_PORT dl_port;
    parse_url(url, dl_host, dl_path, dl_port);

    HINTERNET hSess = WinHttpOpen(L"AuthSS-AutoUpdate/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return false;

    HINTERNET hConn = WinHttpConnect(hSess, dl_host.c_str(), dl_port, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return false; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", dl_path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return false; }

    BOOL sent = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (!sent || !WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return false;
    }

    std::ofstream ofs(target_path, std::ios::binary | std::ios::out);
    if (!ofs.is_open()) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return false;
    }

    char buf[8192];
    DWORD rd = 0;
    while (WinHttpReadData(hReq, buf, sizeof(buf), &rd) && rd > 0) {
        ofs.write(buf, rd);
        rd = 0;
    }
    ofs.close();

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return true;
}

// ─── Internal: validate_download_url ────────────────────────────────────────

std::pair<bool, std::string> Api::validate_download_url(const std::string& url) {
    // Basic URL validation — only allow HTTPS downloads from known hosts
    if (url.substr(0, 8) != "https://") {
        return {false, "Download URL must use HTTPS."};
    }

    // Check host is in allowed list
    std::wstring dl_host, dl_path;
    INTERNET_PORT dl_port;
    parse_url(url, dl_host, dl_path, dl_port);
    std::string host_str = to_string(dl_host);

    bool host_ok = false;
    for (const auto& h : allowed_hosts) {
        if (host_str == h || host_str.find("." + h) != std::string::npos) {
            host_ok = true;
            break;
        }
    }

    // Also allow GitHub releases
    if (host_str.find("github.com") != std::string::npos ||
        host_str.find("github.io") != std::string::npos) {
        host_ok = true;
    }

    if (!host_ok) {
        return {false, "Download host '" + host_str + "' not in allowed list."};
    }
    return {true, ""};
}

// ─── Auto-Updater ───────────────────────────────────────────────────────────

void Api::handle_update_stage() {
    // Check if we were launched with --authss-update-finish flag
    int argc = __argc;
    for (int i = 1; i < argc; ++i) {
        std::string arg = __argv[i];
        if (arg == "--authss-update-finish") {
            // Update was applied — remove .old backup if exists
            std::wstring current = get_current_executable_path();
            if (!current.empty()) {
                std::wstring old = current + L".old";
                DeleteFileW(old.c_str());
            }
            LOG_INFO("[AUTO-UPDATE] Update completed successfully.");
            break;
        }
    }
}

std::wstring Api::get_current_executable_path() {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return std::wstring(path);
}

UpdateInfo Api::check_for_updates() {
    UpdateInfo info;
    info.current_version = version;

    nlohmann::json payload = {
        {"app_id", ownerid},
        {"version", version}
    };

    nlohmann::json response = do_request("/check-update", payload);

    if (!response.is_null() && response.value("status", "") == "success") {
        auto data = response.value("data", nlohmann::json::object());
        info.update_available = data.value("update_available", false);
        info.latest_version = data.value("latest_version", "");
        info.download_url = data.value("download_url", "");
        info.file_name = data.value("file_name", "");
        info.release_notes = data.value("release_notes", "");
    }

    return info;
}

bool Api::perform_update(const UpdateInfo& info) {
    if (!info.update_available || info.download_url.empty()) {
        LOG_WARN("[AUTO-UPDATE] No update available or no download URL.");
        return false;
    }

    // Validate download URL
    auto [url_valid, url_err] = validate_download_url(info.download_url);
    if (!url_valid) {
        LOG_ERROR("[AUTO-UPDATE] " << url_err);
        return false;
    }

    LOG_INFO("[AUTO-UPDATE] Downloading update from: " << info.download_url);

    // Create temp path for download
    std::wstring current_path = get_current_executable_path();
    std::wstring temp_path = current_path + L".update";
    std::wstring old_path = current_path + L".old";

    // Download new version
    if (!download_file_winhttp(info.download_url, temp_path)) {
        LOG_ERROR("[AUTO-UPDATE] Failed to download update.");
        return false;
    }

    // Backup current executable
    MoveFileW(current_path.c_str(), old_path.c_str());

    // Move downloaded file to current location
    if (!MoveFileW(temp_path.c_str(), current_path.c_str())) {
        LOG_ERROR("[AUTO-UPDATE] Failed to replace executable. Restoring backup.");
        MoveFileW(old_path.c_str(), current_path.c_str());
        return false;
    }

    LOG_INFO("[AUTO-UPDATE] Update installed. Restarting...");

    // Restart with --authss-update-finish flag
    std::wstring cmd = L"\"" + current_path + L"\" --authss-update-finish";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    CreateProcessW(NULL, const_cast<wchar_t*>(cmd.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    ExitProcess(0);
    return true;
}

// =============================================================================
// Others utility class (sama seperti AuthLX::Others)
// =============================================================================

std::string Others::get_checksum() {
    // Get checksum of current executable for integrity verification
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, path, MAX_PATH);

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    // Get file size
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size)) {
        CloseHandle(hFile);
        return "";
    }

    // Read entire file
    DWORD size = (DWORD)file_size.QuadPart;
    std::vector<BYTE> buffer(size);
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, buffer.data(), size, &bytes_read, NULL)) {
        CloseHandle(hFile);
        return "";
    }
    CloseHandle(hFile);

    // SHA-256 hash
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) return "";

    DWORD hash_obj_size = 0, hash_len = 0, cb = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hash_obj_size, sizeof(DWORD), &cb, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hash_len, sizeof(DWORD), &cb, 0);

    std::vector<BYTE> hash_obj(hash_obj_size);
    std::vector<BYTE> hash(hash_len);

    if (BCryptCreateHash(hAlg, &hHash, hash_obj.data(), hash_obj_size, NULL, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptHashData(hHash, buffer.data(), size, 0);
    BCryptFinishHash(hHash, hash.data(), hash_len, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Convert to hex string
    std::stringstream ss;
    for (DWORD i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void Others::anti_debug() {
#ifdef _WIN32
    // Standard anti-debug checks
    if (IsDebuggerPresent()) {
        LOG_WARN("[SECURITY] Debugger detected! Consider removing before production.");
        // In production, you might want to: ExitProcess(0);
    }

    // Check NtGlobalFlag (debug flags)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb && pPeb->NtGlobalFlag != 0) {
        LOG_WARN("[SECURITY] Debug flags detected in PEB NtGlobalFlag.");
    }
#endif
}

std::string Others::get_hwid(std::string method) {
    if (method == "windows_user") {
        // Windows SID-based HWID
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return "";

        DWORD token_info_len = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &token_info_len);
        if (token_info_len == 0) { CloseHandle(hToken); return ""; }

        std::vector<BYTE> token_info_buf(token_info_len);
        if (!GetTokenInformation(hToken, TokenUser, token_info_buf.data(), token_info_len, &token_info_len)) {
            CloseHandle(hToken);
            return "";
        }

        PTOKEN_USER pTokenUser = (PTOKEN_USER)token_info_buf.data();
        LPSTR sid_str = NULL;
        if (!ConvertSidToStringSidA(pTokenUser->User.Sid, &sid_str)) {
            CloseHandle(hToken);
            return "";
        }

        std::string hwid(sid_str);
        LocalFree(sid_str);
        CloseHandle(hToken);
        return hwid;
    }

    if (method == "machine") {
        // Machine GUID from registry
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                          KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return "";

        char buf[256] = {0};
        DWORD buf_size = sizeof(buf);
        DWORD type = REG_SZ;
        if (RegQueryValueExA(hKey, "MachineGuid", NULL, &type, (LPBYTE)buf, &buf_size) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return "";
        }
        RegCloseKey(hKey);
        return std::string(buf);
    }

    // Default: windows_user
    return get_hwid("windows_user");
}

} // namespace Authss
