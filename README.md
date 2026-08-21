<p align="center">
  <img src="https://img.shields.io/badge/SDK-v2.0-030712?style=for-the-badge&logo=cplusplus&logoColor=F97316" alt="SDK">
  <img src="https://img.shields.io/badge/Language-C++%20%7C%20C%23-00599C?style=for-the-badge" alt="Language">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<h1 align="center">🛡️ Santet Sentinel Auth SDK</h1>

<p align="center">
  <strong>Guardian of Digital Realm</strong><br>
  Secure authentication, licensing & anti-reverse-engineering SDK for C++ and C#.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#c-examples">C++</a> •
  <a href="#c-examples-1">C#</a> •
  <a href="#security">Security</a> •
  <a href="#api-reference">API</a>
</p>

---

## 📦 Repository Structure

```
SantetSentinel-AuthSDK/
│
├── cpp/                              # ── C++ SDK ──
│   ├── include/authSS/
│   │   ├── authSS.hpp                # Main header (Api, Others classes)
│   │   ├── authSS.cpp                # API implementation
│   │   ├── Security.hpp              # Security module header
│   │   ├── Security.cpp              # Anti-debug, anti-dump, anti-hook, anti-VM
│   │   ├── Logger.hpp                # Thread-safe logger
│   │   ├── skCrypter.h               # Compile-time string encryption
│   │   ├── json.hpp                  # JSON parser (run setup.bat to download)
│   │   └── setup.bat                 # Download json.hpp
│   │
│   └── examples/
│       ├── basic/main.cpp            # Minimal integration
│       ├── login/main.cpp            # All auth methods
│       └── security/main.cpp         # Full security demo
│
├── csharp/                           # ── C# SDK ──
│   ├── SentinelAuth.cs               # Main SDK class
│   ├── SentinelSecurity.cs           # Anti-debug, anti-dump, anti-injection
│   │
│   └── examples/
│       ├── basic/Program.cs          # Minimal integration
│       └── security/Program.cs       # Full security demo
│
├── CMakeLists.txt                    # CMake build (C++)
├── README.md                         # This file
├── .gitignore
└── LICENSE                           # MIT
```

> **Ini bukan website project.** Ini adalah SDK source code + examples saja.

---

## 🚀 Quick Start

### C++

```cpp
#include "authSS/authSS.hpp"
#include "authSS/skCrypter.h"

int main() {
    std::string name    = skCrypt("your_app_name").decrypt();
    std::string ownerid = skCrypt("your_owner_id").decrypt();
    std::string secret  = skCrypt("your_app_secret").decrypt();
    std::string version = skCrypt("1.0").decrypt();
    std::string url     = skCrypt("https://santetsentinel.web.id/api/v1/client/").decrypt();

    std::string my_hash = Authss::Others::get_checksum();

    Authss::Api authssapp(name, ownerid, version, secret, my_hash, url);

    Authss::Security::start_all();

    if (authssapp.login("user", "pass")) {
        std::cout << "Welcome: " << authssapp.user_data.username << std::endl;
    }
}
```

### C#

```csharp
using SentinelAuth;

var app = new SentinelAuth("your_app_name", "1.0");
await app.InitAsync();

SentinelSecurity.StartAll();

var hwid = SentinelAuth.GetDefaultHwid();
await app.LicenseAsync("YOUR-LICENSE-KEY", hwid);

if (app.Response.Success)
{
    Console.WriteLine($"Welcome: {app.UserData.Username}");
}
```

---

## 🛠️ Build

### C++ (CMake)

```bash
cd cpp
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# Output:
# build/Release/authss.lib
# build/Release/authss-basic.exe
# build/Release/authss-login.exe
# build/Release/authss-security.exe
```

### C++ (Manual)

```bash
cl.exe /EHsc /O2 /MT main.cpp /I../../include /Fe:app.exe /link winhttp.lib bcrypt.lib advapi32.lib crypt32.lib psapi.lib
```

### C#

```bash
cd csharp/examples/basic
dotnet build -c Release

# Publish standalone EXE:
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

---

## 📚 C++ Examples

### Basic (`cpp/examples/basic/`)

Paling dasar: init → security → login → tampilkan data.

```bash
cd cpp/examples/basic
# Build & jalankan authss-basic.exe
```

### Login (`cpp/examples/login/`)

Semua metode autentikasi: login, register, web login, upgrade, verifikasi token.

```bash
cd cpp/examples/login
# Build & jalankan authss-login.exe
```

### Security (`cpp/examples/security/`)

Demo lengkap semua fitur keamanan: anti-debug, anti-dump, anti-hook, anti-VM, integrity check.

```bash
cd cpp/examples/security
# Build & jalankan authss-security.exe
```

---

## 📚 C# Examples

### Basic (`csharp/examples/basic/`)

Minimal: init → security → login.

### Security (`csharp/examples/security/`)

Full security: anti-debug, anti-decompiler, anti-dump, DLL injection monitoring.

---

## 🛡️ Security Features

### `Authss::Security` (C++) / `SentinelSecurity` (C#)

| Feature | C++ | C# | Description |
|---------|-----|-----|-------------|
| **Anti-Debug** | ✅ | ✅ | IsDebuggerPresent, remote debug, hardware breakpoints, timing |
| **Anti-Dump** | ✅ | ✅ | .text section read-only, PE header protection |
| **Anti-Hook** | ✅ | ✅ | JMP/PUSH hook detection on kernel32/ntdll |
| **Anti-VM** | ✅ | ✅ | VMware, VirtualBox, Hyper-V, QEMU (registry + CPUID) |
| **Anti-Memory Scan** | ✅ | ✅ | Cheat Engine scanner protection |
| **Anti-DLL Injection** | ✅ | ✅ | DLL monitoring, auto-kill injectors |
| **Anti-Decompiler** | ✅ | ✅ | PE header erasure / ILDASM detection |
| **Anti-Process** | ✅ | ✅ | 50+ blocked tools (debuggers, injectors, analyzers) |
| **Integrity Check** | ✅ | ✅ | SHA256 file hash verification |
| **Ban Monitor** | ✅ | ✅ | Runtime session verification |

### Blocked Tools (50+)

| Category | Tools |
|----------|-------|
| Debuggers | x64dbg, x32dbg, ollydbg, windbg, ida, ida64, dnSpy, ReClass.NET |
| Injectors | Extreme Injector, Xenos, GH Injector, ProcessHacker |
| Analyzers | Cheat Engine, KsDumper, HTTPDebugger, Fiddler, Wireshark |
| Network | tcpview, procmon, procexp, autoruns, dumpcap |
| VM | vmtoolsd, vmwaretray, vboxservice, vboxtray |

---

## 📚 API Reference

### `Authss::Api` (C++)

```cpp
Authss::Api(name, ownerid, version, secret, hash, url);
```

| Method | Returns | Description |
|--------|---------|-------------|
| `login(user, pass, hwid)` | `bool` | Login with username + password |
| `registerAccount(user, email, pass, key)` | `bool` | Register with license key |
| `webLogin(user, pass)` | `bool` | Login without HWID |
| `logout()` | `bool` | End session |
| `upgrade(user, key)` | `bool` | Upgrade with new license key |
| `check()` | `bool` | Verify session |
| `verifyToken(token)` | `bool` | Verify standalone token |
| `changeUsername(new_user)` | `bool` | Change username |
| `var(name)` | `string` | Get global variable |
| `start_ban_monitor(secs)` | `void` | Start runtime monitoring |
| `set_allowed_hosts(hosts)` | `void` | Set host whitelist |

### `Authss::Security` (C++)

| Method | Returns | Description |
|--------|---------|-------------|
| `start_all(interval_ms)` | `void` | Start all protections |
| `anti_debug()` | `bool` | Detect debugger |
| `anti_dump()` | `void` | Protect memory |
| `anti_hook()` | `bool` | Detect API hooking |
| `anti_vm()` | `bool` | Detect VM |
| `integrity_check(hash)` | `bool` | Verify EXE hash |
| `stop_all()` | `void` | Stop all |
| `set_on_violation(fn)` | `void` | Custom violation handler |

### `Authss::Others` (C++)

| Method | Returns | Description |
|--------|---------|-------------|
| `get_checksum()` | `string` | SHA-256 of EXE |
| `get_hwid(method)` | `string` | Hardware ID |
| `anti_debug()` | `void` | Basic anti-debug |

### User Data

```cpp
authssapp.user_data.username         // string
authssapp.user_data.hwid             // string
authssapp.user_data.expires          // string (ISO 8601)
authssapp.user_data.subscription     // string (plan name)
authssapp.user_data.is_authenticated // bool
```

---

## 🔗 Links

- 🌐 **Website:** [santetsentinel.web.id](https://santetsentinel.web.id)
- 📖 **Docs:** [santetsentinel.web.id/docs](https://santetsentinel.web.id/docs)
- 💬 **Discord:** [Join Community](https://discord.gg/9f59WuPJUF)
- 📦 **Main Repo:** [S4NT3T-S3NT1N3L-V1](https://github.com/santetsentinel36/S4NT3T-S3NT1N3L-V1)

---

## 📄 License

MIT License — see [LICENSE](LICENSE).

**Third-party:**
- `json.hpp` — [nlohmann/json](https://github.com/nlohmann/json) — MIT
- `skCrypter.h` — [skadro](https://github.com/skadro-official) — MIT

---

<p align="center"><strong>Made with ❤️ by Santet Sentinel</strong></p>
