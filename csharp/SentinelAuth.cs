// =============================================================================
// SENTINEL AUTH — C# SDK (SANTET SENTINEL)
// =============================================================================
// SDK resmi C# untuk project EXE / software client.
// Pola API mirip KeyAuth: init() → license(key) → cek response.success.
//
// Endpoint: POST /api/sdk/verify
// Persyaratan: .NET 6+ (tanpa package tambahan).
//
// Contoh penggunaan:
//   var app = new SentinelAuth("AppName", "1.0");
//   await app.InitAsync();
//   if (!app.Response.Success) { /* error */ return; }
//
//   await app.LicenseAsync("YOUR-KEY", SentinelAuth.GetDefaultHwid());
//   if (!app.Response.Success) { /* error */ return; }
//
//   Console.WriteLine($"User: {app.UserData.Username}");
//   Console.WriteLine($"Plan: {app.UserData.Plan}");
//   Console.WriteLine($"Days left: {app.UserData.DaysLeft}");
//
// FAIL-CLOSED: setiap kegagalan → Success=false.
// =============================================================================

using System;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SentinelAuth
{
    /// <summary>C++-style response (mirip KeyAuth: app.response.success).</summary>
    public class ResponseData
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string Code { get; set; } = "";
    }

    /// <summary>User data (mirip KeyAuth: app.user_data.username, etc.).</summary>
    public class UserData
    {
        public string Username { get; set; } = "";
        public string Hwid { get; set; } = "";
        public string Plan { get; set; } = "";
        public string Expiry { get; set; } = "";
        public int DaysLeft { get; set; }
        public string Status { get; set; } = "";
        public string CreatedAt { get; set; } = "";
        public string LastLogin { get; set; } = "";
    }

    /// <summary>App data (mirip KeyAuth: app.app_data.numUsers, etc.).</summary>
    public class AppData
    {
        public int NumUsers { get; set; }
        public int NumOnlineUsers { get; set; }
        public int NumKeys { get; set; }
        public string Version { get; set; } = "";
    }

    /// <summary>Main SDK class — pola mirip KeyAuth.</summary>
    public class SentinelAuth
    {
        private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(15) };
        private const string DefaultBaseUrl = "https://santetsentinel.web.id";

        public string Name { get; }
        public string Version { get; }
        public string BaseUrl { get; }
        public string Hwid { get; }

        public ResponseData Response { get; } = new();
        public UserData UserData { get; } = new();
        public AppData AppData { get; } = new();

        private string _sessionId = "";
        private string _apiKey = "";

        /// <summary>Create app instance (mirip KeyAuth: api KeyAuthApp(name, ver)).</summary>
        public SentinelAuth(string name, string version = "1.0", string baseUrl = DefaultBaseUrl)
        {
            Name = name ?? "";
            Version = string.IsNullOrWhiteSpace(version) ? "1.0" : version.Trim();
            BaseUrl = (string.IsNullOrWhiteSpace(baseUrl) ? DefaultBaseUrl : baseUrl).TrimEnd('/');
            Hwid = GetDefaultHwid();
        }

        /// <summary>Set X-API-KEY header (opsional — identifikasi reseller).</summary>
        public void SetApiKey(string apiKey) => _apiKey = apiKey ?? "";

        // ── HTTP Helper ────────────────────────────────────────────────

        private async Task<JsonElement> PostJson(string path, object payload)
        {
            var body = JsonSerializer.Serialize(payload);
            using var content = new StringContent(body, Encoding.UTF8, "application/json");

            using var req = new HttpRequestMessage(HttpMethod.Post, BaseUrl + path);
            req.Content = content;
            if (!string.IsNullOrEmpty(_apiKey))
                req.Headers.Add("X-API-KEY", _apiKey);

            using var resp = await Client.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(text))
                throw new SentinelAuthException($"Empty response (HTTP {(int)resp.StatusCode}).");

            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.Clone();
        }

        private static string Str(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

        private static int Int(JsonElement e, string name, int dflt = 0) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : dflt;

        private static bool Bool(JsonElement e, string name, bool dflt = false) =>
            e.TryGetProperty(name, out var v) && (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False)
                ? v.GetBoolean() : dflt;

        private void ParseResponse(JsonElement root)
        {
            Response.Success = Bool(root, "success");
            Response.Message = Str(root, "message");
            Response.Code = Str(root, "code");

            UserData.Username = Str(root, "username");
            UserData.Hwid = Str(root, "hwidBound");
            UserData.Plan = Str(root, "plan");
            UserData.Expiry = Str(root, "expiresAt");
            UserData.DaysLeft = Int(root, "daysLeft");
            UserData.Status = Str(root, "status");
            UserData.CreatedAt = Str(root, "createdAt");
            UserData.LastLogin = Str(root, "lastLogin");

            AppData.Version = Version;
            AppData.NumUsers = Int(root, "numUsers");
            AppData.NumOnlineUsers = Int(root, "numOnlineUsers");
            AppData.NumKeys = Int(root, "numKeys");
        }

        // ── Public API (pola mirip KeyAuth) ────────────────────────────

        /// <summary>Initialize session (WAJIB dipanggil duluan). Mirip KeyAuth: app.init().</summary>
        public async Task InitAsync()
        {
            _sessionId = Guid.NewGuid().ToString("N")[..32];
            Response.Reset();
            UserData.Reset();
            AppData.Reset();
            AppData.Version = Version;

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    action = "init",
                    name = Name,
                    version = Version,
                    hwid = Hwid,
                    sessionid = _sessionId,
                    type = "init",
                });
                ParseResponse(root);
                if (Response.Success && string.IsNullOrEmpty(Response.Message))
                    Response.Message = "Init berhasil. Session siap.";
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>License key verification. Mirip KeyAuth: app.license(key).</summary>
        public async Task LicenseAsync(string key, string hwid = "")
        {
            Response.Reset();
            UserData.Reset();

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    key = key,
                    hwid = string.IsNullOrEmpty(hwid) ? Hwid : hwid,
                    username = "Operator",
                });
                ParseResponse(root);

                if (!Response.Success && string.IsNullOrEmpty(Response.Code))
                {
                    Response.Code = "PARSE_ERROR";
                    Response.Message = "Gagal membaca respons server.";
                }
                if (string.IsNullOrEmpty(Response.Message))
                    Response.Message = Response.Success ? "License valid. Akses dibuka." : "License tidak valid.";
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>Login with username + password. Mirip KeyAuth: app.login(user, pass).</summary>
        public async Task LoginAsync(string username, string password)
        {
            Response.Reset();
            UserData.Reset();

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    action = "login",
                    name = Name,
                    version = Version,
                    hwid = Hwid,
                    sessionid = _sessionId,
                    type = "login",
                    username,
                    password,
                });
                ParseResponse(root);
                if (string.IsNullOrEmpty(Response.Message))
                    Response.Message = Response.Success ? "Login berhasil." : "Login gagal.";
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>Register with license key. Mirip KeyAuth: app.regstr(user, pass, key).</summary>
        public async Task RegisterAsync(string username, string password, string key)
        {
            Response.Reset();
            UserData.Reset();

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    action = "register",
                    name = Name,
                    version = Version,
                    hwid = Hwid,
                    sessionid = _sessionId,
                    type = "register",
                    username,
                    password,
                    key,
                });
                ParseResponse(root);
                if (string.IsNullOrEmpty(Response.Message))
                    Response.Message = Response.Success ? "Register berhasil." : "Register gagal.";
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>Upgrade user with new key. Mirip KeyAuth: app.upgrade(user, key).</summary>
        public async Task UpgradeAsync(string username, string key)
        {
            Response.Reset();
            UserData.Reset();

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    action = "upgrade",
                    name = Name,
                    version = Version,
                    hwid = Hwid,
                    sessionid = _sessionId,
                    type = "upgrade",
                    username,
                    key,
                });
                ParseResponse(root);
                if (string.IsNullOrEmpty(Response.Message))
                    Response.Message = Response.Success ? "Upgrade berhasil." : "Upgrade gagal.";
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>Check session validity. Mirip KeyAuth: app.check().</summary>
        public async Task CheckAsync()
        {
            Response.Reset();
            UserData.Reset();

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    action = "check",
                    name = Name,
                    version = Version,
                    hwid = Hwid,
                    sessionid = _sessionId,
                    type = "check",
                });
                ParseResponse(root);
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>Fetch app statistics. Mirip KeyAuth: app.fetchstats().</summary>
        public async Task FetchStatsAsync()
        {
            Response.Reset();

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    action = "stats",
                    name = Name,
                    version = Version,
                    hwid = Hwid,
                    sessionid = _sessionId,
                    type = "stats",
                });
                ParseResponse(root);
                Response.Success = true;
                Response.Message = "Stats fetched.";
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>Log event to server. Mirip KeyAuth: app.log("event").</summary>
        public async Task LogAsync(string message)
        {
            Response.Reset();

            try
            {
                var root = await PostJson("/api/sdk/verify", new
                {
                    action = "log",
                    name = Name,
                    version = Version,
                    hwid = Hwid,
                    sessionid = _sessionId,
                    type = "log",
                    message,
                });
                ParseResponse(root);
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        /// <summary>Ban user (block HWID + IP). Mirip KeyAuth: app.ban(reason).</summary>
        public async Task BanAsync(string reason = "")
        {
            Response.Reset();

            try
            {
                var body = new Dictionary<string, string>
                {
                    ["action"] = "ban",
                    ["name"] = Name,
                    ["version"] = Version,
                    ["hwid"] = Hwid,
                    ["sessionid"] = _sessionId,
                    ["type"] = "ban",
                };
                if (!string.IsNullOrEmpty(reason)) body["reason"] = reason;

                var root = await PostJson("/api/sdk/verify", body);
                ParseResponse(root);
            }
            catch (Exception ex)
            {
                Response.Success = false;
                Response.Code = "NETWORK_ERROR";
                Response.Message = ex.Message;
            }
        }

        // ── HWID ─────────────────────────────────────────────────────────

        /// <summary>SHA-256 fingerprint: MachineName|VolumeSerial(C:)|MAC — identik dengan C++ SDK.</summary>
        public static string GetDefaultHwid()
        {
            var raw = GetDeviceFingerprint();
            if (string.IsNullOrEmpty(raw)) raw = Environment.MachineName ?? "unknown-machine";
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>Raw fingerprint (debugging only): MachineName|VolumeSerialC|MAC.</summary>
        public static string GetDeviceFingerprint()
        {
            var machine = Environment.MachineName ?? "";
            var volume = GetSystemVolumeSerial();
            var mac = GetPrimaryMacAddress();
            return $"{machine}|{volume}|{mac}";
        }

        private static string GetSystemVolumeSerial()
        {
            if (!OperatingSystem.IsWindows()) return "";
            try
            {
                var vol = new StringBuilder(256);
                var fs = new StringBuilder(256);
                if (GetVolumeInformationW("C:\\", vol, vol.Capacity, out uint serial, out _, out _, fs, fs.Capacity))
                    return serial.ToString("X8");
            }
            catch { }
            return "";
        }

        private static string GetPrimaryMacAddress()
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    var type = nic.NetworkInterfaceType;
                    if (type == NetworkInterfaceType.Loopback || type == NetworkInterfaceType.Tunnel) continue;
                    var mac = nic.GetPhysicalAddress()?.ToString();
                    if (!string.IsNullOrEmpty(mac)) return mac.ToLowerInvariant();
                }
            }
            catch { }
            return "";
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool GetVolumeInformationW(string lpRootPathName,
            StringBuilder lpVolumeNameBuffer, int nVolumeNameSize,
            out uint lpVolumeSerialNumber, out uint lpMaximumComponentLength,
            out uint lpFileSystemFlags, StringBuilder lpFileSystemNameBuffer, int nFileSystemNameSize);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    internal static class ResponseExtensions
    {
        public static void Reset(this ResponseData r) { r.Success = false; r.Message = ""; r.Code = ""; }
        public static void Reset(this UserData u) { u.Username = ""; u.Hwid = ""; u.Plan = ""; u.Expiry = ""; u.DaysLeft = 0; u.Status = ""; u.CreatedAt = ""; u.LastLogin = ""; }
        public static void Reset(this AppData a) { a.NumUsers = 0; a.NumOnlineUsers = 0; a.NumKeys = 0; a.Version = ""; }
    }

    public class SentinelAuthException : Exception
    {
        public int HttpStatus { get; }
        public SentinelAuthException(string message, int httpStatus = 0) : base(message) { HttpStatus = httpStatus; }
    }
}
