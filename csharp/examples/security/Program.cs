// =============================================================================
// Santet Sentinel AuthSS — C# Security Example
// =============================================================================
using System;
using System.Threading.Tasks;
using SentinelAuth;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Santet Sentinel AuthSS — C# Security ===\n");

        // 1. Init
        var app = new SentinelAuth("your_app_name", "1.0");
        await app.InitAsync();
        if (!app.Response.Success)
        {
            Console.WriteLine($"Init failed: {app.Response.Message}");
            return;
        }

        // 2. Individual checks
        Console.WriteLine("--- Individual Checks ---");
        Console.WriteLine(SentinelSecurity.AntiDebug() ? "[WARN] Debugger detected!" : "[OK] Anti-Debug pass");
        AntiDecompiler.Protect();
        Console.WriteLine("[OK] Anti-Decompiler active");
        AntiDump.Protect();
        Console.WriteLine("[OK] Anti-Dump active");

        // 3. Start all
        SentinelSecurity.SetOnViolation(reason =>
        {
            Console.WriteLine($"\n[SECURITY VIOLATION] {reason}\nExiting...");
        });
        SentinelSecurity.StartAll(2000);
        Console.WriteLine("[OK] All security started");

        // 4. Login
        Console.Write("\nUsername: ");
        string user = Console.ReadLine()?.Trim() ?? "";
        Console.Write("Password: ");
        string pass = Console.ReadLine()?.Trim() ?? "";

        var hwid = SentinelAuth.GetDefaultHwid();
        await app.LicenseAsync(user, hwid);

        if (app.Response.Success)
        {
            Console.WriteLine($"\n=== LOGIN OK — ALL PROTECTIONS ACTIVE ===");
            Console.WriteLine($"  User: {app.UserData.Username}");
            Console.WriteLine($"  Plan: {app.UserData.Plan}");
            Console.WriteLine($"  Expires: {app.UserData.Expiry}");
            Console.WriteLine("==========================================");
            Console.WriteLine("\nPress Enter to exit...");
            Console.ReadLine();
        }
        else
        {
            Console.WriteLine($"Login failed: {app.Response.Message}");
        }
    }
}
