// =============================================================================
// Santet Sentinel AuthSS — C# Basic Example
// =============================================================================
using System;
using System.Threading.Tasks;
using SentinelAuth;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Santet Sentinel AuthSS — C# Basic ===\n");

        // 1. Init
        var app = new SentinelAuth("your_app_name", "1.0");
        await app.InitAsync();
        if (!app.Response.Success)
        {
            Console.WriteLine($"Init failed: {app.Response.Message}");
            return;
        }
        Console.WriteLine("[OK] SDK initialized");

        // 2. Security
        SentinelSecurity.StartAll();
        Console.WriteLine("[OK] Security active");

        // 3. Login
        Console.Write("Username: ");
        string user = Console.ReadLine()?.Trim() ?? "";
        Console.Write("Password: ");
        string pass = Console.ReadLine()?.Trim() ?? "";

        var hwid = SentinelAuth.GetDefaultHwid();
        await app.LicenseAsync(user, hwid);

        if (app.Response.Success)
        {
            Console.WriteLine($"\n[OK] Logged in: {app.UserData.Username}");
            Console.WriteLine($"    Plan: {app.UserData.Plan}");
            Console.WriteLine($"    Expires: {app.UserData.Expiry}");
            Console.WriteLine("\nPress Enter to exit...");
            Console.ReadLine();
        }
        else
        {
            Console.WriteLine($"Login failed: {app.Response.Message}");
        }
    }
}
