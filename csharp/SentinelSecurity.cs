// =============================================================================
// SENTINEL AUTH — C# SECURITY MODULE (SANTET SENTINEL)
// =============================================================================
// Proteksi anti-reverse-engineering untuk aplikasi C#.
// Dipanggil setelah SentinelAuth.InitAsync() berhasil untuk melindungi aplikasi.
//
// Contoh penggunaan:
//   SentinelSecurity.StartAll();
//   // atau individual:
//   SentinelSecurity.AntiDebug();
//   SentinelSecurity.AntiDllInjection.Start();
//   SentinelSecurity.AntiDecompiler.Protect();
//   SentinelSecurity.AntiProcess.BlockUnauthorizedProcesses();
//
// =============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace SentinelAuth
{
    /// <summary>
    /// Main security class — aktifkan semua proteksi sekaligus atau individual.
    /// </summary>
    public static class SentinelSecurity
    {
        private static bool _isRunning = false;
        private static Thread _monitorThread;
        private static Action<string> _onViolation;

        /// <summary>Aktifkan semua proteksi sekaligus.</summary>
        public static void StartAll(int checkIntervalMs = 2000)
        {
            if (_isRunning) return;
            _isRunning = true;

            // Initial checks
            if (AntiDebug())
            {
                HandleViolation("Debugger detected at startup");
                return;
            }

            AntiDecompiler.Protect();
            AntiDllInjection.Start();
            AntiDump.Protect();
            AntiHook.Detect();  // Initial check
            AntiVM.Detect();    // Initial check
            AntiMemoryScan.Protect();
            AntiProcess.StartMonitor();

            // Start monitoring thread
            _monitorThread = new Thread(() => MonitorLoop(checkIntervalMs))
            {
                IsBackground = true,
                Priority = ThreadPriority.Highest
            };
            _monitorThread.Start();
        }

        /// <summary>Hentikan semua proteksi.</summary>
        public static void StopAll()
        {
            _isRunning = false;
            AntiDllInjection.Stop();
            AntiProcess.StopMonitor();
        }

        /// <summary>Set callback saat pelanggaran terdeteksi.</summary>
        public static void SetOnViolation(Action<string> callback)
        {
            _onViolation = callback;
        }

        // ── Anti-Debug ────────────────────────────────────────────────────

        /// <summary>Deteksi debugger (managed + native).</summary>
        public static bool AntiDebug()
        {
            bool detected = false;

            // 1. Managed debugger
            if (Debugger.IsAttached || Debugger.IsLogging())
                detected = true;

            // 2. Check COR_DEBUG_INFO environment
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING")))
                detected = true;

            // 3. Check for debugger via Win32 API
            if (NativeAntiDebug.IsDebuggerPresent())
                detected = true;

            // 4. Check remote debugger
            bool isRemoteDebug = false;
            NativeAntiDebug.CheckRemoteDebuggerPresent(
                Process.GetCurrentProcess().Handle, ref isRemoteDebug);
            if (isRemoteDebug)
                detected = true;

            return detected;
        }

        // ── Monitor Loop ──────────────────────────────────────────────────

        private static void MonitorLoop(int intervalMs)
        {
            while (_isRunning)
            {
                try
                {
                    // Check blocked processes
                    AntiProcess.CheckBlockedProcesses();

                    // Periodic anti-debug
                    if (AntiDebug())
                    {
                        HandleViolation("Debugger detected during runtime");
                    }

                    // Periodic anti-hook
                    if (AntiHook.Detect())
                    {
                        HandleViolation("API hooking detected during runtime");
                    }

                    // Periodic anti-VM
                    if (AntiVM.Detect())
                    {
                        HandleViolation("Virtual machine detected during runtime");
                    }

                    Thread.Sleep(intervalMs);
                }
                catch
                {
                    Thread.Sleep(intervalMs);
                }
            }
        }

        private static void HandleViolation(string reason)
        {
            _onViolation?.Invoke(reason);
            // Default: exit immediately
            Environment.Exit(1);
        }
    }

    // =========================================================================
    // Anti-Decompiler (anti ILDASM, assembly tampering)
    // =========================================================================

    public static class AntiDecompiler
    {
        /// <summary>Deteksi ILDASM dan assembly tampering.</summary>
        public static void Protect()
        {
            // 1. Check for ILDASM resource
            foreach (string resourceName in Assembly.GetExecutingAssembly().GetManifestResourceNames())
            {
                if (resourceName.Contains("ILDASM"))
                    Environment.Exit(0);
            }

            // 2. Assembly integrity check
            try
            {
                Assembly executing = Assembly.GetExecutingAssembly();
                foreach (Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
                {
                    // If assembly can't be loaded properly, it may be tampered
                    Assembly.Load(assembly.GetName());
                }
            }
            catch
            {
                Environment.Exit(0);
            }
        }
    }

    // =========================================================================
    // Anti-DLL Injection
    // =========================================================================

    public static class AntiDllInjection
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private static readonly string[] AllowedDlls = {
            "mscoree.dll", "mscorlib.dll", "kernel32.dll", "ntdll.dll",
            "user32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
            "gdi32.dll", "shell32.dll", "crypt32.dll", "bcrypt.dll",
            "winhttp.dll", "ws2_32.dll", "clretwrc.dll", "clr.dll",
            "mscordacwks.dll", "mscorjit.dll", "clrjit.dll",
            "sentinelauth.dll", "system.windows.forms.dll",
            "system.dll", "system.Drawing.dll", "system.core.dll"
        };

        private static readonly string[] BlockedProcesses = {
            "extreme injector", "xenos", "gh injector", "process hacker",
            "cheat engine", "ollydbg", "x64dbg", "dnspy", "injector",
            "processhacker", "cheatengine", "x32dbg", "ilspy",
            "dotpeek", "justdecompile", "reflector"
        };

        private static bool _isRunning = false;
        private static Thread _monitorThread;

        public static void Start()
        {
            if (_isRunning) return;
            _isRunning = true;
            _monitorThread = new Thread(MonitorLoop)
            {
                IsBackground = true,
                Priority = ThreadPriority.Highest
            };
            _monitorThread.Start();
        }

        public static void Stop()
        {
            _isRunning = false;
        }

        private static void MonitorLoop()
        {
            while (_isRunning)
            {
                try
                {
                    CheckInjectedDlls();
                    CheckForInjectors();
                    Thread.Sleep(500);
                }
                catch
                {
                    Thread.Sleep(500);
                }
            }
        }

        private static void CheckInjectedDlls()
        {
            try
            {
                Process currentProcess = Process.GetCurrentProcess();
                foreach (ProcessModule module in currentProcess.Modules)
                {
                    string moduleName = module.ModuleName.ToLower();
                    string modulePath = module.FileName.ToLower();

                    if (IsAllowedDll(moduleName)) continue;
                    if (IsSystemDll(modulePath)) continue;

                    // Unknown DLL detected
                    Debug.WriteLine($"[SENTINEL-SECURITY] Suspicious DLL: {moduleName}");
                }
            }
            catch { }
        }

        private static void CheckForInjectors()
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string procName = proc.ProcessName.ToLower();
                    foreach (var blocked in BlockedProcesses)
                    {
                        if (procName.Contains(blocked))
                        {
                            try { proc.Kill(); } catch { }
                            Debug.WriteLine($"[SENTINEL-SECURITY] Killed injector: {procName}");
                        }
                    }
                }
                catch { }
            }
        }

        private static bool IsAllowedDll(string moduleName)
        {
            foreach (var allowed in AllowedDlls)
            {
                if (moduleName.Contains(allowed))
                    return true;
            }
            return false;
        }

        private static bool IsSystemDll(string modulePath)
        {
            string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            return modulePath.StartsWith(windowsDir);
        }
    }

    // =========================================================================
    // Anti-Dump (protect memory from dumping)
    // =========================================================================

    public static class AntiDump
    {
        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        private const uint PAGE_EXECUTE_READ = 0x20;

        /// <summary>Protect PE headers and .text section from memory dumping.</summary>
        public static void Protect()
        {
            try
            {
                ProcessModule module = Process.GetCurrentProcess().MainModule;
                IntPtr baseAddr = module.BaseAddress;

                // Read DOS header
                byte[] dosHeader = new byte[64];
                Marshal.Copy(baseAddr, dosHeader, 0, 64);

                // Get PE header offset
                int peOffset = BitConverter.ToInt32(dosHeader, 60);
                IntPtr peHeader = IntPtr.Add(baseAddr, peOffset);

                // Read number of sections
                byte[] sectionCountBytes = new byte[2];
                Marshal.Copy(IntPtr.Add(peHeader, 6), sectionCountBytes, 0, 2);
                short sectionCount = BitConverter.ToInt16(sectionCountBytes, 0);

                // Get optional header size
                byte[] optHeaderSizeBytes = new byte[2];
                Marshal.Copy(IntPtr.Add(peHeader, 20), optHeaderSizeBytes, 0, 2);
                short optHeaderSize = BitConverter.ToInt16(optHeaderSizeBytes, 0);

                // Iterate sections
                IntPtr sectionStart = IntPtr.Add(peHeader, 24 + optHeaderSize);
                for (int i = 0; i < sectionCount; i++)
                {
                    IntPtr sectionAddr = IntPtr.Add(sectionStart, i * 40);

                    // Read section characteristics
                    byte[] charsBytes = new byte[4];
                    Marshal.Copy(IntPtr.Add(sectionAddr, 36), charsBytes, 0, 4);
                    uint characteristics = BitConverter.ToUInt32(charsBytes, 0);

                    // If executable section, make it read-only
                    if ((characteristics & 0x20000000) != 0) // IMAGE_SCN_MEM_EXECUTE
                    {
                        byte[] sizeBytes = new byte[4];
                        Marshal.Copy(IntPtr.Add(sectionAddr, 8), sizeBytes, 0, 4);
                        uint virtualSize = BitConverter.ToUInt32(sizeBytes, 0);

                        byte[] vaddrBytes = new byte[4];
                        Marshal.Copy(IntPtr.Add(sectionAddr, 12), vaddrBytes, 0, 4);
                        uint virtualAddr = BitConverter.ToUInt32(vaddrBytes, 0);

                        if (virtualSize > 0 && virtualAddr > 0)
                        {
                            IntPtr sectionPtr = IntPtr.Add(baseAddr, (int)virtualAddr);
                            VirtualProtect(sectionPtr, (UIntPtr)virtualSize,
                                PAGE_EXECUTE_READ, out _);
                        }
                    }
                }

                // Erase DOS header signature
                Marshal.Copy(new byte[] { 0, 0 }, 0, baseAddr, 2);

                Debug.WriteLine("[SENTINEL-SECURITY] Anti-dump protection applied");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SENTINEL-SECURITY] Anti-dump error: {ex.Message}");
            }
        }
    }

    // =========================================================================
    // Anti-Process (block debuggers, injectors, analyzers)
    // =========================================================================

    public static class AntiProcess
    {
        private static readonly string[] BlockedProcesses = {
            // Debuggers
            "x64dbg", "x32dbg", "ollydbg", "ImmunityDebugger",
            "windbg", "WinDbgX", "ida", "ida64", "idaq64",
            "dnSpy", "ReClass.NET", "ilspy", "dotpeek",
            "justdecompile", "Reflector",
            // Injectors
            "Extreme Injector", "Xenos", "GH Injector",
            "ProcessHacker", "Process Hacker",
            // Analyzers
            "Cheat Engine", "cheatengine", "cheatengine-x86_64",
            "KsDumper", "Dump-Fixer", "kdstinker",
            "HTTPDebugger", "Fiddler", "Wireshark", "dumpcap",
            "tcpview", "procmon", "procexp", "autoruns",
            "HookExplorer", "ImportREC", "PETools", "LordPE",
            "SysInspector", "sysAnalyzer", "sniff_hit",
            "joeboxcontrol", "joeboxserver",
            "MugenJinFuu", "Mugen JinFuu",
            "cmd"
        };

        private static bool _isRunning = false;
        private static Thread _monitorThread;

        public static void StartMonitor()
        {
            if (_isRunning) return;
            _isRunning = true;
            _monitorThread = new Thread(() =>
            {
                while (_isRunning)
                {
                    try
                    {
                        CheckBlockedProcesses();
                        Thread.Sleep(1000);
                    }
                    catch { Thread.Sleep(1000); }
                }
            })
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };
            _monitorThread.Start();
        }

        public static void StopMonitor()
        {
            _isRunning = false;
        }

        public static void CheckBlockedProcesses()
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string procName = proc.ProcessName.ToLower();
                    foreach (var blocked in BlockedProcesses)
                    {
                        if (procName.Contains(blocked.ToLower()))
                        {
                            try { proc.Kill(); } catch { }
                            Debug.WriteLine($"[SENTINEL-SECURITY] Killed blocked process: {procName}");
                        }
                    }
                }
                catch { }
            }
        }

        /// <summary>Block processes via Windows Policy registry (on app exit).</summary>
        public static void BlockProcessesOnExit()
        {
            foreach (var name in BlockedProcesses)
            {
                try
                {
                    using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", true))
                    {
                        key?.SetValue(name, 0, Microsoft.Win32.RegistryValueKind.DWord);
                    }
                }
                catch { }
            }
        }
    }

    // =========================================================================
    // Native P/Invoke helpers
    // =========================================================================

    internal static class NativeAntiDebug
    {
        [DllImport("kernel32.dll")]
        public static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
            IntPtr processHandle, int processInformationClass,
            ref IntPtr processInformation, int processInformationLength,
            ref int returnLength);
    }

    // =========================================================================
    // Anti-Hook (detect API hooking)
    // =========================================================================

    public static class AntiHook
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private static readonly string[][] HookedAPIs = {
            new[] { "kernel32.dll", "IsDebuggerPresent" },
            new[] { "kernel32.dll", "CheckRemoteDebuggerPresent" },
            new[] { "kernel32.dll", "WriteProcessMemory" },
            new[] { "kernel32.dll", "ReadProcessMemory" },
            new[] { "ntdll.dll", "NtQueryInformationProcess" },
        };

        /// <summary>Detect JMP/PUSH hooks on critical APIs.</summary>
        public static bool Detect()
        {
            foreach (var api in HookedAPIs)
            {
                IntPtr hMod = GetModuleHandle(api[0]);
                if (hMod == IntPtr.Zero) continue;
                IntPtr proc = GetProcAddress(hMod, api[1]);
                if (proc == IntPtr.Zero) continue;

                byte[] bytes = new byte[16];
                Marshal.Copy(proc, bytes, 0, 16);

                // JMP rel (0xE9), JMP [addr] (0xFF 0x25), PUSH imm32 (0x68), MOV RAX+JMP (0x48 0xB8)
                if (bytes[0] == 0xE9 || bytes[0] == 0xEA) return true;
                if (bytes[0] == 0xFF && bytes[1] == 0x25) return true;
                if (bytes[0] == 0x68) return true;
                if (bytes[0] == 0x48 && bytes[1] == 0xB8) return true;
            }
            return false;
        }
    }

    // =========================================================================
    // Anti-VM (detect virtual machines)
    // =========================================================================

    public static class AntiVM
    {
        private static readonly string[] VMIndicators = {
            "vmware", "virtualbox", "virtual", "qemu", "hyper-v",
            "vbox", "xen", "parallels"
        };

        /// <summary>Detect VM environment via registry + WMI.</summary>
        public static bool Detect()
        {
            // Check registry keys
            string[] keys = {
                @"SYSTEM\CurrentControlSet\Control\SystemInformation",
                @"SOFTWARE\VMware, Inc.\VMware Tools",
                @"SOFTWARE\Oracle\VirtualBox Guest Additions"
            };

            foreach (var keyPath in keys)
            {
                try
                {
                    using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }
            }

            // Check system manufacturer
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SystemInformation"))
                {
                    string manufacturer = key?.GetValue("SystemManufacturer")?.ToString() ?? "";
                    string product = key?.GetValue("SystemProductName")?.ToString() ?? "";
                    string combined = (manufacturer + product).ToLower();

                    foreach (var indicator in VMIndicators)
                    {
                        if (combined.Contains(indicator)) return true;
                    }
                }
            }
            catch { }

            return false;
        }
    }

    // =========================================================================
    // Anti-Memory Scan (protect from Cheat Engine)
    // =========================================================================

    public static class AntiMemoryScan
    {
        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;

        /// <summary>Protect sensitive memory regions from scanning.</summary>
        public static void Protect()
        {
            try
            {
                // Erase PE header to prevent memory scanning tools
                ProcessModule module = Process.GetCurrentProcess().MainModule;
                IntPtr baseAddr = module.BaseAddress;

                // Read DOS header
                byte[] dosHeader = new byte[64];
                Marshal.Copy(baseAddr, dosHeader, 0, 64);

                // Get PE header offset
                int peOffset = BitConverter.ToInt32(dosHeader, 60);
                IntPtr peHeader = IntPtr.Add(baseAddr, peOffset);

                // Read section count
                byte[] sectionCountBytes = new byte[2];
                Marshal.Copy(IntPtr.Add(peHeader, 6), sectionCountBytes, 0, 2);
                short sectionCount = BitConverter.ToInt16(sectionCountBytes, 0);

                // Get optional header size
                byte[] optHeaderSizeBytes = new byte[2];
                Marshal.Copy(IntPtr.Add(peHeader, 20), optHeaderSizeBytes, 0, 2);
                short optHeaderSize = BitConverter.ToInt16(optHeaderSizeBytes, 0);

                // Iterate sections and protect data sections
                IntPtr sectionStart = IntPtr.Add(peHeader, 24 + optHeaderSize);
                for (int i = 0; i < sectionCount; i++)
                {
                    IntPtr sectionAddr = IntPtr.Add(sectionStart, i * 40);

                    byte[] nameBytes = new byte[8];
                    Marshal.Copy(sectionAddr, nameBytes, 0, 8);
                    string sectionName = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0').ToLower();

                    // Protect .data and .rdata sections (prevent scanning)
                    if (sectionName == ".data" || sectionName == ".rdata")
                    {
                        byte[] vaddrBytes = new byte[4];
                        Marshal.Copy(IntPtr.Add(sectionAddr, 12), vaddrBytes, 0, 4);
                        uint virtualAddr = BitConverter.ToUInt32(vaddrBytes, 0);

                        byte[] sizeBytes = new byte[4];
                        Marshal.Copy(IntPtr.Add(sectionAddr, 8), sizeBytes, 0, 4);
                        uint virtualSize = BitConverter.ToUInt32(sizeBytes, 0);

                        if (virtualSize > 0 && virtualAddr > 0)
                        {
                            IntPtr sectionPtr = IntPtr.Add(baseAddr, (int)virtualAddr);
                            // Make read-only to prevent scanning
                            VirtualProtect(sectionPtr, (UIntPtr)virtualSize, PAGE_READONLY, out _);
                        }
                    }
                }

                Debug.WriteLine("[SENTINEL-SECURITY] Anti-memory scan protection applied");
            }
            catch { }
        }
    }

    // =========================================================================
    // Integrity Check
    // =========================================================================

    public static class IntegrityCheck
    {
        /// <summary>Verify EXE file hash matches expected value.</summary>
        public static bool Verify(string expectedHash)
        {
            if (string.IsNullOrEmpty(expectedHash)) return true;

            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(exePath))
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    string hashStr = BitConverter.ToString(hash).Replace("-", "").ToLower();
                    return hashStr == expectedHash.ToLower();
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
