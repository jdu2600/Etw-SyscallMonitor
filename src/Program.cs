using Microsoft.Win32;
using SyscallSummariser.ETW;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;

using SyscallSummariser.Utilities;
using System.Windows;

namespace SyscallSummariser
{
    class Program
    {
        [DllImport("PPLKillerDLL.dll")]
        public static extern void EnablePPL(Int32 dwProcessId);

        [DllImport("PPLKillerDLL.dll")]
        public static extern void DisablePPL(Int32 dwProcessId);

        [DllImport("PPLKillerDLL.dll")]
        public static extern void InstallDriver();

        [DllImport("PPLKillerDLL.dll")]
        public static extern void UninstallDriver();

        public static bool verbose = false;
        public static bool runAsPPL = File.Exists("PPLKillerDLL.dll");
        public static bool startupComplete = false;

        private static readonly EtwUserTrace userTrace = new EtwUserTrace();
        private static TraitsProfiler jsonOutputThread = null;

        public static MainWindow mainWindow = null;

        public static void Main()
        {
            lock (_stopLock)  // can't call stop until startup is complete
            {
                // Launch our main GUI window
                var windowThread = new Thread(new ThreadStart(() =>
                    {
                        mainWindow = new MainWindow
                        {
                            Visibility = Visibility.Visible
                        };
                        mainWindow.FontSize = 16;
                        System.Windows.Threading.Dispatcher.Run();
                    }));
                windowThread.SetApartmentState(ApartmentState.STA);
                windowThread.IsBackground = true;
                windowThread.Start();
                while (mainWindow == null)
                    Thread.Sleep(100);

                Log.Write("================================================================================");

                var product = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "").ToString();
                var display = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", "").ToString();
                if (string.IsNullOrEmpty(display))
                {
                    display = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", "").ToString();
                }
                var major = Environment.OSVersion.Version.Major;
                var minor = Environment.OSVersion.Version.Minor;
                var build = Environment.OSVersion.Version.Build;
                var release = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", "").ToString();
                var buildex = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "BuildLabEx", "").ToString();
                Log.Write($"{product} {display} ({major}.{minor}.{build}.{release} {buildex})");

                // Most of the interesting ETW events were introduced in Windows 10
                if (major < 10)
                {
                    Log.ErrorWrite("This program requires NT 10.0+");
                    return;
                }

                // We need Administrator to BYOVD to enable PPL for Microsoft-Windows-Threat-Intelligence
                // We also explicitly need SYSTEM for Microsoft-Windows-Security-Auditing
                if (!TokenUtils.ImpersonateSystem())
                {
                    Log.ErrorWrite("Failed to elevate to SYSTEM - This program must be run as Administrator");
                    return;
                }

                // On Windows 11, this call is hardened to kernel callers - so we see less events.
                if (major > 10)
                {
                    Log.Write("Insufficient privilege to call NtSetInformationProcess(EnableReadWriteVmLogging)");
                    Log.Write(" --> WriteProcessMemory/ReadProcessMemory events only available on Win10");
                }

                // Initialise our TraitsProfiler - this combines similiar processes started with similar attributes
                // into a single entity.
                // It also handles our periodic output to json file
                jsonOutputThread = new TraitsProfiler();

                // We're not using an AutoLogger ETW session (yet) - so enumerate current process state instead.
                // 1. processes - enables partial process tree reconstruction
                /* userTrace.EnumerateProcessState(); */
                // For reasons currently unknown, ETW rundown events are not always generated
                // So scan processes instead :-/
                ProcessCreationTraitsMap.PrePopulateScan();

                // Configure audit policy now.
                // Because, after we enable PPL, launching processes isn't straightforward.
                ProcessUtils.Execute(@"C:\Windows\system32\auditpol.exe", "/set /subcategory:\"Token Right Adjusted Events\"");

                // enable PPL so that we can subscribe to Threat-Intelligence events
                if (runAsPPL)
                {
                    Log.Write("Enabling PPL via DKOM through vulnerable driver...");
                    InstallDriver();
                    EnablePPL(Process.GetCurrentProcess().Id);
                }

                // enable ETW providers
                userTrace.Stop();
                userTrace.Enable();

                if (runAsPPL)
                {
                    // We need PPL for userTrace.trace.Start() below
                    // Afterwards, PPL affects our ability to debug and terminate this process
                    ThreadPool.QueueUserWorkItem(delegate (object _)
                    {
                        // Wait for the userTrace to start
                        do
                        {
                            Thread.Sleep(TimeSpan.FromMilliseconds(100));
                        } while (0 == userTrace.trace.QueryStats().EventsTotal);

                        Thread.Sleep(TimeSpan.FromSeconds(3));
                        startupComplete = true;

                        lock (_stopLock)
                        {
                            if (!stopping)
                            {
                                Log.Write("Disabling PPL via DKOM...");
                                DisablePPL(Process.GetCurrentProcess().Id);
                            }
                        }
                    });
                }

            } // startup complete

            // process the UserMode ETW events on this thread
            if (userTrace != null)
                userTrace.BlockingStart();
            Thread.Sleep(TimeSpan.FromSeconds(5));

            // cleanup
            Stop();
            Log.Write("All done.");
        }

        internal static bool stopping = false;
        internal static object _stopLock = new object();

        public static void Stop()
        {
            lock (_stopLock)
            {
                if (!stopping)
                {
                    stopping = true;

                    Log.Write("Stopping...");
                    if (jsonOutputThread != null)
                        jsonOutputThread.Stop();

                    if (runAsPPL)
                    {
                        // re-enable PPL so that we can exit cleanly
                        EnablePPL(Process.GetCurrentProcess().Id);
                    }

                    userTrace.Stop();
                    Thread.Sleep(TimeSpan.FromSeconds(5));
                }
            }
        }
    }
}
