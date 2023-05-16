namespace SyscallSummariser {
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Diagnostics;
    using System.IO;
    using System.Text;
    using System.Text.RegularExpressions;
    using Win32;

    class ProcessUtils {

        internal static void Execute(string filename, string arguments)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = filename,
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                }
            };
            // process.OutputDataReceived += (sender, args) => Log.Write($"[{Path.GetFileNameWithoutExtension(filename)}] {args.Data}");

            Log.Write($"> {Path.GetFileName(filename)} {process.StartInfo.Arguments}");
            process.Start();
            process.BeginOutputReadLine();
            process.WaitForExit();
        }

        internal static WindowsPath GetModuleFileName(SafeProcessHandle hProcess, UIntPtr hModule) {
            // note - GetModuleFileNameEx returns the value from the PEB->LDR_TABLE_ENTRY
            //        this may be the *redirected* path for syswow64 processes
            try {
                var sbModuleFilePath = new StringBuilder(WindowsPath.MAX_PATH);

                if (Psapi.GetModuleFileNameEx(hProcess, hModule, sbModuleFilePath, (uint)sbModuleFilePath.Capacity) != 0)
                    return new WindowsPath(sbModuleFilePath.ToString());
            } catch { }

            return new WindowsPath(string.Empty);
        }

        internal static WindowsPath GetMappedFileName(SafeProcessHandle hProcess, UIntPtr hModule) {
            try {
                var sbModuleFilePath = new StringBuilder(WindowsPath.MAX_PATH);
                if (Psapi.GetMappedFileName(hProcess, hModule, sbModuleFilePath, (uint)sbModuleFilePath.Capacity) != 0)
                    return new WindowsPath(sbModuleFilePath.ToString());
            } catch { }

            return new WindowsPath(string.Empty);
        }

        internal static WindowsPath GetModuleName(SafeProcessHandle hProcess, UIntPtr hModule) {
            try {
                var moduleName = new StringBuilder(WindowsPath.MAX_PATH);
                if (Psapi.GetModuleBaseName(hProcess, hModule, moduleName, (uint)moduleName.Capacity) != 0)
                    return new WindowsPath(moduleName.ToString());
            } catch { }

            return new WindowsPath(string.Empty);
        }

        internal static List<WindowsPath> ModulePaths(Process process) {
            var moduleNames = new List<WindowsPath>();
            try {
                foreach (var module in Modules(process.SafeHandle))
                    moduleNames.Add(GetMappedFileName(process.SafeHandle, module));
            } catch (InvalidOperationException) { } // the process has exited
            catch (Win32Exception) { } // access is denied

            return moduleNames;
        }

        internal static UIntPtr[] Modules(SafeProcessHandle hProcess) {
            var modules = new UIntPtr[0];

            var totalNumberOfModules = 32;
            UIntPtr[] modulePointers;
            int bytesProvided;
            int bytesNeeded;
            try {
                do {
                    totalNumberOfModules *= 2;
                    modulePointers = new UIntPtr[totalNumberOfModules];
                    bytesProvided = UIntPtr.Size * totalNumberOfModules;
                    if (!Psapi.EnumProcessModulesEx(hProcess, modulePointers, bytesProvided, out bytesNeeded, (uint)Psapi.ModuleFilter.ListModulesAll))
                        return modules;
                } while (bytesNeeded > bytesProvided);
                modules = modulePointers;
            } catch (Win32Exception) { }  // access denied
            catch (InvalidOperationException) { } // the process has exited

            return modules;
        }

        internal static string NormaliseSID(string sid) {
            if (sid != null) {
                sid = Regex.Replace(sid, @"^S-1-5-21-\d+-\d+-\d+-(?<rid>5\d\d)", @"S-1-5-21-%domain%-${rid}");
                sid = Regex.Replace(sid, @"^S-1-5-21-\d+-\d+-\d+-\d+", @"S-1-5-21-%domain%-%rid%");
            }
            return sid;
        }
    }
}