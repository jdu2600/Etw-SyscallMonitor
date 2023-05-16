using Microsoft.O365.Security.ETW;
using Newtonsoft.Json;
using SyscallSummariser.Utilities;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

using static SyscallSummariser.ETW.Microsoft_Windows_Kernel_Process;
using static Win32.Advapi;
using static Win32.Kernel32;
using static Win32.Ntdll;
using static Win32.Psapi;


namespace SyscallSummariser {
    /*
     * maintain a mapping from pid -> CreationTraitsHash -> CreationTraits
     * 
     */
    class ProcessCreationTraitsMap {
        internal static ConcurrentDictionary<string, ProcessCreationTraits> hashTraitsMap = new ConcurrentDictionary<string, ProcessCreationTraits>();
        internal static ConcurrentDictionary<uint, string> pidHashMap = new ConcurrentDictionary<uint, string>();
        internal static ConcurrentDictionary<uint, string> pidTreeMap = new ConcurrentDictionary<uint, string>();
        internal static ConcurrentDictionary<uint, string> oldPidHashMap = new ConcurrentDictionary<uint, string>();

        internal static string GetProcessTree(uint pid) {
            pidTreeMap.TryGetValue(pid, out var tree);
            return tree;
        }

        internal static void AddProcessTree(uint pid, string parentTree) {
            var node = pidHashMap[pid].Split(':')[0];
            if (string.IsNullOrEmpty(parentTree) || parentTree == "idle")
                pidTreeMap[pid] = node;
            else
                pidTreeMap[pid] = $"{parentTree}->{node}";
        }

        internal static void AddProcess(IEventRecord record) {
            //  Microsoft-Windows-Kernel-Process
            var pid = record.GetUInt32("ProcessID");
            var parentProcessTree = GetProcessTree(record.GetUInt32("ParentProcessID"));
            var creatorProcess = string.Empty;
            if (record.Id == 1) // ProcessStart events only - ProcessRundown events don't include an accurate creator ThreadId
                creatorProcess = GetProcessTree(record.ProcessId);
            var sessionId = record.GetUInt32("SessionID");
            var flags = record.GetUInt32("Flags");
            var processTokenElevationType = record.GetUInt32("ProcessTokenElevationType");
            var processTokenIsElevated = record.GetUInt32("ProcessTokenIsElevated");
            var integrityLevel = IntegrityLevelFriendlyName(new SecurityIdentifier(record.GetBinary("MandatoryLabel"), 0));
            var fullProcessImageName = new WindowsPath(record.GetUnicodeString("ImageName", string.Empty));

            var processTraits = new ProcessCreationTraits
            {
                ParentProcessTree = parentProcessTree,
                CreatorProcess = creatorProcess,
                SessionID = $"{sessionId}",
                Flags = $"0x{flags:x}",
                ProcessTokenElevationType = $"{processTokenElevationType}",
                ProcessTokenIsElevated = $"{processTokenIsElevated}",
                MandatoryLabel = integrityLevel,
                OriginalFilename = PeMetadata.GetOriginalFilename(fullProcessImageName.DrivePath),
                Signer = PeMetadata.GetSigner(fullProcessImageName.DrivePath),
                ImageName = fullProcessImageName.NormalisedPath
            };

            // CommandLine (and UserSid) are best effort only.
            // These are availble in the 'Windows Kernel Trace' provider ETW process start event.
            // However introducing a second ETW session also introduces out-of-order events.
            var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessID = {pid}");
            foreach (ManagementObject wmiProcess in searcher.Get()) {
                if (pid != (uint)wmiProcess["ProcessId"])
                    continue;

                var commandLine = wmiProcess["CommandLine"] != null ? (string)wmiProcess["CommandLine"] : string.Empty;
                processTraits.CommandLineExtract = ExtractInterestingCommandLine(commandLine, fullProcessImageName);

                var argList = new string[] { string.Empty };
                try {
                    if (Convert.ToInt32(wmiProcess.InvokeMethod("GetOwnerSid", argList)) == 0)
                        processTraits.UserSID = ProcessUtils.NormaliseSID(argList[0]);
                } catch { }
                
            }

            LogProcess(pid, processTraits);
        }

        private static string ExtractInterestingCommandLine(string commandLine, WindowsPath fullProcessImageName) {
            var interestingCommandline = string.Empty;

            // some processes have entire commandlines that are interesting
            var interestingFullCommandlineRegex = new Regex(@"^(" +
                @"(%windir%\\system32\\svchost)|" +
                @"(%windir%\\System32\\dllhost)|" +
                @"(%windir%\\System32\\taskhostw)|" +
                @")\.exe$", RegexOptions.IgnoreCase);

            if (interestingFullCommandlineRegex.Match(fullProcessImageName.NormalisedPath).Success) {
                var commandWords = commandLine.Split(' ').ToList(); // splitting on ' ' is safe only because of the list of matching processes
                commandWords.RemoveAt(0);  // remove process name
                interestingCommandline = string.Join(" ", commandWords);
                interestingCommandline = "'" + interestingCommandline + "'";
            }

            // some processes have just an interesting first argument
            var interestingArgumentRegex = new Regex(@"^(" +
                @"(%windir%\\system32\\rundll32)|" +
                @")\.exe$", RegexOptions.IgnoreCase);
            if (interestingArgumentRegex.Match(fullProcessImageName.NormalisedPath).Success)
                interestingCommandline = commandLine.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[1];

            // some processes have an interesting sub-type specified on the commandline - especially chrome
            var typeMatches = new Regex(@"(?<type>--type=\w+)", RegexOptions.IgnoreCase).Match(commandLine);
            if (string.IsNullOrEmpty(interestingCommandline) && typeMatches.Success)
                interestingCommandline = typeMatches.Groups["type"].Value;

            // Microsoft Office / Internet Explorer automation 'Embedding' instances are interesting
            if (string.IsNullOrEmpty(interestingCommandline) && commandLine.EndsWith(" -Embedding"))
                
                interestingCommandline = "-Embedding";

            return interestingCommandline;
        }

        internal static void LogProcess(UInt32 pid, ProcessCreationTraits processTraits) {
            var processHash = processTraits.Hash();
            hashTraitsMap[processHash] = processTraits;
            pidHashMap[pid] = processHash;
            AddProcessTree(pid, processTraits.ParentProcessTree);

            TraitsProfiler.LogFeature(pid, "ProcessCreationTraitsHash", processHash);

            TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"ImageName={processTraits.ImageName}");
            if (!string.IsNullOrEmpty(processTraits.CommandLineExtract))
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"CommandLineExtract={processTraits.CommandLineExtract}");
            if (processTraits.ParentProcessTree != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"ParentProcessTree={processTraits.ParentProcessTree}");
            TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"SessionID={processTraits.SessionID}");
            if (processTraits.CreatorProcess != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"CreatorProcess={processTraits.CreatorProcess}");
            if (processTraits.Flags != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"Flags={processTraits.Flags}");
            if (processTraits.UserSID != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"UserSID={processTraits.UserSID}");
            if (processTraits.ProcessTokenIsElevated != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"ProcessToken IsElevated={processTraits.ProcessTokenIsElevated} Type={processTraits.ProcessTokenElevationType}");
            if (processTraits.MandatoryLabel != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"MandatoryLabel={processTraits.MandatoryLabel}");
            if (processTraits.OriginalFilename != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"OriginalFilename={processTraits.OriginalFilename}");
            if (processTraits.Signer != null)
                TraitsProfiler.LogFeature(pid, "ProcessCreationTraits", $"Signer={processTraits.Signer}");
        }

        internal static void RemoveProcess(IEventRecord record) {
            var pid = record.GetUInt32("ProcessID");
            // drop future events for exited processes/threads now rather than risk bad data
            // we could use the ProcessStartKey instead - but not all events include this, and there is no thread equivalent
            // ETW queues can either be system-wide with guaranteed event order, or per-processor for performance
            // ETW queues are flushed when full, or every second otherwise
            pidHashMap.TryRemove(pid, out var traitsHash);
            oldPidHashMap.TryRemove(pid, out _);
            oldPidHashMap[pid] = traitsHash;
        }

        internal static string GetCreationTraitsHash(uint pid) {
            pidHashMap.TryGetValue(pid, out var traitsHash);
            if (traitsHash == null)
            {
                // There is a race condition on startup between the process scan and
                // the ETW session starting.
                AddProcessViaScan((int)pid);
                pidHashMap.TryGetValue(pid, out traitsHash);
            }

            return traitsHash;
        }


        internal static ProcessCreationTraits GetCreationTraits(uint id) {
            ProcessCreationTraits creationTraits = null;
            pidHashMap.TryGetValue(id, out var hash);
            if(hash == null)
                oldPidHashMap.TryGetValue(id, out hash);
            if (hash != null)
                hashTraitsMap.TryGetValue(hash, out creationTraits);
            return creationTraits;
        }

        internal static string GetProcessName(uint id) {
            var creationTraits = GetCreationTraits(id);
            return creationTraits == null ? $"pid:{id}" : creationTraits.ProcessName();
        }

        internal static readonly string[] interestingTargetProcesses = { "lsass", "explorer", "svchost", "spoolsv", "winlogon" };
        internal static readonly string[] interestingTargets = { "lsass", "System" };

        internal static string GetTarget(uint callingPid, uint targetPid)
        {
            if(targetPid == 0)
            {
                return "all";
            }
            
            if (targetPid == callingPid)
            {
                return "self";
            }

            // :TODO: add "child"? requires a cache of parent pids

            var traits = ProcessCreationTraitsMap.GetCreationTraits(targetPid);
            if (Path.GetFileNameWithoutExtension(traits?.ProcessName()) == "lsass")
            {
                return "lsass";
            }

            return traits?.MandatoryLabel;

        }

        internal static void PrePopulateScan() {
            var bufferSize = 0x1000000; // YOLO
            var buffer = Marshal.AllocHGlobal(bufferSize);

            Log.Write("Listing processes via NtQuerySystemInformation(SystemProcessInformation)");
            if (NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemProcessInformation, buffer, bufferSize, out var _) != 0)
                throw new Exception($"SystemProcessInformation - buffer too small  error={Marshal.GetLastWin32Error()}");

            // Enumerate CommandLine and UserSID via WMI
            var commandLines = new ConcurrentDictionary<uint, string>();
            var userSids = new ConcurrentDictionary<uint, string>();
            var mgmtClass = new ManagementClass("Win32_Process");
            foreach (ManagementObject wmiProcess in mgmtClass.GetInstances()) {
                var pid = (uint)wmiProcess["ProcessId"];
                if (pid == 0)
                    continue;

                commandLines[pid] = wmiProcess["CommandLine"] != null ? (string)wmiProcess["CommandLine"] : string.Empty;

                var argList = new string[] { string.Empty };
                try {
                    if (Convert.ToInt32(wmiProcess.InvokeMethod("GetOwnerSid", argList)) == 0)
                        userSids[pid] = argList[0];
                } catch {
                    userSids[pid] = null;
                }
            }

            var process = new SYSTEM_PROCESS_INFORMATION();
            var processOffset = buffer;
            do {
                var processTraits = new ProcessCreationTraits();
                try {
                    process = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(processOffset, process.GetType());
                    processTraits.SessionID = $"{process.SessionId}";

                    var hProcessLimited = OpenProcess(ProcessDesiredAccess.QueryLimitedInformation, false, (int)process.UniqueProcessId);
                    if (hProcessLimited.IsInvalid) {
                        if ((int)process.UniqueProcessId == 0)
                            throw new NotSupportedException("The parameter is incorrect");  // Idle
                        if (Marshal.GetLastWin32Error() == 87)
                            throw new TimeoutException("The parameter is incorrect");  // process exited
                        throw new ApplicationException($"OpenProcess(QueryLimitedInformation) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    }

                    userSids.TryGetValue((uint)process.UniqueProcessId, out var userSid);
                    processTraits.UserSID = ProcessUtils.NormaliseSID(userSid);

                    var processInformation = new PROCESS_BASIC_INFORMATION();
                    if (NtQueryInformationProcess(hProcessLimited, PROCESSINFOCLASS.ProcessBasicInformation, ref processInformation, Marshal.SizeOf(processInformation), out _) != 0)
                        throw new ApplicationException($"NtQueryInformationProcess(ProcessBasicInformation) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    processTraits.ParentProcessTree = GetProcessTree((UInt32)processInformation.InheritedFromUniqueProcessId);

                    var maxPath = WindowsPath.MAX_PATH;
                    var nameBuffer = new StringBuilder((int)maxPath);
                    if (GetProcessImageFileName(hProcessLimited, nameBuffer, maxPath) > 0) {
                        var path = new WindowsPath(nameBuffer.ToString());
                        processTraits.OriginalFilename = PeMetadata.GetOriginalFilename(path.DrivePath);
                        processTraits.Signer = PeMetadata.GetSigner(path.DrivePath);
                        processTraits.ImageName = path.NormalisedPath;
                        if (commandLines.ContainsKey((uint)process.UniqueProcessId))
                        {
                            processTraits.CommandLineExtract = ExtractInterestingCommandLine(commandLines[(uint)process.UniqueProcessId], path);
                        }
                    } else
                        processTraits.ImageName = Process.GetProcessById((int)process.UniqueProcessId).ProcessName;

                    if (!OpenProcessToken(hProcessLimited, TOKEN_QUERY, out var hToken)) {
                        if ((int)process.UniqueProcessId == 4)
                            throw new NotSupportedException("Access is denied");  // System
                        throw new ApplicationException($"OpenProcessToken(TOKEN_QUERY) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    }

                    var isElevated = new TOKEN_ELEVATION();
                    if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, ref isElevated, (uint)Marshal.SizeOf(isElevated), out var _))
                        throw new ApplicationException($"GetTokenInformation(TokenElevation) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    processTraits.ProcessTokenIsElevated = $"{isElevated.TokenIsElevated}";

                    var elevationType = new TOKEN_ELEVATION_TYPE();
                    if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, ref elevationType, (uint)Marshal.SizeOf(elevationType), out _))
                        throw new ApplicationException($"GetTokenInformation(TokenElevationType) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    processTraits.ProcessTokenElevationType = $"{elevationType.TokenElevationType}";

                    var mandatoryLabel = new TOKEN_MANDATORY_LABEL();
                    if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ref mandatoryLabel, (uint)Marshal.SizeOf(mandatoryLabel), out _))
                        throw new ApplicationException($"GetTokenInformation(TokenIntegrityLevel) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    processTraits.MandatoryLabel = IntegrityLevelFriendlyName(new SecurityIdentifier(mandatoryLabel.Sid));

                    var isWow64Process = false;
                    if (!IsWow64Process(hProcessLimited, out isWow64Process))
                        throw new ApplicationException($"IsWow64Process failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");

                    var hProcessRead = OpenProcess(ProcessDesiredAccess.QueryInformation | ProcessDesiredAccess.VirtualMemoryRead, false, (int)process.UniqueProcessId);
                    if (!hProcessRead.IsInvalid) {
                        var processParametersOffset = isWow64Process ? 0x10 : 0x20;
                        var processParametersBufferSize = isWow64Process ? 4 : 8;
                        var processParametersBuffer = new byte[processParametersBufferSize];
                        if (ReadProcessMemory(hProcessRead, new UIntPtr((UInt64)processInformation.PebBaseAddress + (UInt32)processParametersOffset), processParametersBuffer, processParametersBufferSize, out _)) {
                            UInt64 pProcessParameters = isWow64Process ? (UInt32)BitConverter.ToInt32(processParametersBuffer, 0) : (UInt64)BitConverter.ToInt64(processParametersBuffer, 0);
                            var flagsBuffer = new byte[4];
                            if (ReadProcessMemory(hProcessRead, new UIntPtr(pProcessParameters + sizeof(ulong) * 2), flagsBuffer, 4, out _)) {
                                processTraits.Flags = $"0x{(UInt32)BitConverter.ToInt32(flagsBuffer, 0):x}";
                            }
                        } else {
                            // ReadProcessMemory is failing with a seemingly valid handle...
                            // Close it to prevent future errors.
                            // This seems to occur for Isolated User Mode processes.
                            // :TODO: Check for IUM with IsSecureProcess()?
                            hProcessRead.Close();
                        }
                    }
                } catch (NotSupportedException) { }  // continue
                catch (TimeoutException) { }  // continue
                catch (ApplicationException e) {
                    Log.WarnWrite(e.Message);
                }

                if ((int)process.UniqueProcessId != 0 && processTraits.ImageName != null) {  // not Idle(0) and process has not exited
                    LogProcess((UInt32)process.UniqueProcessId, processTraits);
                }

                processOffset = (IntPtr)((UInt64)processOffset + process.NextEntryOffset);
            } while (0 != process.NextEntryOffset);

            Marshal.FreeHGlobal(buffer);
        }

        internal static void AddProcessViaScan(int pid) {
            var commandLine = string.Empty;
            var userSid = string.Empty;
            var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessID = {pid}");
            foreach (ManagementObject wmiProcess in searcher.Get()) {
                if (pid != (uint)wmiProcess["ProcessId"])
                    continue;

                commandLine = wmiProcess["CommandLine"] != null ? (string)wmiProcess["CommandLine"] : string.Empty;
                var argList = new string[] { string.Empty };
                try {
                    if (Convert.ToInt32(wmiProcess.InvokeMethod("GetOwnerSid", argList)) == 0)
                        userSid = argList[0];
                } catch { }
            }

            var bufferSize = 0x100000; // YOLO
            var buffer = Marshal.AllocHGlobal(bufferSize);
            if (NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemProcessInformation, buffer, bufferSize, out var requiredSize) != 0)
                throw new Exception($"SystemProcessInformation - buffer too small  error={Marshal.GetLastWin32Error()}");

            var processOffset = buffer;

            var process = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(processOffset, typeof(SYSTEM_PROCESS_INFORMATION));
            while (!((int)process.UniqueProcessId == pid || 0 == process.NextEntryOffset)) {
                processOffset = (IntPtr)((UInt64)processOffset + process.NextEntryOffset);
                process = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(processOffset, process.GetType());
            }

            if ((int)process.UniqueProcessId == pid) {
                var processTraits = new ProcessCreationTraits();
                try {
                    processTraits.SessionID = $"{process.SessionId}";

                    var hProcessLimited = OpenProcess(ProcessDesiredAccess.QueryLimitedInformation, false, (int)process.UniqueProcessId);
                    if (hProcessLimited.IsInvalid) {
                        if ((int)process.UniqueProcessId == 0)
                            throw new NotSupportedException("The parameter is incorrect");  // Idle
                        if (Marshal.GetLastWin32Error() == 87)
                            throw new TimeoutException("The parameter is incorrect");  // process exited
                        throw new ApplicationException($"OpenProcess(QueryLimitedInformation) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    }

                    processTraits.UserSID = ProcessUtils.NormaliseSID(userSid);

                    var processInformation = new PROCESS_BASIC_INFORMATION();
                    if (NtQueryInformationProcess(hProcessLimited, PROCESSINFOCLASS.ProcessBasicInformation, ref processInformation, Marshal.SizeOf(processInformation), out _) != 0)
                        throw new ApplicationException($"NtQueryInformationProcess(ProcessBasicInformation) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    
                    processTraits.ParentProcessTree = GetProcessTree((UInt32)processInformation.InheritedFromUniqueProcessId);

                    var maxPath = WindowsPath.MAX_PATH;
                    var nameBuffer = new StringBuilder((int)maxPath);
                    if (GetProcessImageFileName(hProcessLimited, nameBuffer, maxPath) > 0) {
                        var path = new WindowsPath(nameBuffer.ToString());
                        processTraits.OriginalFilename = PeMetadata.GetOriginalFilename(path.DrivePath);
                        processTraits.Signer = PeMetadata.GetSigner(path.DrivePath);
                        processTraits.ImageName = path.NormalisedPath;
                        processTraits.CommandLineExtract = ExtractInterestingCommandLine(commandLine, path);
                    } else
                        processTraits.ImageName = Process.GetProcessById((int)process.UniqueProcessId).ProcessName;

                    if (!OpenProcessToken(hProcessLimited, TOKEN_QUERY, out var hToken)) {
                        if ((int)process.UniqueProcessId == 4)
                            throw new NotSupportedException("Access is denied");  // System
                        throw new ApplicationException($"OpenProcessToken(TOKEN_QUERY) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    }

                    var isElevated = new TOKEN_ELEVATION();
                    if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, ref isElevated, (uint)Marshal.SizeOf(isElevated), out var _))
                        throw new ApplicationException($"GetTokenInformation(TokenElevation) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    processTraits.ProcessTokenIsElevated = $"{isElevated.TokenIsElevated}";

                    var elevationType = new TOKEN_ELEVATION_TYPE();
                    if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, ref elevationType, (uint)Marshal.SizeOf(elevationType), out _))
                        throw new ApplicationException($"GetTokenInformation(TokenElevationType) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    processTraits.ProcessTokenElevationType = $"{elevationType.TokenElevationType}";

                    var mandatoryLabel = new TOKEN_MANDATORY_LABEL();
                    if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ref mandatoryLabel, (uint)Marshal.SizeOf(mandatoryLabel), out _))
                        throw new ApplicationException($"GetTokenInformation(TokenIntegrityLevel) failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");
                    processTraits.MandatoryLabel = IntegrityLevelFriendlyName(new SecurityIdentifier(mandatoryLabel.Sid));

                    var isWow64Process = false;
                    if (!IsWow64Process(hProcessLimited, out isWow64Process))
                        throw new ApplicationException($"IsWow64Process failed - pid={process.UniqueProcessId} error={Marshal.GetLastWin32Error()}");

                    var hProcessRead = OpenProcess(ProcessDesiredAccess.QueryInformation | ProcessDesiredAccess.VirtualMemoryRead, false, (int)process.UniqueProcessId);
                    if (!hProcessRead.IsInvalid) {
                        var processParametersOffset = isWow64Process ? 0x10 : 0x20;
                        var processParametersBufferSize = isWow64Process ? 4 : 8;
                        var processParametersBuffer = new byte[processParametersBufferSize];
                        if (ReadProcessMemory(hProcessRead, new UIntPtr((UInt64)processInformation.PebBaseAddress + (UInt32)processParametersOffset), processParametersBuffer, processParametersBufferSize, out _)) {
                            UInt64 pProcessParameters = isWow64Process ? (UInt32)BitConverter.ToInt32(processParametersBuffer, 0) : (UInt64)BitConverter.ToInt64(processParametersBuffer, 0);
                            var flagsBuffer = new byte[4];
                            if (ReadProcessMemory(hProcessRead, new UIntPtr(pProcessParameters + sizeof(ulong) * 2), flagsBuffer, 4, out _)) {
                                processTraits.Flags = $"0x{(UInt32)BitConverter.ToInt32(flagsBuffer, 0):x}";
                            }
                        }
                        // fall through on error
                    }
                } catch (NotSupportedException) { }  // continue
                catch (TimeoutException) { }  // continue
                catch (ApplicationException e) {
                    Log.WarnWrite(e.Message);
                }

                if ((int)process.UniqueProcessId != 0 && processTraits.ImageName != null) {  // not Idle(0) and process has not exited
                    LogProcess((UInt32)process.UniqueProcessId, processTraits);
                }
            }

            Marshal.FreeHGlobal(buffer);
        }
    }

    public class ProcessCreationTraits {
        public const string UnknownProcess = "Unknown";

        [JsonProperty(Order = 1)]
        public string ParentProcessTree { get; set; }

        // Note - we don't need to explcitly log the pid of the creator process
        // This is implied from the tid.
        [JsonProperty(Order = 2)]
        public string CreatorProcess { get; set; }

        [JsonProperty(Order = 3)]
        public string SessionID { get; set; }

        [JsonProperty(Order = 4)]
        public string Flags { get; set; }

        [JsonProperty(Order = 5)]
        public string ProcessTokenElevationType { get; set; }

        [JsonProperty(Order = 6)]
        public string ProcessTokenIsElevated { get; set; }

        [JsonProperty(Order = 7)]
        public string MandatoryLabel { get; set; }

        [JsonProperty(Order = 8)]
        public string ImageName { get; set; }

        [JsonProperty(Order = 9)]
        public string OriginalFilename { get; set; }

        [JsonProperty(Order = 10)]
        public string Signer { get; set; }
        
        [JsonProperty(Order = 11)]
        public string UserSID { get; set; }

        [JsonProperty(Order = 12)]
        public string CommandLineExtract { get; set; }

        // Note - We deliberately don't log variable fields such as file hash and file version
        // Doing this creates a more stable, though slightly lesss accurate, fingerprint

        public string Hash()
        {
            return Prefix() + HashUtils.SHA1(this.ToJson());
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        public string ProcessName() {
            if (ImageName == null)
                return UnknownProcess;
            if (ImageName.Contains("\\"))
                return new Regex(@"^.*\\(?<name>[^\\]+)$").Match(ImageName).Groups["name"].Value;
            return ImageName;
        }

        internal string Prefix() {
            return $"{ProcessName()}::";
        }

        public string FilePath() {
            return Hash().Replace(':', '_');
        }
    }
}
