namespace SyscallSummariser.ETW {
    using Microsoft.O365.Security.ETW;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Security.Principal;

    using static Win32.Kernel32;
    using static Win32.Ntdll;
    using static Win32.Advapi;
    using static Win32.Psapi;
    using System;
    using System.Text;
    using SyscallSummariser.Utilities;
    using System.IO;

    /// <summary>
    /// records the latest ImageName for each ephemeral process id in the <c>ProcessPidMap</c>
    /// using Microsoft-Windows-Kernel-Process events
    /// </summary>
    internal class Microsoft_Windows_Kernel_Process : EtwUserTraceProvider {
        public Microsoft_Windows_Kernel_Process(UserTrace trace) : base(trace) { }

        internal override string ProviderName {
            get { return "Microsoft-Windows-Kernel-Process"; }
        }

        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
        internal static Dictionary<string, string> integrityLevelMap = new Dictionary<string, string>()
        {
            ["S-1-16-0"]      = "Untrusted",  // ML_UNSTRUSTED
            ["S-1-16-4096"]   = "Low",        // ML_LOW
            ["S-1-16-8192"]   = "Medium",     // ML_MEDIUM
            ["S-1-16-8448"]   = "Medium+",    // ML_MEDIUM_PLUS
            ["S-1-16-12288"]  = "High",       // ML_HIGH
            ["S-1-16-16384"]  = "System",     // ML_SYSTEM
            ["S-1-16-20480"]  = "Protected",  // ML_PROTECTED_PROCESS
            ["S-1-16-28672"]  = "Secure"      // ML_SECURE_PROCESS
        };

        /// <summary>
        /// return the friendly name of the integrity level
        /// </summary>
        /// <param name="sid">Mandatory Label (SID)</param>
        /// <returns>the friendly name (if any)</returns>
        internal static string IntegrityLevelFriendlyName(SecurityIdentifier sid) {
            string friendlyName = sid.ToString();
            if (integrityLevelMap.TryGetValue(friendlyName, out string lookup))
                friendlyName = lookup;

            return friendlyName;
        }

        internal override void Enable() {
            
            var processProvider = new Provider(this.ProviderName)
            {
                Any = 0x10 |  // WINEVENT_KEYWORD_PROCESS
                      0x20 |  // WINEVENT_KEYWORD_THREAD
                      0x40 |  // WINEVENT_KEYWORD_IMAGE
                      0x200,  // WINEVENT_KEYWORD_PROCESS_FREEZE
                TraceFlags = TraceFlags.IncludeStackTrace
            };

            var processFilter = new EventFilter(Filter.EventIdIs(1));  // ProcessStart
            processFilter.OnEvent += (record) => {
                ProcessCreationTraitsMap.AddProcess(record);

                var pid = record.GetUInt32("ProcessID");
                var name = Path.GetFileName(record.GetUnicodeString("ImageName"));
                Microsoft_Windows_Threat_Intellgience.EnableReadWriteMemoryLogging((int)pid, name);
                MemoryMap.Add(pid, name);

                var callStack = record.GetStackTrace();
                if (MemoryMap.IsMonitored(pid))
                {
                    var (callingModule, calledApi, callStackSummary) = MemoryMap.FinalUserModule(pid, callStack);
                    if (callingModule == "ntdll" && calledApi == "ntdll!LdrpInitializeProcess" && callStackSummary.Contains("kernelbase!ConsoleAllocate"))
                        return; // ignore conhost
                }

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtCreateUserProcess()", callStack);
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            processProvider.AddFilter(processFilter);

            var processStopFilter = new EventFilter(Filter.EventIdIs(2));  // ProcessStop
            processStopFilter.OnEvent += (record) =>
            {
                // TODO(jdu) handle any deferred events?
                ProcessCreationTraitsMap.RemoveProcess(record);

                // ensure that the output files are updated shortly after process exit
                TraitsProfiler.OutputJsonFiles();
            };
            processProvider.AddFilter(processStopFilter);

            var threadStartFilter = new EventFilter(Filter.EventIdIs(3));  // ThreadStart
            threadStartFilter.OnEvent += (record) => {
                var pid = record.GetUInt32("ProcessID");
                if (pid == 4)
                    return;

                if (pid == record.Id)
                {
                    // CreateThread()
                    var tid = record.GetUInt32("ThreadID");
                    var creatorProcess = pid == record.ProcessId ? null : ProcessCreationTraitsMap.GetProcessTree(record.ProcessId);
                    var win32StartAddress = record.GetUInt64("Win32StartAddr");
                    
                    var regionInfo = new MEMORY_BASIC_INFORMATION();
                    var hProcess = OpenProcess(ProcessDesiredAccess.QueryInformation, false, (int)pid);
                    WindowsPath fullModuleName = null;
                    string type = null;
                    string state = null;
                    string protect = null;
                    string allocationProtect = null;
                    if (!hProcess.IsInvalid)
                    {
                        if (0 != VirtualQueryEx(hProcess, new UIntPtr(win32StartAddress), ref regionInfo, (uint)Marshal.SizeOf(regionInfo)))
                        {
                            type = $"{regionInfo.Type}";
                            state = $"{regionInfo.State}";
                            protect = $"{regionInfo.Protect}";
                            allocationProtect = $"{regionInfo.AllocationProtect}";
                        }

                        var filename = new StringBuilder(WindowsPath.MAX_PATH);
                        if (0 != GetMappedFileName(hProcess, regionInfo.BaseAddress, filename, (uint)filename.Capacity))
                        {
                            fullModuleName = new WindowsPath(filename.ToString());
                        }
                    }

                    string win32StartAddr_Symbol = null;
                    if (TraitsProfiler.useCommonSymbols)
                    {
                        win32StartAddr_Symbol = SymbolUtils.GetCommonSymbol(fullModuleName, win32StartAddress - regionInfo.AllocationBase.ToUInt64());
                    }

                    var serviceTag = record.GetUInt32("SubProcessTag");
                    string serviceName = null;
                    if (serviceTag != 0)
                    {
                        var tagQuery = new SC_SERVICE_TAG_QUERY
                        {
                            ProcessId = pid,
                            ServiceTag = serviceTag,
                            Unknown = 0,
                            Buffer = IntPtr.Zero
                        };

                        if (I_QueryTagInformation(IntPtr.Zero, SC_SERVICE_TAG_QUERY_TYPE.ServiceNameFromTagInformation, ref tagQuery) == 0)
                        {
                            serviceName = Marshal.PtrToStringUni(tagQuery.Buffer);
                            LocalFree(tagQuery.Buffer);
                        }
                    }

                    var thread = (type == "MEM_IMAGE") ? fullModuleName.FileName() : $"{type} [{protect}, {allocationProtect}]";
                    if (creatorProcess != null)
                        thread += $", Creator={creatorProcess}";

                    if (!string.IsNullOrEmpty(serviceName))
                        thread += $", Service={serviceName}";

                    if (!string.IsNullOrEmpty(win32StartAddr_Symbol))
                        thread += $", Symbol={win32StartAddr_Symbol}";

                    var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"CreateThread({thread})", record.GetStackTrace());
                    TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
                }
                else
                {
                    // CreateRemoteThread
                    var hProcess = OpenProcess(ProcessDesiredAccess.QueryLimitedInformation, false, (int)pid);
                    var processInformation = new PROCESS_BASIC_INFORMATION();
                    // ignore thread starts in child processes
                    // TODO(jdu) - ignore initial thread start only?
                    if (!hProcess.IsInvalid &&
                        NtQueryInformationProcess(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref processInformation, Marshal.SizeOf(processInformation), out _) != 0 &&
                        pid != processInformation.InheritedFromUniqueProcessId.ToUInt32())
                    {
                        var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"CreateRemoteThread({ProcessCreationTraitsMap.GetProcessName(pid)})", record.GetStackTrace());
                        TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
                    }
                }
            };
            processProvider.AddFilter(threadStartFilter);

            var moduleLoadFilter = new EventFilter(Filter.EventIdIs(5));  // ImageLoad
            moduleLoadFilter.OnEvent += (record) => {

                var image = new WindowsPath(record.GetUnicodeString("ImageName"));
                TraitsProfiler.LogModule(record.ProcessId, image, record);

                var pid = record.GetUInt32("ProcessID");
                var imageBase = record.GetUInt64("ImageBase");
                MemoryMap.Add(pid, new LoadedImage(record));
            };
            processProvider.AddFilter(moduleLoadFilter);

            var imageUnloadFilter = new EventFilter(Filter.EventIdIs(6));
            imageUnloadFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("ProcessID");
                UInt64 imageBase = record.GetUInt64("ImageBase");
                MemoryMap.Remove(pid, imageBase);
            };
            processProvider.AddFilter(imageUnloadFilter);

            // NtProcessSuspend - but not CREATE_SUSPENDED?
            var processFreezeFilter = new EventFilter(Filter.EventIdIs(11));  // ProcessFreeze
            processFreezeFilter.OnEvent += (record) => {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtProcessSuspend", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            processProvider.AddFilter(processFreezeFilter);

            this.trace.Enable(processProvider);
        }
    }
}