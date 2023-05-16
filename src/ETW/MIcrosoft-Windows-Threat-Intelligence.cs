namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;
    using static Win32.Kernel32;
    using static Win32.Ntdll;

    /// <summary>
    /// profiles use of security relevant kernel APIs
    /// </summary>
    internal class Microsoft_Windows_Threat_Intellgience : EtwUserTraceProvider
    {
        public Microsoft_Windows_Threat_Intellgience(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-Threat-Intelligence"; }
        }

        private string EnrichPointer(IEventRecord record, string addressField, string mappedfilenameField, string regionTypeField)
        {
            var address = record.GetUInt64(addressField, 0);
            var targetPid = record.GetUInt32("TargetProcessId");
            var owner = MemoryMap.GetOwner(targetPid, address);

            if (owner == MemoryMap.Unknown && !string.IsNullOrEmpty(mappedfilenameField))
            {
                owner = Path.GetFileName(record.GetUnicodeString(mappedfilenameField, ""));
                if (string.IsNullOrEmpty(owner))
                    owner = $"{(MemoryType)record.GetUInt32(regionTypeField, 0)}";
            }

            return owner;
        }

        public static void EnableReadWriteMemoryLogging(int pid, string name, bool verbose = false)
        {
            // Note this only works on Windows 10.
            // This syscall has been hardened in Windows 11.
            using (var hProcess = OpenProcess(ProcessDesiredAccess.SetLimitedInformation, false, pid))
            {
                if (!hProcess.IsInvalid)
                {
                    var prwmli = new PROCESS_READWRITEVM_LOGGING_INFORMATION
                    {
                        Flags = 3 // EnableReadVmLogging | EnableWriteVmLogging 
                    };
                    _ = NtSetInformationProcess(hProcess, PROCESSINFOCLASS.ProcessEnableReadWriteVmLogging, ref prwmli, Marshal.SizeOf(prwmli));
                }
            }
        }

        /// <summary>
        /// enable ETW profiling via Microsoft-Windows-Threat-Intelligence events
        /// </summary>
        internal override void Enable()
        {
            if (!Program.runAsPPL)
            {
                Log.WarnWrite($"Skipping {ProviderName} - insufficient privilege");
                Log.WarnWrite(" --> PPLKillerDLL.dll (BYOVD) is missing");
                this.trace = null;
                return;
            }

            foreach (var name in ProcessCreationTraitsMap.interestingTargetProcesses)
            {
                foreach(var process in Process.GetProcessesByName(name)) {
                    EnableReadWriteMemoryLogging(process.Id, name);
                }
            }

            var tiProvider = new Provider(this.ProviderName)
            {
                TraceFlags = TraceFlags.IncludeStackTrace
            };

            //  1 ALLOCVM_REMOTE
            //  6 ALLOCVM_LOCAL
            // 21 ALLOCVM_REMOTE_KERNEL_CALLER
            // 26 ALLOCVM_LOCAL_KERNEL_CALLER
            var allocVMFilter = new EventFilter(Filter.EventIdIs(1)
                                            .Or(Filter.EventIdIs(6))
                                            .Or(Filter.EventIdIs(21))
                                            .Or(Filter.EventIdIs(26)));
            allocVMFilter.OnEvent += (record) => {

                var region = new MemoryRegion(record, true, (record.Id & 1) == 1);
                MemoryMap.Add(region.Pid, region.BaseAddress, region);

                var callingPid = (record.Id == 21 || record.Id == 26) ? 4 : record.GetUInt32("CallingProcessId");
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(callingPid, targetPid);
                var protection = (MemoryProtection)record.GetUInt32("ProtectionMask");
                var type = $"{(MemoryState)record.GetUInt32("AllocationType")}".Replace(", ", "|"); ;
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtProtectVirtualMemory({target}, {protection}, {type})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            tiProvider.AddFilter(allocVMFilter);

            //  2 PROTECTVM_REMOTE
            //  7 PROTECTVM_LOCAL
            // 22 PROTECTVM_REMOTE_KERNEL_CALLER
            // 27 PROTECTVM_LOCAL_KERNEL_CALLER
            var protectVMFilter = new EventFilter(Filter.EventIdIs(2)
                                              .Or(Filter.EventIdIs(7))
                                              .Or(Filter.EventIdIs(22))
                                              .Or(Filter.EventIdIs(27)));
            protectVMFilter.OnEvent += (record) => {
                var region = new MemoryRegion(record, false, (record.Id & 1) == 0);
                MemoryMap.Add(region.Pid, region.BaseAddress, region);
                
                var callingPid = (record.Id == 22 || record.Id == 27) ? 4 : record.GetUInt32("CallingProcessId");
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(callingPid, targetPid);
                var originalProtection = (MemoryProtection)record.GetUInt32("VaVadAllocationProtect", 0); // 21H2+
                var originalProtectionString = (originalProtection == MemoryProtection.Unknown) ? "" : $"{ originalProtection}->";
                var oldProtection = (MemoryProtection)record.GetUInt32("LastProtectionMask");
                var protection = (MemoryProtection)record.GetUInt32("ProtectionMask");
                var address = EnrichPointer(record, "BaseAddress", "VaVadMmfName", "VaVadRegionType");
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtProtectVirtualMemory({target}, {address}, {originalProtectionString}{oldProtection}->{protection})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);

            };
            tiProvider.AddFilter(protectVMFilter);

            //  3 MAPVIEW_REMOTE
            //  8 MAPVIEW_LOCAL
            // 23 MAPVIEW_REMOTE_KERNEL_CALLER
            // 28 MAPVIEW_LOCAL_KERNEL_CALLER
            var mapViewFilter = new EventFilter(Filter.EventIdIs(3)
                                              .Or(Filter.EventIdIs(8))
                                              .Or(Filter.EventIdIs(23))
                                              .Or(Filter.EventIdIs(28)));
            mapViewFilter.OnEvent += (record) => {
                var region = new MemoryRegion(record, (record.Id & 1) == 1);
                MemoryMap.Add(region.Pid, region.BaseAddress, region);
                // TODO kernel callers

                var callingPid = (record.Id == 23 || record.Id == 28) ? 4 : record.GetUInt32("CallingProcessId");
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(callingPid, targetPid);
                var type = (MemoryType)record.GetUInt32("AllocationType");
                var protection = (MemoryProtection)record.GetUInt32("ProtectionMask");

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"API-MapViewOfSection({target}, {type}, {protection}))", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);

            };
            tiProvider.AddFilter(mapViewFilter);

            //  4 QUEUEUSERAPC_REMOTE
            // 24 QUEUEUSERAPC_REMOTE_KERNEL_CALLER
            var queueApcFilter = new EventFilter(Filter.EventIdIs(4)
                                             .Or(Filter.EventIdIs(24)));
            queueApcFilter.OnEvent += (record) => {
                var callingPid = (record.Id == 25) ? 4 : record.GetUInt32("CallingProcessId");
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(callingPid, targetPid);
                var apcRoutine = EnrichPointer(record, "ApcRoutine", "ApcRoutineVadAllocationProtect", "ApcRoutineVadMmfName");
                var apcArgument1 = EnrichPointer(record, "ApcArgument1", "ApcArgument1VadMmfName", "ApcArgument1VadRegionType");
                var apcArgument2 = EnrichPointer(record, "ApcArgument2", null, null); // TODO(jdu) feature request?
                var apcArgument3 = EnrichPointer(record, "ApcArgument3", null, null);
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"API-QueueUserAPC({target}, {apcRoutine} {apcArgument1}, {apcArgument2}, {apcArgument3})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            tiProvider.AddFilter(queueApcFilter);

            //  5 SETTHREADCONTEXT_REMOTE
            // 25 SETTHREADCONTEXT_REMOTE_KERNEL_CALLER
            var threadContextFilter = new EventFilter(Filter.EventIdIs(5)
                                                  .Or(Filter.EventIdIs(25)));
            threadContextFilter.OnEvent += (record) => {
                var callingPid = (record.Id == 25) ? 4 : record.GetUInt32("CallingProcessId");
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(callingPid, targetPid);
                var rip = EnrichPointer(record, "Pc", "PcVadMmfName", "PcVadRegionType");
                // TODO - enrich Reg0..Reg7, Sp, Fp to find oddities?
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"API-SetThreadContext({target}, {rip}))", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            tiProvider.AddFilter(threadContextFilter);

            // 11 READVM_LOCAL
            // 12 WRITEVM_LOCAL
            // 13 READVM_REMOTE
            // 14 WRITEVM_REMOTE
            var readWriteFilter = new EventFilter(Filter.EventIdIs(11)
                                              .Or(Filter.EventIdIs(12))
                                              .Or(Filter.EventIdIs(13))
                                              .Or(Filter.EventIdIs(14)));
            readWriteFilter.OnEvent += (record) => {
                var api = (record.Id % 2 == 1) ? "NtReadVirtualMemory" : "NtWriteVirtualMemory";
                var callingPid = record.GetUInt32("CallingProcessId");
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(callingPid, targetPid);
                if (string.IsNullOrEmpty(target) || target == "self")
                    return;

                var originalProtection = (MemoryProtection)record.GetUInt32("VaVadAllocationProtect", 0);// 21H2+
                var targetRegion = EnrichPointer(record, "BaseAddress", "VaVadMmfName", "VaVadRegionType");
                var szOriginalProtection = originalProtection == MemoryProtection.Unknown ? "" : $", {originalProtection}";
                var szTargetRegion = (targetRegion == MemoryMap.Unknown || targetRegion == MemoryMap.NULL) ? "" : $", {targetRegion}";

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"{api}({target}{szTargetRegion}{szOriginalProtection})", record.GetStackTrace());
                if (value != null && (value.Contains("->kernelbase!K32GetModuleFileName") || value.Contains("->kernel32!CreateToolhelp32Snapshot->")))
                    return; // drop common PEB reads
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            tiProvider.AddFilter(readWriteFilter);

            // 15 SUSPEND_THREAD
            // 16 RESUME_THREAD
            // 17 SUSPEND_PROCESS
            // 18 RESUME_PROCESS
            // 19 FREEZE_PROCESS
            // 20 THAW_PROCESS
            var suspendResumeFilter = new EventFilter(Filter.EventIdIs(15)
                                                  .Or(Filter.EventIdIs(16))
                                                  .Or(Filter.EventIdIs(17))
                                                  .Or(Filter.EventIdIs(18))
                                                  .Or(Filter.EventIdIs(19))
                                                  .Or(Filter.EventIdIs(20)));
            suspendResumeFilter.OnEvent += (record) => {
                var api = "%error%";
                switch(record.Id)
                {
                    case 15:
                        api = "SuspendThread";
                        break;
                    case 16:
                        api = "ResumeThread";
                        break;
                    case 17:
                        api = "SuspendProcess";
                        break;
                    case 18:
                        api = "ResumeProcess";
                        break;
                    case 19:
                        api = "FreezeProcess";
                        break;
                    case 20:
                        api = "ThawProcess";
                        break;
                }
                var callingPid = record.GetUInt32("CallingProcessId");
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(callingPid, targetPid);
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"API-{api}({target})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            tiProvider.AddFilter(suspendResumeFilter);

            // 29 DRIVER_DEVICE
            // 30 DRIVER_DEVICE
            var driverLoadFilter = new EventFilter(Filter.EventIdIs(29)
                                               .Or(Filter.EventIdIs(30)));
            driverLoadFilter.OnEvent += (record) => {
                var api = (record.Id == 29) ? "NtLoadDriver" : "NtUnloadDriver";
                var driverName = record.GetUnicodeString("DriverName");

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"{api}({driverName})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);

            };
            tiProvider.AddFilter(driverLoadFilter);

            // 31 DRIVER_DEVICE
            // 32 DRIVER_DEVICE
            var driverDeviceFilter = new EventFilter(Filter.EventIdIs(31)
                                                 .Or(Filter.EventIdIs(32)));
            driverDeviceFilter.OnEvent += (record) => {
                var api = (record.Id == 31) ? "NtCreateFile" : "NtClose";
                var driverName = record.GetUnicodeString("DriverName");
                var deviceName = record.GetUnicodeString("DeviceName");
                deviceName = deviceName != "(null)" ? deviceName : driverName;
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"{api}(\\Device{deviceName})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            tiProvider.AddFilter(driverDeviceFilter);

            this.trace.Enable(tiProvider);
        }
    }
}