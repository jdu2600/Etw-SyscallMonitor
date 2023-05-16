namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// profiles use of an (interesting) subset of syscalls using Microsoft-Windows-Kernel-Audit-API-Calls events
    /// </summary>
    internal class Microsoft_Windows_Kernel_Audit_API_Calls : EtwUserTraceProvider
    {
        public Microsoft_Windows_Kernel_Audit_API_Calls(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-Kernel-Audit-API-Calls"; }
        }

        enum ProcessAccessRights : uint {
            TERMINATE = 0x1,
            CREATE_THREAD = 0x2,
            SET_SESSIONID = 0x4,
            VM_OPERATION = 0x8,
            VM_READ = 0x10,
            VM_WRITE = 0x20,
            DUP_HANDLE = 0x40,
            CREATE_PROCESS = 0x80,
            SET_QUOTA = 0x100,
            SET_INFORMATION = 0x200,
            QUERY_INFORMATION = 0x400,
            SUSPEND_RESUME = 0x800,
            QUERY_LIMITED_INFORMATION = 0x1000,
            DELETE = 0x10000,
            READ_CONTROL = 0x20000,
            WRITE_DAC = 0x40000,
            WRITE_OWNER = 0x80000,
            SYNCHRONIZE = 0x100000
        }
        internal string DesiredAccess(uint desiredAccess) {

            if (desiredAccess == 0x1FFFFF)
                return "ALL_ACCESS";

            if (desiredAccess == 0x1F0FFF)
                return "ALL_ACCESS(XP)";

            var rights = new List<string>();
            foreach (uint right in Enum.GetValues(typeof(ProcessAccessRights))) {
                if ((desiredAccess & right) == right)
                    rights.Add(Enum.GetName(typeof(ProcessAccessRights), right));
            }
            return string.Join("|", rights);
        }
        enum ThreadAccessRights : uint {
            TERMINATE = 0x1,
            SUSPEND_RESUME = 0x2,
            ALERT = 0x4,
            GET_CONTEXT = 0x8,
            SET_CONTEXT = 0x10,
            SET_INFORMATION = 0x20,
            QUERY_INFORMATION = 0x40,
            SET_THREAD_TOKEN = 0x80,
            IMPERSONATE = 0x100,
            DIRECT_IMPERSONATION = 0x200,
            SET_LIMITED_INFORMATION = 0x400,
            QUERY_LIMITED_INFORMATION = 0x800,
            DELETE = 0x10000,
            READ_CONTROL = 0x20000,
            WRITE_DAC = 0x40000,
            WRITE_OWNER = 0x80000,
            SYNCHRONIZE = 0x100000
        }
        internal string threadAccessRights(uint desiredAccess) {

            if (desiredAccess == 0x1FFFFF)
                return "ALL_ACCESS";

            if (desiredAccess == 0x1F03FF)
                return "ALL_ACCESS(XP)";

            var rights = new List<string>();
            foreach (uint right in Enum.GetValues(typeof(ThreadAccessRights))) {
                if ((desiredAccess & right) == right)
                    rights.Add(Enum.GetName(typeof(ThreadAccessRights), right));
            }
            return string.Join("|", rights);
        }
        internal override void Enable()
        {
            /*
               Matt's mapping from event ids to API functions -
               https://twitter.com/mattifestation/status/1140655593318993920?s=19

               Event ID 1: PspLogAuditSetLoadImageNotifyRoutineEvent(kernel)
               Event ID 2: PspLogAuditTerminateRemoteProcessEvent
               Event ID 3: NtCreateSymbolicLink
               Event ID 4: PspSetContextThreadInternal
               Event ID 5: PspLogAuditOpenProcessEvent
               Event ID 6: PspLogAuditOpenThreadEvent
               Event ID 7: IoRegisterLastChanceShutdownNotification(kernel)
               Event ID 8: IoRegisterShutdownNotification(kernel)
             */

            var win32Provider = new Provider(this.ProviderName)
            {
                TraceFlags = TraceFlags.IncludeStackTrace
            };

            var terminateProcessFilter = new EventFilter(Filter.EventIdIs(2));
            terminateProcessFilter.OnEvent += (record) =>
            {
                var targetPid = record.GetUInt32("TargetProcessId");
                var target = ProcessCreationTraitsMap.GetTarget(record.ProcessId, targetPid);

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtTerminateProcess({target})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            win32Provider.AddFilter(terminateProcessFilter);

            var createSymbolicLinkFilter = new EventFilter(Filter.EventIdIs(3));
            createSymbolicLinkFilter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtCreateSymbolicLinkObject", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);

            };
            win32Provider.AddFilter(createSymbolicLinkFilter);

            var openProcessFilter = new EventFilter(Filter.EventIdIs(5));
            openProcessFilter.OnEvent += (record) =>
            {
                var targetPid = record.GetUInt32("TargetProcessId");
                var desiredAccess = record.GetUInt32("DesiredAccess");
                var strDesiredAccess = DesiredAccess(desiredAccess);
                var target = ProcessCreationTraitsMap.GetTarget(record.ProcessId, targetPid);

                if(ProcessCreationTraitsMap.interestingTargets.Contains(target))
                {
                    var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtOpenProcess({target}, {strDesiredAccess})", record.GetStackTrace());
                    if (value != null && value.Contains("->kernel32!CreateToolhelp32Snapshot->"))
                        return; // drop some common occurances
                    TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
                }
            };
            win32Provider.AddFilter(openProcessFilter);

            var openThreadFilter = new EventFilter(Filter.EventIdIs(6));
            openThreadFilter.OnEvent += (record) =>
            {
                var targetPid = record.GetUInt32("TargetProcessId");
                var desiredAccess = record.GetUInt32("DesiredAccess");
                var strDesiredAccess = threadAccessRights(desiredAccess);
                var target = ProcessCreationTraitsMap.GetTarget(record.ProcessId, targetPid);
                if (string.IsNullOrEmpty(target) || target == "self")
                    return;

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtOpenThread({target}, {strDesiredAccess})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            win32Provider.AddFilter(openThreadFilter);

            this.trace.Enable(win32Provider);
        }
    }
}