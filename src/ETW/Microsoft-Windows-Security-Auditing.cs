namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;
    using System;
    using System.Security.Principal;

    // Reference: https://medium.com/palantir/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e
    //
    // Note - we enable these events using auditpol.exe, not provider flags.

    internal class Microsoft_Windows_Security_Auditing : EtwUserTraceProvider
    {
        public Microsoft_Windows_Security_Auditing(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-Security-Auditing"; }
        }

        internal override void Enable() {
            if (!WindowsIdentity.GetCurrent().IsSystem)
            {
                Log.VerboseWrite("skipping Microsoft-Windows-Security-Auditing - insufficient privilege");
                return;
            }

            // We can only consume from the existing "EventLog-Security" session.
            // We cannot enable this provider on our own session - even as PPL.
            this.trace = new UserTrace("EventLog-Security");
            var securityAuditProvider = new Provider(this.ProviderName);

            var privilegeAdjustFilter = new EventFilter(Filter.EventIdIs(4703));
            privilegeAdjustFilter.OnEvent += (record) => {
                var pid = (UInt32)record.GetUInt64("ProcessId", 0);
                var privilegeList = record.GetUnicodeString("EnabledPrivilegeList", "");
                foreach (var privilege in privilegeList.Split(new char[] { '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                    TraitsProfiler.LogFeature(pid, "Syscalls", $"RtlAdjustPrivilege({privilege})");
            };
            securityAuditProvider.AddFilter(privilegeAdjustFilter);

            this.trace.Enable(securityAuditProvider);
        }
    }
}