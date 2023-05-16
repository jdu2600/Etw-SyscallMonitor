namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;

    /// <summary>
    /// profiles use of kernel Graphics Device Interface (GDI) - aka Win32k[.sys]
    /// via Microsoft-Windows-Win32k events
    /// </summary>
    internal class Microsoft_Windows_Win32k : EtwUserTraceProvider
    {
        public Microsoft_Windows_Win32k(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-Win32k"; }
        }

        internal override void Enable()
        {
            var win32kProvider = new Provider(this.ProviderName)
            {
                Any = 0x00000000400 |  // AuditApiCalls
                      0x80000000000,   // ReadClipboard
                TraceFlags = TraceFlags.IncludeStackTrace
            };

            var clipboardEventFilter = new EventFilter(Filter.EventIdIs(463));  // ReadClipboard
            clipboardEventFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("CallerPid");  // logging process pid != event pid for kernel providers
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "Win32k-ReadClipboard", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            win32kProvider.AddFilter(clipboardEventFilter);

            var setWinEventHookFilter = new EventFilter(Filter.EventIdIs(1000));  // SetWinEventHook
            setWinEventHookFilter.OnEvent += (record) =>
            {
                var eventMin = record.GetUInt32("eventMin");
                var eventMax = record.GetUInt32("eventMax");

                var targetPid = record.GetUInt32("idEventProcess");
                var target = ProcessCreationTraitsMap.GetTarget(record.ProcessId, targetPid);

                var thread = record.GetUInt32("idEventThread") == 0 ? "all" : "single";
                var flags = record.GetUInt32("Flags");

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtUserSetWinEventHook(0x{eventMin:x}..0x{eventMax:x}, {target}, {thread}, 0x{flags:x})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);

            };
            win32kProvider.AddFilter(setWinEventHookFilter);

            var task1001Filter = new EventFilter(Filter.EventIdIs(1001));  // RegisterRawInputDevices
            task1001Filter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "Win32k-RegisterRawInputDevices", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);

            };
            win32kProvider.AddFilter(task1001Filter);

            var setWindowsHookFilter = new EventFilter(Filter.EventIdIs(1002));  // SetWindowsHook
            setWindowsHookFilter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtNtUserSetWindowsHookEx", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            win32kProvider.AddFilter(setWindowsHookFilter);

            var getAsyncKeyStateFilter = new EventFilter(Filter.EventIdIs(1003));  // GetAsyncKeyState
            getAsyncKeyStateFilter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "Win32k-GetAsyncKeyState", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            win32kProvider.AddFilter(getAsyncKeyStateFilter);

            this.trace.Enable(win32kProvider);
        }
    }
}