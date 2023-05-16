namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// profiles use of Event Tracing for Windows (ETW)
    /// </summary>
    internal class Microsoft_Windows_Kernel_EventTracing : EtwUserTraceProvider
    {
        public Microsoft_Windows_Kernel_EventTracing(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-Kernel-EventTracing"; }
        }

        private static Dictionary<string, bool> droppedEvents = new Dictionary<string, bool>();

        /// <summary>
        /// enable ETW profiling via Microsoft-Windows-Kernel-EventTracing events
        /// </summary>
        internal override void Enable()
        {
            var etwProvider = new Provider(this.ProviderName);
            etwProvider.Any = 0x10 |   // ETW_KEYWORD_SESSION
                              0x20 |   // ETW_KEYWORD_PROVIDER
                              0x40 |   // ETW_KEYWORD_LOST_EVENT
                              0x400;   // ETW_KEYWORD_ENABLEMENT
            etwProvider.TraceFlags = TraceFlags.IncludeStackTrace;

            // SessionStart
            var sessionStartFilter = new EventFilter(Filter.EventIdIs(2).Or(Filter.EventIdIs(10)));
            sessionStartFilter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtTraceControl(SESSION_START)", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            etwProvider.AddFilter(sessionStartFilter);

            // SessionConfigure
            var sessionConfigureFilter = new EventFilter(Filter.EventIdIs(12).Or(Filter.EventIdIs(17)));
            sessionConfigureFilter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtTraceControl(SESSION_CONFIGURE)", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            etwProvider.AddFilter(sessionConfigureFilter);

            // ProviderEnable
            var providerEnableFilter = new EventFilter(Filter.EventIdIs(14));
            providerEnableFilter.OnEvent += (record) =>
            {
                var provider = new Guid(record.GetBinary("ProviderName"));
                var any = record.GetUInt64("MatchAnyKeyword");
                var all = record.GetUInt64("MatchAllKeyword");
                var level = record.GetUInt8("Level");
                var property = record.GetUInt32("EnableProperty");
                // TODO(jdu) expand enable flags
                // https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtTraceControl(ENABLE_PROVIDER, {provider}, {level}, 0x{any:x}, 0x{all:x}, 0x{property:x})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            etwProvider.AddFilter(providerEnableFilter);

            // ProviderDisable
            var providerDisableFilter = new EventFilter(Filter.EventIdIs(15));
            providerDisableFilter.OnEvent += (record) =>
            {
                var provider = new Guid(record.GetBinary("ProviderName"));
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtTraceControl(DISABLE_PROVIDER, {provider})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            etwProvider.AddFilter(providerDisableFilter);

            // EnableInfo
            var enableInfoFilter = new EventFilter(Filter.EventIdIs(26));
            enableInfoFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("ProcessId", 0);
                var provider = new Guid(record.GetBinary("GUID"));
                var any = record.GetUInt64("MatchAnyKeyword");
                var all = record.GetUInt64("MatchAllKeyword");
                var level = record.GetUInt8("Level");
                var property = record.GetUInt32("EnableProperty");
                // TODO(jdu) expand enable flags
                // https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtTraceControl(CAPTURE_STATE, {provider}, {level}, 0x{any:x}, 0x{all:x}, 0x{property:x})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            etwProvider.AddFilter(enableInfoFilter);

            // Provider
            var providerFilter = new EventFilter(Filter.EventIdIs(27));
            providerFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("ProcessId", 0);
                var provider = new Guid(record.GetBinary("ProviderGUID"));
                var group = new Guid(record.GetBinary("GroupGUID"));
                var flags = record.GetUInt16("Flags");
                var mask = record.GetUInt8("EnableMask");
                var groupMask = record.GetUInt8("GroupEnableMask");
                // TODO(jdu) expand flags
                // https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
                // https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/perfinfo_groupmask.hpp

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtTraceControl(CAPTURE_STATE_KERNEL, {provider}, {group}, 0x{flags:x}, 0x{mask:x}, 0x{groupMask:x})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            etwProvider.AddFilter(providerFilter);

            // LostEvent
            var lostEventFilter = new EventFilter(Filter.EventIdIs(19));
            lostEventFilter.OnEvent += (record) =>
            {
                var sessionName = record.GetUnicodeString("SessionName", string.Empty);
                if (!droppedEvents.ContainsKey(sessionName) && sessionName.StartsWith(typeof(Program).Namespace))
                {
                    Log.WarnWrite($"Dropping events in session {sessionName}...");
                    droppedEvents[sessionName] = true;
                }
            };
            etwProvider.AddFilter(lostEventFilter);

            this.trace.Enable(etwProvider);
        }
    }
}