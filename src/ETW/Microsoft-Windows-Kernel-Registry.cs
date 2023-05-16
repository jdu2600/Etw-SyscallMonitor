namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;
    using System;
    using System.Text.RegularExpressions;

    /// <summary>
    /// profiles use of a registry APIs using Microsoft-Windows-Kernel-Registry events
    /// </summary>
    internal class Microsoft_Windows_Kernel_Registry : EtwUserTraceProvider
    {
        public Microsoft_Windows_Kernel_Registry(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-Kernel-Registry"; }
        }

        internal Regex hiveRegex = new Regex(@"^\\REGISTRY\\(?<hive>[^\\]+)\\");

        internal override void Enable()
        {
            var registryProvider = new Provider(this.ProviderName)
            {
                TraceFlags = TraceFlags.IncludeStackTrace
            };

            var createKeyFilter = new EventFilter(Filter.EventIdIs(1));
            createKeyFilter.OnEvent += (record) =>
            {
                // *** use registry kernel callbacks (or sysmon events) instead ***
                // only having access to relative paths makes this event impractical to profile accurately

                var relativeName = record.GetUnicodeString("RelativeName", string.Empty);
                var hiveMatch = hiveRegex.Match(relativeName);
                var hiveName = hiveMatch.Success ? hiveMatch.Groups["hive"].Value : "";

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtCreateKey({hiveName})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            registryProvider.AddFilter(createKeyFilter);

            var setValueKeyFilter = new EventFilter(Filter.EventIdIs(5));
            setValueKeyFilter.OnEvent += (record) =>
            {
                var callStack = record.GetStackTrace();
                if (MemoryMap.IsMonitored(record.ProcessId))
                {
                    var (callingModule, calledApi, _) = MemoryMap.FinalUserModule(record.ProcessId, callStack);
                    if (callingModule == "ntdll" && calledApi == "ntdll!LdrpInitializeProcess")
                        return; // ignore process initialisation
                }

                // log the data size (to the closest power of eight) for further profiling
                var dataSize = record.GetUInt32("DataSize", 0);
                int i = 0;
                for (i = 8; dataSize > (1 << i); i+=8)
                    ;
                var strDataSize = "size <= " + (8 << i);
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtSetValueKey({strDataSize})", callStack);
                if (value is null ||
                    value.Contains("->kernel32!CreateProcess") ||
                    value.Contains("->kernelbase!CreateProcessAsUser")
                    )
                    return;
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            registryProvider.AddFilter(setValueKeyFilter);

            var setInformationKeyFilter = new EventFilter(Filter.EventIdIs(11));
            setInformationKeyFilter.OnEvent += (record) =>
            {
                var infoClass = KeyInformationClass(record.GetUInt32("InfoClass", UInt32.MaxValue));
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtSetInformationKey({infoClass})", record.GetStackTrace());
                if (infoClass == "KeyFlagsInformation")
                    return;  // too common
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);

            };
            registryProvider.AddFilter(setInformationKeyFilter);


            var setSecurityKeyFilter = new EventFilter(Filter.EventIdIs(15));
            setSecurityKeyFilter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtSetSecurityObject(RegistryKey)", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            registryProvider.AddFilter(setSecurityKeyFilter);

            this.trace.Enable(registryProvider);
        }

        private static string KeyInformationClass(UInt32 infoClass)
        {
            if (infoClass < _KeyInformationClass.Length)
                return _KeyInformationClass[infoClass];

            return $"{infoClass}";
        }

        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ne-wdm-_key_information_class
        private static readonly string[] _KeyInformationClass =
        {
            "KeyBasicInformation",
            "KeyNodeInformation",
            "KeyFullInformation",
            "KeyNameInformation",
            "KeyCachedInformation",
            "KeyFlagsInformation",
            "KeyVirtualizationInformation",
            "KeyHandleTagsInformation",
            "KeyTrustInformation",
            "KeyLayerInformation"
        };
    }
}