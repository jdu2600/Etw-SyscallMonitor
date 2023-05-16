namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;

    /// <summary>
    /// profiles network activity blocked by the Windows Filtering Platform (WFP) via Microsoft-Windows-WFP events
    /// </summary>
    /// Provider suggested by @pathtofile
    internal class Microsoft_Windows_WFP : EtwUserTraceProvider
    {
        public Microsoft_Windows_WFP(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-WFP"; }
        }

        internal ushort ephemeralPortStart = Microsoft_Windows_Kernel_Network.tcpEphemeralPortStart < Microsoft_Windows_Kernel_Network.udpEphemeralPortStart ? 
                                                Microsoft_Windows_Kernel_Network.tcpEphemeralPortStart : 
                                                Microsoft_Windows_Kernel_Network.udpEphemeralPortStart;

        internal override void Enable()
        {
            var wfpProvider = new Provider(this.ProviderName);
            wfpProvider.Any = 0x10;  // AOAC (alternatively 0x10000000000)
            var blockedPacketFilter = new EventFilter(Filter.EventIdIs(1001));  // task_0
            blockedPacketFilter.OnEvent += (record) =>
            {
                var app = record.GetUnicodeString("AppId", string.Empty);
                if (!app.Equals("NULL"))
                {
                    var sockaddr = record.GetBinary("RemoteAddress");
                    var version = sockaddr.Length < 16 ? "IPv4" : "IPv6";
                    var port = (ushort)(sockaddr[3] + 256 * sockaddr[2]);
                    // TODO(jdu) there doesn't appear to be a way to determine if it was a TCP or UDP packet???
                    var truncatedPort = port <= ephemeralPortStart ? $"{port}" : $"{ephemeralPortStart}+";
                    TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", $"connect({version}, ???:{truncatedPort})");
                }
            };
            wfpProvider.AddFilter(blockedPacketFilter);

            this.trace.Enable(wfpProvider);
        }
    }
}