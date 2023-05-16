namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;
    using System;
    using System.Net;

    /// <summary>
    /// profiles Internet Protocol (TCP/IP) activity  using Microsoft-Windows-Kernel-Network events
    /// </summary>
    internal class Microsoft_Windows_Kernel_Network : EtwUserTraceProvider
    {
        public const ushort udpEphemeralPortStart = 48 * 1024;
        public const ushort tcpEphemeralPortStart = 32 * 1024;

        public Microsoft_Windows_Kernel_Network(UserTrace trace) : base(trace) { }

        internal override string ProviderName
        {
            get { return "Microsoft-Windows-Kernel-Network"; }
        }

        internal override void Enable()
        {
            var networkProvider = new Provider(this.ProviderName);

            // TODO(jdu) Log whether address is Broadcast/Multicast/LAN/Internet?

            // IPv4
            var udpSendFilter = new EventFilter(Filter.EventIdIs(42));  // KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol
            udpSendFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var remoteIP = new IPAddress(record.GetUInt32("daddr", 0));
                var remotePortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(remotePortBytes);

                var remotePort = BitConverter.ToUInt16(remotePortBytes, 0);
                var truncatedPort = remotePort <= udpEphemeralPortStart ? $"{remotePort}" : $"{udpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"send(IPv4, udp:{truncatedPort})");
            };
            networkProvider.AddFilter(udpSendFilter);

            var udpReceiveFilter = new EventFilter(Filter.EventIdIs(43));  // KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol
            udpReceiveFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var localPortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(localPortBytes);

                var localPort = BitConverter.ToUInt16(localPortBytes, 0);
                var truncatedPort = localPort <= udpEphemeralPortStart ? $"{localPort}" : $"{udpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"recv(IPv4, udp:{truncatedPort})");
            };
            networkProvider.AddFilter(udpReceiveFilter);

            var tcpConnectionFilter = new EventFilter(Filter.EventIdIs(12));  // KERNEL_NETWORK_TASK_TCPIPConnectionattempted
            tcpConnectionFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var remoteIP = new IPAddress(record.GetUInt32("daddr", 0));
                var remotePortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(remotePortBytes);

                var remotePort = BitConverter.ToUInt16(remotePortBytes, 0);
                var truncatedPort = remotePort <= tcpEphemeralPortStart ? $"{remotePort}" : $"{tcpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"connect(IPv4, tcp:{truncatedPort})");
            };
            networkProvider.AddFilter(tcpConnectionFilter);

            var tcpAcceptFilter = new EventFilter(Filter.EventIdIs(15));  // KERNEL_NETWORK_TASK_TCPIPConnectionaccepted
            tcpAcceptFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var localPortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(localPortBytes);

                var localPort = BitConverter.ToUInt16(localPortBytes, 0);
                var truncatedPort = localPort <= tcpEphemeralPortStart ? $"{localPort}" : $"{tcpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"accept(IPv4, tcp:{truncatedPort})");
            };
            networkProvider.AddFilter(tcpAcceptFilter);

            // IPv6
            var udp6SendFilter = new EventFilter(Filter.EventIdIs(58));  // KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol.58
            udp6SendFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var remoteIP = new IPAddress(record.GetBinary("daddr"));
                var remotePortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(remotePortBytes);

                var remotePort = BitConverter.ToUInt16(remotePortBytes, 0);
                var truncatedPort = remotePort <= udpEphemeralPortStart ? $"{remotePort}" : $"{udpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"send(IPv6, udp:{truncatedPort})");
            };
            networkProvider.AddFilter(udp6SendFilter);

            var udp6ReceiveFilter = new EventFilter(Filter.EventIdIs(59));  // KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol.59
            udp6ReceiveFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var localPortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(localPortBytes);

                var localPort = BitConverter.ToUInt16(localPortBytes, 0);
                var truncatedPort = localPort <= udpEphemeralPortStart ? $"{localPort}" : $"{udpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"recv(IPv6, udp:{truncatedPort})");
            };
            networkProvider.AddFilter(udp6ReceiveFilter);

            var tcp6ConnectionFilter = new EventFilter(Filter.EventIdIs(28));  // KERNEL_NETWORK_TASK_TCPIPConnectionattempted.28
            tcp6ConnectionFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var remoteIP = new IPAddress(record.GetUInt32("daddr", 0));
                var remotePortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(remotePortBytes);

                var remotePort = BitConverter.ToUInt16(remotePortBytes, 0);
                var truncatedPort = remotePort <= tcpEphemeralPortStart ? $"{remotePort}" : $"{tcpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"connect(IPv6, tcp:{truncatedPort})");
            };
            networkProvider.AddFilter(tcp6ConnectionFilter);

            var tcp6AcceptFilter = new EventFilter(Filter.EventIdIs(31));  // KERNEL_NETWORK_TASK_TCPIPConnectionaccepted.31
            tcp6AcceptFilter.OnEvent += (record) =>
            {
                var pid = record.GetUInt32("PID", 0);  // logging process pid != event pid for kernel providers
                var localPortBytes = BitConverter.GetBytes(record.GetUInt16("dport", 0));
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(localPortBytes);

                var localPort = BitConverter.ToUInt16(localPortBytes, 0);
                var truncatedPort = localPort <= tcpEphemeralPortStart ? $"{localPort}" : $"{tcpEphemeralPortStart}+";
                TraitsProfiler.LogFeature(pid, "Syscalls", $"accept(IPv6, tcp:{truncatedPort})");
            };
            networkProvider.AddFilter(tcp6AcceptFilter);

            this.trace.Enable(networkProvider);
        }
    }
}