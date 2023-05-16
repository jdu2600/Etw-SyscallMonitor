namespace SyscallSummariser.ETW
{
    using Microsoft.O365.Security.ETW;

    internal abstract class EtwUserTraceProvider
    {
        internal UserTrace trace = null;

        internal EtwUserTraceProvider(UserTrace trace)
        {
            this.trace = trace;
        }

        /* derived clasess will need to implement a constructor */
        // public Microsoft_Windows_Something(UserTrace trace) : base(trace) { }

        internal virtual string ProviderName { get; set; }
        //get { return "Microsoft-Windows-Something"; }

        internal abstract void Enable();
        //{
        //    var somethingProvider = new Provider(providerName);
        //    somethingProvider.Any = 0x12345;
        //    var eventFilter = new EventFilter(Filter.EventIdIs(1337));
        //    eventFilter.OnEvent += (record) =>
        //    {
        //        Log.Write("Hello World");
        //    };
        //    somethingProvider.AddFilter(eventFilter);
        //    this.trace.Enable(somethingProvider);
        //}
    }
}
