namespace SyscallSummariser.ETW {
    using Microsoft.O365.Security.ETW;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using System.Threading;

    internal class EtwUserTrace {
        internal UserTrace trace = null;
        private static string _sessionName;
        private static readonly List<EtwUserTraceProvider> providers = new List<EtwUserTraceProvider>();  // enabled providers

        internal void Enable() {
            _sessionName = $"{typeof(Program).Namespace}-User-Trace";
            this.trace = new UserTrace(_sessionName);

            var properties = new EventTraceProperties
            {
                // we need a buffer large enough for 1 second of events
                // note - maximum single event size is 64KB
                BufferSize = 512 // KB
                
                // https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
                // by default, ETW uses one buffer per processor - so events can arrive out of order
                // for low volumes (< 1000 events per second) you can specify the use of a common
                // buffer with EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
                // note - krabs enables this common buffer by default.
                // for high volume tracing this should be overridden to avoid dropped events
                //   LogFileMode = (uint)LogFileModeFlags.FLAG_EVENT_TRACE_REAL_TIME_MODE
            };
            this.trace.SetTraceProperties(properties);

            var providerTypes = Assembly.GetExecutingAssembly().GetTypes().Where(x => x.BaseType == typeof(EtwUserTraceProvider));
            foreach (var providerType in providerTypes) {
                var provider = (EtwUserTraceProvider)Activator.CreateInstance(providerType, new Object[] { this.trace });
                providers.Add(provider);
                provider.Enable();
            }

            var Lost_Event = new Provider(new Guid("{6a399ae0-4bc6-4de9-870b-3657f8947e7e}"));
            Lost_Event.OnEvent += (record) =>
            {
                Log.WarnWrite("Lost_Event received");
            };

            Lost_Event.OnError += (record) =>
            {
                Log.WarnWrite($"Lost_Event received");
            };
            trace.Enable(Lost_Event);
        }

        internal void BlockingStart() {

            foreach (var provider in providers)
            {
                if (provider.trace != null && provider.trace != this.trace)
                {
                    ThreadPool.QueueUserWorkItem(_this => {
                        var Lost_Event = new Provider(new Guid("{6a399ae0-4bc6-4de9-870b-3657f8947e7e}"));
                        Lost_Event.OnEvent += (record) =>
                        {
                            Log.WarnWrite($"[{provider.ProviderName}] Lost_Event received");
                        };

                        Lost_Event.OnError += (record) =>
                        {
                            Log.WarnWrite($"[{provider.ProviderName}] Lost_Event received");
                        };
                        ((UserTrace)_this).Enable(Lost_Event);
                        ((UserTrace)_this).Start();
                    }, provider.trace);
                }
            }

            try {
                Log.Write($"Starting UserTrace({_sessionName})...");
                this.trace.Start();
                Log.Write($"UserTrace.Start({_sessionName}) completed");
            } catch (NoTraceSessionsRemaining) {
                Log.ErrorWrite($"{_sessionName}.Start() failed - no trace sessions remaining");
            } catch (OpenTraceFailure) {
                Log.ErrorWrite($"{_sessionName}.Start() failed - trace failed to start");
            } catch (TraceAlreadyRegistered) {
                Log.ErrorWrite($"{_sessionName}.Start() failed - the ETW trace object is already registered");
            } catch (InvalidParameter) {
                Log.ErrorWrite($"{_sessionName}.Start() failed - an invalid parameter was provided");
            } catch (SEHException) {
                Log.ErrorWrite($"{_sessionName}.Start() trace threw SEH exception");
            }
        }

        internal void Stop() {
            foreach (var provider in providers)
            {
                if (provider.trace != null && provider.trace != this.trace)
                {
                    Log.ErrorWrite($"{provider.ProviderName} != this.trace");
                    provider.trace.Stop();
                }
            }

            if (this.trace != null) {
                Log.Write($"Stopping UserTrace({_sessionName})...");
                try {
                    this.trace.Stop();
                } catch (Exception e) {
                    Log.ErrorWrite($"UserTrace.Stop() threw {e.Message}");
                }
                this.trace = null;
            }
        }
    }
}