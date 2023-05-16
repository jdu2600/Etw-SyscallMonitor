using Microsoft.O365.Security.ETW;
using Newtonsoft.Json;
using SyscallSummariser.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace SyscallSummariser
{
    /* 
     *  for each process/thread, store a set of observed values for a number of interesting features
     *  use creation traits hash as key
     *  features include - modules, syscalls, Network endpoints
     *
     *  { traitshash : { feature : set(observed values) } 
     *  e.g. { "calc.exe_9baac013..." : { "Syscalls": ["API-LoadLibrary(%windir%, ntdll.dll) [ntdll.dll, Microsoft Corporation, 9AA4E92DA41B87A1CD9829A16F7EAE5A80D739B3]"] } }
     */
    public class TraitsProfiler
    {
        internal static bool useCommonSymbols = true;

        internal static Dictionary<string, Dictionary<string, SortedSet<string>>> summaries = new Dictionary<string, Dictionary<string, SortedSet<string>>>();

        internal static SortedSet<string> summariesWithNewBehaviours = new SortedSet<string>();

        private const uint MAX_VALUES = 500;

        private static Timer outputTimer = null;

        private const string outputFilename = "SyscallSummary.json";
        private static readonly object fileLock = new object();
        private static int outputJsonSize = 0;
        private const int maximumJsonSize = 64 * 1024 * 1024;  // 64 MB

        private const int outputStartupDelaySeconds = 120;
        private const int outputIntervalSeconds = 120;          // 2 minutes

        public const string summariesOutputDirectory = "SyscallSummaries";

        public TraitsProfiler()
        {
            Log.Write($"Console logfile                   : {Log.logfile}");
            Log.Write($"Whole system json output filename : {outputFilename}");
            Log.Write($"Per-process json output directory : {summariesOutputDirectory}");

            // restore state from previous run
            FromJson(outputFilename);
            UpdateTreeview();

            // periodically output the observed profile to a json file
            outputTimer = new Timer(delegate (object state)
            {
                OutputJsonFiles();
            }, null, outputStartupDelaySeconds * 1000, outputIntervalSeconds * 1000);
        }

        private void UpdateTreeview()
        {
            Program.mainWindow.AddTreeView(summaries);
        }

        public void Stop()
        {
            if (outputTimer != null)
            {
                outputTimer.Dispose();
                outputTimer = null;
            }
        }

        public static void OutputJsonFiles()
        {
            string json;
            lock (fileLock)
            {
                lock (summaries)
                {
                    // all profiles together
                    json = ToJson();
                    // if output file is too large, then reset our data collection
                    if (json.Length > maximumJsonSize)
                    {
                        Log.Write("Output file size limit reached - clearing state");
                        Clear();
                        Program.verbose = false;

                        File.WriteAllText(outputFilename, json);
                        PathUtils.CompressAndDeleteFile(outputFilename);

                        json = ToJson();
                        outputJsonSize = 0;
                    }

                    // individual profiles
                    foreach (var key in summaries.Keys)
                        SaveProfileToDisk(key, summaries[key]);
                }

                if (!Program.verbose && outputJsonSize != 0 && json.Length == outputJsonSize)
                {
                    Log.VerboseWrite("Startup collection complete - switching to verbose output");
                    Program.verbose = true;
                }

                if (json.Length != outputJsonSize)
                {
                    outputJsonSize = json.Length;
                    File.WriteAllText(outputFilename, json);
                }
            }
        }

        public static string ToJson()
        {
            return JsonConvert.SerializeObject(summaries, Formatting.Indented);
        }

        public static void FromJson(string jsonFile)
        {
            try
            {
                if (File.Exists(jsonFile))
                {
                    var json = File.ReadAllText(jsonFile);
                    summaries = JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, SortedSet<string>>>>(json);
                    if (summaries != null)
                    {
                        // we have (some) existing system state - it's okay to enable verbose output
                        Program.verbose = true;
                    }
                    else
                    {
                        summaries = new Dictionary<string, Dictionary<string, SortedSet<string>>>();
                    }
                }
            }
            catch { }
        }

        public static void Clear()
        {
            // clear all of the observed features
            lock (summaries)
                summaries.Clear();
        }

        internal static string EnrichFeature(uint pid, string originalValue, List<UIntPtr> callStack)
        {
            if (callStack.Count == 0)
                return originalValue;

            if (!MemoryMap.IsMonitored(pid))
                return null;

            var (callingModule, calledApi, _) = MemoryMap.FinalUserModule(pid, callStack);
            if (string.IsNullOrEmpty(callingModule) || callingModule == MemoryMap.Unknown || string.IsNullOrEmpty(calledApi))
            {
                return null;
            }

            var enrichedValue = $"{callingModule}->{calledApi}->{originalValue}";
            if (callingModule == MemoryMap.Shellcode)
            {
                Log.ErrorWrite($"{ProcessCreationTraitsMap.GetProcessName(pid)} {enrichedValue}");
            }
            else if(callingModule.Contains("TppTimerpExecuteCallback"))
            {
                Log.WarnWrite($"{ProcessCreationTraitsMap.GetProcessName(pid)} {enrichedValue}");
            }

            return enrichedValue;
        }

        internal static void LogFeature(uint pid, string feature, string value)
        {
            if (Program.stopping || string.IsNullOrEmpty(feature) || string.IsNullOrEmpty(value))
                return;

            var key = ProcessCreationTraitsMap.GetCreationTraitsHash(pid);
            if (key == null)
                return;

            lock (summaries)
            {
                if (!summaries.ContainsKey(key))
                    summaries.Add(key, new Dictionary<string, SortedSet<string>>());
            }

            var processFeatures = summaries[key];
            lock (processFeatures)
            {
                if (!processFeatures.ContainsKey(feature))
                    processFeatures.Add(feature, new SortedSet<string>());
            }

            var values = processFeatures[feature];
            lock (values)
            {
                if (!values.Contains(value))
                {
                    if (values.Count == MAX_VALUES)
                    {
                        values.Add("<OUTPUT_TRUNCATED>");
                        Log.WarnWrite($"MAX_VALUES exceeded in {ProcessCreationTraitsMap.GetProcessName(pid)} :: {feature}");
                    }

                    if (values.Count < MAX_VALUES)
                    {
                        values.Add(value);

                        // update TTPHash
                        if (processFeatures.ContainsKey("Syscalls"))
                        {
                            var TTPjson = JsonConvert.SerializeObject(processFeatures["Syscalls"], Formatting.Indented);

                            if (!processFeatures.ContainsKey("TTPHash"))
                                processFeatures.Add("TTPHash", new SortedSet<string>());
                            else
                                processFeatures["TTPHash"].Clear();
                            // flush old hash for now
                            // TODO(jdu) add (timestamp, hash) tuples

                            processFeatures["TTPHash"].Add(HashUtils.SHA1(TTPjson));
                        }

                        // monitored process with a new behaviour detected
                        if (MemoryMap.IsMonitored(pid) && !summariesWithNewBehaviours.Contains(key))
                        {
                            summariesWithNewBehaviours.Add(key);
                            Program.mainWindow.AddTreeView(summaries);
                        }
                    }
                }
            }
        }

        private static void SaveProfileToDisk(string key, Dictionary<string, SortedSet<string>> profile)
        {
            Debug.Assert(key != null);
            if (!summariesWithNewBehaviours.Contains(key))
                return;

            var json = JsonConvert.SerializeObject(profile, Formatting.Indented);

            try
            {
                // output the json to profilesOutputDirectory\\key.json
                Directory.CreateDirectory(summariesOutputDirectory);
                var filepath = Path.Combine(summariesOutputDirectory, key.Replace(':', '_') + ".json");
                File.WriteAllText(filepath, json);
            }
            catch (Exception e) when (e is PathTooLongException || e is DirectoryNotFoundException)
            {
                Log.WarnWrite(e.Message);
            }
        }

        // TODO(jdu) - improve on this name-only matching
        internal static readonly string[] commonMicrosoftModules = { "bcrypt", "cfgmgr32", "combase", "dbgcore", "dui70", "duser", "mpr", "winbrand", "wkscli" };
        internal static readonly string[] commonMicrosoftCallers = { "kernelbase!GetProcAddressForCaller", "user32!CreateWindowExW" };

        internal static bool IsMicrosoftSigner(string signer)
        {
            return signer == "Microsoft Corporation";
        }

        public static void LogModule(uint pid, WindowsPath moduleName, IEventRecord record)
        {
            if (moduleName.IsNullOrEmpty())
                return;

            // We normalise LoadLibrary events to just the module's signer
            // We could consider more verbose logging for specific modules here.
            var signer = PeMetadata.GetSigner(moduleName.DrivePath);
            var value = EnrichFeature(pid, $"NtMapViewOfSection({signer})", record.GetStackTrace());
            LogFeature(record.ProcessId, "Syscalls", value);
        }
    }
}
