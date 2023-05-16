using Microsoft.O365.Security.ETW;
using SyscallSummariser.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Win32.Kernel32;
using static Win32.Psapi;

namespace SyscallSummariser
{
    public class MemoryMap
    {
        // :TODO: - add a kernel module memory map...

        private static readonly Dictionary<uint, string> _MonitoredProcesses = new Dictionary<uint, string>();
        private static readonly Dictionary<UInt64, LoadedImage> _GlobalModuleMap = new Dictionary<UInt64, LoadedImage>();
        private static readonly Dictionary<uint, Dictionary<UInt64, LoadedImage>> _LocalModuleMap = new Dictionary<uint, Dictionary<UInt64, LoadedImage>>();
        private static readonly Dictionary<uint, Dictionary<UInt64, MemoryRegion>> _MemoryRegionCache = new Dictionary<uint, Dictionary<UInt64, MemoryRegion>>();

        public const string Unbacked = "Unbacked";
        public const string Unknown = "Unknown";
        public const string Shellcode = "Shellcode";
        public const string JIT = "JIT";
        public const string NULL = "NULL";
        public static List<string> apiModules = new List<string> { "ntdll", "kernelbase", "kernel32", "win32u", "user32", "wow64", "wow64cpu" };

        internal static bool IsInSystemImageRange(UInt64 address)
        {
            return ((address >= 0x7FF800000000) && (address < 0x7FFFFFFF0000)) || ((address >= 0x50000000) && (address < 0x78000000));
        }

        public static bool IsMonitored(uint pid)
        {
            return _MonitoredProcesses.ContainsKey(pid);
        }

        public static string GetProcessName(uint pid)
        {
            if (!_MonitoredProcesses.TryGetValue(pid, out var process))
            {
                return $"pid:{pid}";
            }

            return process;
        }

        private static string Normalise(string imageName)
        {
            imageName = imageName.ToLower().Replace(".dll", "");
            if (imageName.EndsWith(".exe"))
                imageName = "exe";

            return imageName;
        }

        public static (string, string, string) FinalUserModule(uint pid, List<UIntPtr> callStack)
        {

            var wow64 = false;
            var callingModule = "";
            var calledApi = "";
            var callStackSummary = "";
            var lastSymbol = "";
            var enrichedStack = new List<string>();
            foreach (var returnAddress in callStack.Select(x => x.ToUInt64()))
            {
                if (returnAddress >= 0x800000000000)
                {
                    continue; // ignore kernel addresses (for now)
                }

                var moduleName = GetOwner(pid, returnAddress);
                var apiModule = apiModules.Contains(moduleName.Split('|')[0]);
                wow64 = wow64 || (moduleName == "wow64") || (apiModule && returnAddress < 0x78000000);
                if (apiModule && returnAddress > 0x78000000)
                {
                    // enrich well-known modules with symbol information
                    moduleName = $"{moduleName}!{SymbolUtils.GetClosestCommonSymbol(returnAddress)}";
                }

                if (string.IsNullOrEmpty(callingModule) &&
                        (!apiModule || moduleName.EndsWith("Callback")))
                {
                    // final user module in the call stack found
                    callingModule = moduleName;
                    calledApi = lastSymbol;
                }

                if (!callStackSummary.EndsWith($"{moduleName};"))
                    callStackSummary += $"{moduleName};";

                lastSymbol = moduleName;
                enrichedStack.Add($"{returnAddress} {moduleName}");
            }

            if (string.IsNullOrEmpty(callingModule))
            {
                // ntdll!LdrpInitializeNode;ntdll!LdrpInitializeGraphRecurse;ntdll!LdrpPrepareModuleForExecution;ntdll!LdrpLoadDllInternal;ntdll!LdrpLoadDll;ntdll!LdrLoadDll;ntdll!LdrpInitializeProcess;ntdll!LdrpInitialize;ntdll!LdrInitializeThunk;
                // ntdll!NtMapViewOfSection;ntdll!LdrpMinimalMapModule;ntdll!LdrpMapDllWithSectionHandle;ntdll!LdrpMapDllNtFileName;ntdll!LdrpMapDllSearchPath;ntdll!LdrpProcessWork;ntdll!LdrpWorkCallback;ntdll!TppWorkpExecuteCallback;ntdll!TppWorkerThread;kernel32!BaseThreadInitThunk;ntdll!RtlUserThreadStart;
                // ntdll!NtMapViewOfSection;wow64!;wow64cpu!;wow64!;ntdll!LdrpInitializeProcess;ntdll!LdrpInitialize;ntdll!LdrInitializeThunk;ntdll!;
                if (callStackSummary.EndsWith("LdrpInitializeProcess;ntdll!LdrpInitialize;ntdll!LdrInitializeThunk;") ||
                    callStackSummary.EndsWith("ntdll!LdrpProcessWork;ntdll!LdrpWorkCallback;ntdll!TppWorkpExecuteCallback;ntdll!TppWorkerThread;kernel32!BaseThreadInitThunk;ntdll!RtlUserThreadStart;") ||
                    (wow64 && callStackSummary.Contains("ntdll!LdrpInitializeProcess;ntdll!LdrpInitialize;ntdll!LdrInitializeThunk;")))
                {
                    callingModule = "ntdll";
                    calledApi = "ntdll!LdrpInitializeProcess";
                }
                else if (callStackSummary.Contains("ntdll!LdrpInitialize;ntdll!LdrInitializeThunk;"))
                {
                    callingModule = "ntdll";
                    calledApi = "ntdll!LdrpInitialize"; // TODO is this a special case to handle or not?
                }
            }
            else if (calledApi == "ntdll!LdrpProcessWork")
            {
                callingModule = "ntdll";
                calledApi = "ntdll!LdrpInitializeProcess";
            }
            // ntdll!NtMapViewOfSection;ntdll!LdrpMinimalMapModule;ntdll!LdrpMapDllWithSectionHandle;ntdll!LdrpLoadKnownDll;ntdll!LdrpFindOrPrepareLoadingModule;ntdll!LdrpLoadDllInternal;ntdll!LdrpLoadForwardedDll;ntdll!LdrpGetDelayloadExportDll;ntdll!LdrpHandleProtectedDelayload;ntdll!LdrResolveDelayLoadedAPI;setupapi;exe;kernel32!BaseThreadInitThunk;ntdll!RtlUserThreadStart;
            else if (calledApi == "ntdll!LdrResolveDelayLoadedAPI")
            {
                callingModule = "ntdll";
            }

            return (callingModule, calledApi, callStackSummary);
        }

        internal static string GetOwner(uint pid, UInt64 address)
        {
            if (0 == address)
                return MemoryMap.NULL;

            if (!IsMonitored(pid) || !_MemoryRegionCache.TryGetValue(pid, out var regions))
                return Unknown;

            // find closest containing region
            // WARNING - logic does not account for overlapping calls
            foreach (var region in regions.Values)
            {
                if (address >= region.BaseAddress && (address < region.BaseAddress + region.RegionSize))  // is contained in region
                {
                    var actingRegion = region.ActingModule.Split('|')[0];
                    if (actingRegion == Unbacked || actingRegion == JIT)
                    {
                        if (region.Name == Unbacked || region.Name == Unknown || region.Name == JIT)
                            return Shellcode;
                        else
                            return region.Name;
                    }
                    else if (region.Name == Unbacked || region.Name == Unknown || region.Name == JIT)
                    {
                        return $"{JIT}|{actingRegion}";
                    }
                    else
                    {
                        return region.Name; 
                    }
                }
            }

            // modules loaded locally
            if (_LocalModuleMap.TryGetValue(pid, out var modules))
            {
                foreach (var module in modules.Values)
                {
                    if (address >= module.BaseAddress && address < module.BaseAddress + module.RegionSize)
                        return Normalise(module.ImageName);
                }
            }

            // modules loaded at shared system address
            foreach (var module in _GlobalModuleMap.Values)
            {
                if (address >= module.BaseAddress && address < module.BaseAddress + module.RegionSize)
                    return Normalise(module.ImageName);
            }

            // last chance
            var hProcess = OpenProcess(ProcessDesiredAccess.QueryInformation, false, (int)pid);
            if (!hProcess.IsInvalid)
            {
                var regionInfo = new MEMORY_BASIC_INFORMATION();
                var filename = new StringBuilder(WindowsPath.MAX_PATH);
                if (0 != VirtualQueryEx(hProcess, new UIntPtr(address), ref regionInfo, (uint)Marshal.SizeOf(regionInfo)))
                {
                    if (regionInfo.Type == MemoryType.MEM_IMAGE &&
                        (0 != GetMappedFileName(hProcess, regionInfo.BaseAddress, filename, (uint)filename.Capacity)))
                    {
                        return Normalise(Path.GetFileName(filename.ToString()));
                    }
                    else if (regionInfo.State == MemoryState.MEM_COMMIT)
                    {
                        return Unbacked;
                    }
                }
            }

            return Unknown;
        }

        public static string GetModulePath(uint pid, UInt64 address)
        {
            if (!_LocalModuleMap.TryGetValue(pid, out var modules))
                return Unknown;

            foreach (var module in modules.Values)
            {
                if (address >= module.BaseAddress && address < module.BaseAddress + module.RegionSize)
                    return module.RawImagePath;
            }

            foreach (var module in _GlobalModuleMap.Values)
            {
                if (address >= module.BaseAddress && address < module.BaseAddress + module.RegionSize)
                    return module.RawImagePath;
            }

            return Unbacked;
        }

        public static UInt64 GetImageBase(uint pid, UInt64 address)
        {
            if (!_LocalModuleMap.TryGetValue(pid, out var modules))
                return 0;
            foreach (var module in modules.Values)
            {
                if (address >= module.BaseAddress && address < module.BaseAddress + module.RegionSize)
                    return module.BaseAddress;
            }

            foreach (var module in _GlobalModuleMap.Values)
            {
                if (address >= module.BaseAddress && address < module.BaseAddress + module.RegionSize)
                    return module.BaseAddress;
            }

            return 0;
        }


        internal static void Remove(uint pid)
        {
            _MonitoredProcesses.Remove(pid);
            _MemoryRegionCache.Remove(pid);
            _LocalModuleMap.Remove(pid);
        }

        internal static void Add(uint pid, string path)
        {

            var name = Path.GetFileName(path);
            _MonitoredProcesses.Remove(pid);
            _MonitoredProcesses.Add(pid, name);
            _MemoryRegionCache.Remove(pid);
            _MemoryRegionCache.Add(pid, new Dictionary<ulong, MemoryRegion>());
            _LocalModuleMap.Remove(pid);
            _LocalModuleMap.Add(pid, new Dictionary<ulong, LoadedImage>());
        }

        internal static void Add(uint pid, LoadedImage image)
        {
            if (IsInSystemImageRange(image.BaseAddress))
            {
                // Ranges in the MiImageBitMap(s) can be freed and later reallocated to new dlls.
                // We need to remove any stale entries from our map.
                for (var va = image.BaseAddress; va < image.BaseAddress + image.RegionSize; va += (64 * 1024))
                {
                    _GlobalModuleMap.Remove(va);
                }
                _GlobalModuleMap.Add(image.BaseAddress, image);
            }
            else
            {
                _LocalModuleMap.TryGetValue(pid, out var modules);
                if (modules != null)
                {
                    for (var va = image.BaseAddress; va < image.BaseAddress + image.RegionSize; va += (64 * 1024))
                    {
                        modules.Remove(va);
                    }
                    modules.Add(image.BaseAddress, image);
                }
            }
        }

        internal static void Remove(uint pid, ulong imageBase)
        {
            _LocalModuleMap.TryGetValue(pid, out var modules);
            if (modules != null)
            {
                modules.Remove(imageBase);
            }
        }

        internal static void Add(uint pid, ulong imageBase, MemoryRegion region)
        {
            _MemoryRegionCache.TryGetValue(pid, out var modules);
            if (modules != null)
            {
                modules.Remove(imageBase);
                modules.Add(imageBase, region);
            }
        }
    }

    internal class MemoryRegion
    {
        public uint Pid;
        public MemoryProtection Protection;
        public UInt64 BaseAddress;
        public UInt64 RegionSize;
        public string Name;
        public string ActingModule;

        public MemoryRegion(IEventRecord record, bool newAllocation, bool remote)
        {
            var callingPid = record.GetUInt32("CallingProcessId");
            var targetPid = remote ? record.GetUInt32("TargetProcessId") : callingPid;
            if (!MemoryMap.IsMonitored(targetPid) || !MemoryMap.IsMonitored(callingPid))
                return;

            Pid = targetPid;
            Protection = (MemoryProtection)record.GetUInt32("ProtectionMask");
            BaseAddress = record.GetUInt64("BaseAddress");
            RegionSize = record.GetUInt64("RegionSize");
            (ActingModule, _, _) = MemoryMap.FinalUserModule(callingPid, record.GetStackTrace());
            Name = newAllocation ? MemoryMap.Unbacked : MemoryMap.GetOwner(targetPid, BaseAddress).Split('|')[0];

            if (Pid != callingPid)
                ActingModule += $"|{MemoryMap.GetProcessName(callingPid)}";
        }

        public MemoryRegion(IEventRecord record, bool remote)
        {
            // NtMapViewOfSection
            var callingPid = record.GetUInt32("CallingProcessId");
            var targetPid = remote ? record.GetUInt32("TargetProcessId") : callingPid;
            if (!MemoryMap.IsMonitored(callingPid) || !MemoryMap.IsMonitored(targetPid))
                return;

            Pid = targetPid;
            Protection = (MemoryProtection)record.GetUInt32("ProtectionMask");
            BaseAddress = record.GetUInt64("BaseAddress");
            RegionSize = record.GetUInt64("ViewSize");
            (ActingModule, _, _) = MemoryMap.FinalUserModule(callingPid, record.GetStackTrace());

            if (Pid != callingPid)
                ActingModule += $"({MemoryMap.GetProcessName(callingPid)})";
        }

        internal static bool IsReadExecutable(MemoryProtection protection)
        {
            return 0 != (protection & (MemoryProtection.EXECUTE | MemoryProtection.EXECUTE_READ | MemoryProtection.EXECUTE_WRITECOPY));
        }
        internal static bool IsExecutable(MemoryProtection protection)
        {
            return IsReadExecutable(protection) || (MemoryProtection.EXECUTE_READWRITE == protection);
        }
        internal static bool IsWritable(MemoryProtection protection)
        {
            return 0 != (protection & (MemoryProtection.READWRITE | MemoryProtection.EXECUTE_READWRITE));
        }
    }

    public class LoadedImage
    {
        public UInt64 BaseAddress;
        public UInt64 RegionSize;
        public string RawImagePath;
        public string ImageName;

        public LoadedImage(IEventRecord record)
        {
            BaseAddress = record.GetUInt64("ImageBase");
            RegionSize = record.GetUInt64("ImageSize");
            RawImagePath = record.GetUnicodeString("ImageName");
            ImageName = Path.GetFileName(RawImagePath);
        }
    }
}
