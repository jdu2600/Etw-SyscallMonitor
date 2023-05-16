using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using static Win32.DbgHelp;
using static Win32.Kernel32;

namespace SyscallSummariser.Utilities {
    class SymbolUtils {
        private static readonly SemaphoreSlim _symbolsMutex = new SemaphoreSlim(1);
        private static bool _initialised = false;       
        private static readonly SafeProcessHandle CurrentProcess = new SafeProcessHandle(new IntPtr(-1), false);
        private static SafeProcessHandle hProcess = null;

        internal static void Initialize() {
            _symbolsMutex.Wait();
            {
                if (!_initialised) {
                    SymSetOptions(SymGetOptions() | 0x00800006);  // SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED | SYMOPT_UNDNAME

                    hProcess = OpenProcess(ProcessDesiredAccess.QueryInformation | ProcessDesiredAccess.VirtualMemoryRead, false, Process.GetCurrentProcess().Id);
                    if (!SymInitialize(hProcess, null, true)) {
                        throw new ApplicationException($"SymInitialize(CurrentProcess) failed - error=0x{(uint)Marshal.GetLastWin32Error():x}");
                    }

                    _initialised = true;
                }
            }
            _symbolsMutex.Release();
        }

        internal static void Cleanup() {
            _symbolsMutex.Wait();
            {
                if (_initialised) {
                    if (!SymCleanup(hProcess)) {
                        Log.WarnWrite($"SymCleanup(CurrentProcess) failed - error=0x{(uint)Marshal.GetLastWin32Error():x}");
                    }
                    hProcess = null;
                    _initialised = false;

                }
                _symbolsMutex.Release();
            }
        }

        internal static string GetCommonSymbol(WindowsPath fullModuleName, ulong offset) {
            var imageBase = GetModuleHandle(fullModuleName?.DrivePath ?? "");
            if (null == fullModuleName || UIntPtr.Zero == imageBase)
                return null;

            if (!_initialised)
                Initialize();

            var address = imageBase.ToUInt64() + offset;
            var symbolInfo = new SYMBOL_INFO();
            symbolInfo.SizeOfStruct = 88;
            symbolInfo.MaxNameLen = 128;  // YOLO
            if (!SymFromAddr(hProcess, address, out var displacement, ref symbolInfo)) {
                Log.WarnWrite($"SymFromAddr({fullModuleName.FileName()}) failed - error=0x{Marshal.GetLastWin32Error():x}");
                return null;
            }
            if (symbolInfo.NameLen > 128)
                throw new ApplicationException($"YOLO'd SymFromAddr() buffer too small");

            if (0 != displacement)
                return null; // exact match not found

            var modBaseName = Path.GetFileNameWithoutExtension(fullModuleName.DrivePath);
            var symbol = symbolInfo.Name.Split('<')[0]; // strip decorations            
            return $"{modBaseName}!{symbol}";
        }

        internal static string GetClosestCommonSymbol(ulong address)
        {
            // TODO - cache!

            if (!_initialised)
                Initialize();

            var symbolInfo = new SYMBOL_INFO();
            symbolInfo.SizeOfStruct = 88;
            symbolInfo.MaxNameLen = 128;  // YOLO
            if (!SymFromAddr(hProcess, address, out var displacement, ref symbolInfo))
            {
                return null;
            }
            if (symbolInfo.NameLen > 128)
                throw new ApplicationException($"YOLO'd SymFromAddr() buffer too small");

            return symbolInfo.Name.Split('<')[0]; // strip decorations
        }


    }
}
