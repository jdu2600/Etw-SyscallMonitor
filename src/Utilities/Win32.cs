namespace Win32
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    internal class Kernel32
    {
        [DllImport("kernel32.dll")]
        internal static extern uint GetProcessId(SafeProcessHandle handle);

        // https://www.pinvoke.net/default.aspx/kernel32.virtualqueryex
        [DllImport("kernel32.dll")]
        internal static extern UInt64 VirtualQueryEx(
            SafeProcessHandle hProcess,
            UIntPtr lpAddress,
            ref MEMORY_BASIC_INFORMATION lpBuffer,
            uint dwLength);

        [Flags]
        internal enum MemoryState : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_FREE = 0x10000,
        }

        [Flags]
        internal enum MemoryType : uint
        {
            Unknown = 0,
            MEM_PRIVATE = 0x20000,
            MEM_MAPPED = 0x40000,
            MEM_IMAGE = 0x1000000,
        }

        internal struct MEMORY_BASIC_INFORMATION
        {
            public UIntPtr BaseAddress;
            public UIntPtr AllocationBase;
            public MemoryProtection AllocationProtect;
            public UIntPtr RegionSize;
            public MemoryState State;
            public MemoryProtection Protect;
            public MemoryType Type;
        }

        [Flags]
        internal enum ProcessDesiredAccess : uint
        {
            Terminate = 0x1,
            CreateThread = 0x2,
            VirtualMemoryOperation = 0x8,
            VirtualMemoryRead = 0x10,
            VirtualMemoryWrite = 0x20,
            DuplicateHandle = 0x40,
            CreateProcess = 0x80,
            SetQuota = 0x100,
            SetInformation = 0x200,
            QueryInformation = 0x400,
            QueryLimitedInformation = 0x1000,
            SetLimitedInformation = 0x2000,
            Synchronize = 0x100000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            ProcessDesiredAccess dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [Flags]
        internal enum MemoryProtection : uint
        {
            Unknown = 0,
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x1,
            READONLY = 0x2,
            READWRITE = 0x4,
            WRITECOPY = 0x8,
            TARGETS_INVALID = 0x40000000,
            GUARD = 0x100,
            NOCACHE = 0x200,
            WRITECOMBINE = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(
            SafeProcessHandle hProcess,
            UIntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out UInt64 lpNumberOfBytesRead);

        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern uint QueryDosDevice(
            [In] string lpDeviceName,
            [Out] StringBuilder lpTargetPath,
            [In] int ucchMax);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process(
            [In] SafeProcessHandle processHandle,
            [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern UIntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

    }

    internal class Psapi
    {
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern UInt32 GetMappedFileName(
           SafeProcessHandle hProcess,
           UIntPtr lpv,
           StringBuilder lpFileName,
           UInt32 nSize);

        [StructLayout(LayoutKind.Sequential)]
        internal struct ModuleInformation
        {
            public UIntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public UIntPtr EntryPoint;
        }

        internal enum ModuleFilter
        {
            ListModulesDefault = 0x0,
            ListModules32Bit = 0x01,
            ListModules64Bit = 0x02,
            ListModulesAll = 0x03,
        }

        [DllImport("psapi.dll")]
        internal static extern bool EnumProcessModulesEx(SafeProcessHandle hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] UIntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll")]
        internal static extern uint GetModuleFileNameEx(SafeProcessHandle hProcess, UIntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] uint nSize);

        [DllImport("psapi.dll")]
        internal static extern uint GetModuleBaseName(SafeProcessHandle hProcess, UIntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern bool GetModuleInformation(SafeProcessHandle hProcess, UIntPtr hModule, out ModuleInformation lpmodinfo, uint cb);

        [DllImport("psapi.dll", SetLastError = true)]
        internal static extern uint GetProcessImageFileName([In] SafeProcessHandle hProcess, [Out] StringBuilder lpImageFileName, [In] [MarshalAs(UnmanagedType.U4)] int nSize);
    }

    internal class Advapi
    {
        internal static uint STANDARD_RIGHTS_READ = 0x00020000;
        internal static uint TOKEN_DUPLICATE = 0x0002;
        internal static uint TOKEN_QUERY = 0x0008;
        internal static uint TOKEN_QUERY_SOURCE = 0x0010;
        internal static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        internal static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(
            SafeProcessHandle ProcessHandle,
            UInt32 DesiredAccess,
            out SafeAccessTokenHandle TokenHandle);


        // SECURITY_IMPERSONATION_LEVEL
        internal static int SecurityImpersonation = 2;

        [DllImport("advapi32.dll")]
        internal static extern bool DuplicateToken(
            SafeAccessTokenHandle ExistingTokenHandle,
            int ImpersonationLevel,
            out SafeAccessTokenHandle DuplicateTokenHandle
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            SafeAccessTokenHandle hToken
        );

        internal enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal unsafe struct TOKEN_MANDATORY_LABEL  {
            public IntPtr Sid;
            public UInt32 Attributes;
            private fixed UInt64 Reserved[2];
        }

        internal struct TOKEN_ELEVATION
        {
            public UInt32 TokenIsElevated;
        }

        internal struct TOKEN_ELEVATION_TYPE
        {
            public UInt32 TokenElevationType;
        }


        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetTokenInformation(SafeHandle TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref TOKEN_ELEVATION TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetTokenInformation(SafeHandle TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref TOKEN_ELEVATION_TYPE TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetTokenInformation(SafeHandle TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref TOKEN_MANDATORY_LABEL TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        internal enum SC_SERVICE_TAG_QUERY_TYPE
        {
            ServiceNameFromTagInformation = 1
        }

        internal struct SC_SERVICE_TAG_QUERY
        {
            public UInt32 ProcessId;
            public UInt32 ServiceTag;
            public UInt32 Unknown;
            public IntPtr Buffer;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern int I_QueryTagInformation(IntPtr Unknown, SC_SERVICE_TAG_QUERY_TYPE QueryType, ref SC_SERVICE_TAG_QUERY Query);

    }

    internal class Ntdll
    {
        internal static uint NT_SUCCESS = 0;

        internal static uint SE_SECURITY_PRIVILEGE = 8;
        internal static uint SE_DEBUG_PRIVILEGE = 20;

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern UInt32 RtlAdjustPrivilege(
            uint dwPrivilege,
            bool bEnablePrivilege,
            bool bIsThreadPrivilege,
            out UInt32 dwPreviousState);

        internal enum PROCESSINFOCLASS : int
        {
            ProcessBasicInformation = 0,
            ProcessWow64Information = 26,
            ProcessEnableReadWriteVmLogging = 87
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public UIntPtr ExitStatus;
            public UIntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public UIntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct PROCESS_READWRITEVM_LOGGING_INFORMATION
        {
            public byte Flags;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int NtQueryInformationProcess(
            SafeProcessHandle hProcess,
            PROCESSINFOCLASS pic,
            ref PROCESS_BASIC_INFORMATION pbi,
            int cb,
            out int pSize);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int NtQueryInformationProcess(
            SafeProcessHandle hProcess,
            PROCESSINFOCLASS pic,
            ref UIntPtr wow64Information,
            int cb,
            out int pSize);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int NtQueryInformationProcess(
            SafeProcessHandle hProcess,
            PROCESSINFOCLASS pic,
            ref PROCESS_READWRITEVM_LOGGING_INFORMATION prwmli,
            int cb,
            out int pSize);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int NtSetInformationProcess(
            SafeProcessHandle hProcess,
            PROCESSINFOCLASS pic,
            ref PROCESS_READWRITEVM_LOGGING_INFORMATION prwmli,
            int cb);

        public enum SYSTEM_INFORMATION_CLASS
        {
            SystemProcessInformation = 0x5,
            SystemModuleInformation = 11,
            SystemFullProcessInformation = 0x94
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SYSTEM_MODULE_INFORMATION
        {
            public UInt32 ModulesCount;
            public SYSTEM_MODULE[] Modules;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SYSTEM_MODULE
        {
            public UIntPtr Reserved1; // BAADF00D
            public UIntPtr Reserved2; // 0
            public IntPtr ImageBase;
            public UInt32 ImageSize;
            public UInt32 Flags;
            public UInt16 LoadOrderIndex;
            public UInt16 InitOrderIndex;
            public UInt16 LoadCount;
            public UInt16 ModuleNameOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public Char[] _ImageName;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SYSTEM_PROCESS_INFORMATION
        {
            internal uint NextEntryOffset;
            internal uint NumberOfThreads;
            private fixed byte Reserved1[48];
            internal UNICODE_STRING ImageName;
            internal int BasePriority;
            internal IntPtr UniqueProcessId;
            private readonly UIntPtr Reserved2;
            internal uint HandleCount;
            internal uint SessionId;
            private readonly UIntPtr Reserved3;
            internal UIntPtr PeakVirtualSize;  // SIZE_T
            internal UIntPtr VirtualSize;
            private readonly uint Reserved4;
            internal UIntPtr PeakWorkingSetSize;  // SIZE_T
            internal UIntPtr WorkingSetSize;  // SIZE_T
            private readonly UIntPtr Reserved5;
            internal UIntPtr QuotaPagedPoolUsage;  // SIZE_T
            private readonly UIntPtr Reserved6;
            internal UIntPtr QuotaNonPagedPoolUsage;  // SIZE_T
            internal UIntPtr PagefileUsage;  // SIZE_T
            internal UIntPtr PeakPagefileUsage;  // SIZE_T
            internal UIntPtr PrivatePageCount;  // SIZE_T
            private fixed long Reserved7[6];
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SYSTEM_THREAD_INFORMATION
        {
            private fixed long Reserved1[3];
            private readonly uint Reserved2;
            internal IntPtr StartAddress;
            internal CLIENT_ID ClientId;
            internal int Priority;
            internal int BasePriority;
            private readonly uint Reserved3;
            internal uint ThreadState;
            internal uint WaitReason;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct SYSTEM_EXTENDED_THREAD_INFORMATION
        {
            internal SYSTEM_THREAD_INFORMATION ThreadInfo;
            internal IntPtr StackBase;
            internal IntPtr StackLimit;
            internal IntPtr Win32StartAddress;
            internal IntPtr TebBase;
            private fixed long Reserved[3];
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CLIENT_ID
        {
            internal IntPtr UniqueProcess;
            internal IntPtr UniqueThread;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            out uint ReturnLength);

        internal enum OBJECT_INFORMATION_CLASS : int
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
            ObjectAllTypesInformation = 3,
            ObjectHandleInformation = 4
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct OBJECT_TYPES_INFORMATION
        {
            [FieldOffset(0)] public UInt32 NumberOfTypes;
            [FieldOffset(0)] private IntPtr _alignment;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct GENERIC_MAPPING
        {
            public UInt32 GenericRead;
            public UInt32 GenericWrite;
            public UInt32 GenericExecute;
            public UInt32 GenericAll;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING TypeName;
            public UInt32 TotalNumberOfObjects;
            public UInt32 TotalNumberOfHandles;
            public UInt32 TotalPagedPoolUsage;
            public UInt32 TotalNonPagedPoolUsage;
            public UInt32 TotalNamePoolUsage;
            public UInt32 TotalHandleTableUsage;
            public UInt32 HighWaterNumberOfObjects;
            public UInt32 HighWaterNumberOfHandles;
            public UInt32 HighWaterPagedPoolUsage;
            public UInt32 HighWaterNonPagedPoolUsage;
            public UInt32 HighWaterNamePoolUsage;
            public UInt32 HighWaterHandleTableUsage;
            public UInt32 InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public UInt32 ValidAccessMask;
            public Byte SecurityRequired; // BOOLEAN
            public Byte MaintainHandleCount; // BOOLEAN
            public Byte TypeIndex;
            public Byte ReservedByte;
            public UInt32 PoolType;
            public UInt32 DefaultPagedPoolCharge;
            public UInt32 DefaultNonPagedPoolCharge;
        }

        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(
            IntPtr objectHandle,
            OBJECT_INFORMATION_CLASS informationClass,
            IntPtr informationPtr,
            uint informationLength,
            ref uint returnLength);
    }

    internal class DbgHelp
    {
        [DllImport("Dbghelp.dll")]
        public static extern int SymSetOptions(
            int SymOptions);

        [DllImport("Dbghelp.dll")]
        public static extern int SymGetOptions();

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymInitialize(
            SafeHandle hProcess,
            StringBuilder UserSearchPath,
            bool fInvadeProcess);

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymCleanup(
            SafeHandle hProcess);

        [DllImport("dbghelp.dll", SetLastError = true)]
        public static extern UIntPtr SymLoadModule64(
            SafeHandle hProcess,
            IntPtr hFile,
            string ImageName,
            string ModuleName,
            UIntPtr BaseOfDll,
            uint SizeOfDll);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct SYMBOL_INFO
        {
            public UInt32 SizeOfStruct;
            public UInt32 TypeIndex;        // Type Index of symbol
            public UInt64 Reserved;
            public UInt64 Reserved2;
            public UInt32 Index;
            public UInt32 Size;
            public UInt64 ModBase;          // Base Address of module comtaining this symbol
            public UInt32 Flags;
            public UInt64 Value;            // Value of symbol, ValuePresent should be 1
            public UInt64 Address;          // Address of symbol including base address of module
            public UInt32 Register;         // register holding value or pointer to value
            public UInt32 Scope;            // scope of the symbol
            public UInt32 Tag;              // pdb classification
            public UInt32 NameLen;          // Actual length of name
            public UInt32 MaxNameLen;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string Name;             // Name of symbol
        }

        [DllImport("Dbghelp.dll", SetLastError = true)]
        public static extern bool SymFromAddr(
            SafeProcessHandle hProcess,
            UInt64 Address,
            out UInt64 Displacement,
            ref SYMBOL_INFO Symbol);
    }
}
