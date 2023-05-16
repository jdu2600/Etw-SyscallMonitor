namespace SyscallSummariser.ETW {
    using Microsoft.O365.Security.ETW;
    using System;
    using System.IO;
    using System.Linq;

    /// <summary>
    /// profiles use of file extensions in Win32 file APIs using Microsoft-Windows-Kernel-File events
    /// </summary>
    internal class Microsoft_Windows_Kernel_File : EtwUserTraceProvider {
        public Microsoft_Windows_Kernel_File(UserTrace trace) : base(trace) { }

        internal override string ProviderName {
            get { return "Microsoft-Windows-Kernel-File"; }
        }

        internal override void Enable() {
            var fileProvider = new Provider(this.ProviderName)
            {
                TraceFlags = TraceFlags.IncludeStackTrace
            };
            fileProvider.Any = 0x10 |  // KERNEL_FILE_KEYWORD_FILENAME
                               0x20 |  // KERNEL_FILE_KEYWORD_FILEIO
                               0x400 | // KERNEL_FILE_KEYWORD_DELETE_PATH
                               0x800 | // KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH
                               0x1000; // KERNEL_FILE_KEYWORD_CREATE_NEW_FILE

            // NameCreate || CreateNewFile
            var nameCreateFilter = new EventFilter(Filter.EventIdIs(10).Or(Filter.EventIdIs(30)));
            nameCreateFilter.OnEvent += (record) => {
                CreateFileEventHandler(record, "NtCreateFile");
            };
            fileProvider.AddFilter(nameCreateFilter);

            // SetInformation
            var setInformationFileFilter = new EventFilter(Filter.EventIdIs(17));
            setInformationFileFilter.OnEvent += (record) => {
                var infoClass = record.GetUInt32("InfoClass", UInt32.MaxValue);
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtSetInformationFile({FileInformationClass(infoClass)})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(setInformationFileFilter);

            // QueryInformation
            /* This event is way too verbose to usefully log */
            //var queryInformationFileFilter = new EventFilter(Filter.EventIdIs(22));
            //queryInformationFileFilter.OnEvent += (record) =>
            //{
            //    var infoClass = record.GetUInt32("InfoClass", UInt32.MaxValue);
            //    ProcessProfile.LogFeatureIfInterestingProcess(record.ProcessId, "Syscalls", $"File-QueryInformation({FileInformationClass(infoClass)})");
            //};
            //fileProvider.AddFilter(queryInformationFileFilter);

            // Rename, Rename29
            var renameFileFilter = new EventFilter(Filter.EventIdIs(19).Or(Filter.EventIdIs(29)));
            renameFileFilter.OnEvent += (record) =>
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtSetInformationFile(Rename)", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(renameFileFilter);

            // DirNotify
            var dirNotifyFilter = new EventFilter(Filter.EventIdIs(25));
            dirNotifyFilter.OnEvent += (record) => {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtNotifyChangeDirectoryFile()", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(dirNotifyFilter);

            // FSCTL
            var fsctlFilter = new EventFilter(Filter.EventIdIs(23));
            fsctlFilter.OnEvent += (record) => {
                var infoClass = (FSCTL)record.GetUInt32("InfoClass");
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"NtFsControlFile({infoClass})", record.GetStackTrace());
                if (value is null || value.Contains("kernelbase!ReplaceFile"))
                    return;
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(fsctlFilter);

            // DeletePath
            var deletePathFilter = new EventFilter(Filter.EventIdIs(26));
            deletePathFilter.OnEvent += (record) => {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtSetInformationFile(DeletePath)", record.GetStackTrace());
                if (value is null || value.Contains("kernelbase!ReplaceFile"))
                    return;
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(deletePathFilter);

            // RenamePath
            var renamePathFilter = new EventFilter(Filter.EventIdIs(27));
            renamePathFilter.OnEvent += (record) => {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtSetInformationFile(RenamePath)", record.GetStackTrace());
                if (value is null || value.Contains("kernelbase!ReplaceFile"))
                    return;
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(renamePathFilter);

            // SetLinkPath
            var setLinkPathFilter = new EventFilter(Filter.EventIdIs(28));
            setLinkPathFilter.OnEvent += (record) => {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "File-SetLinkPath", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(setLinkPathFilter);

            // SetSecurity
            var setSecurityFilter = new EventFilter(Filter.EventIdIs(31));
            setSecurityFilter.OnEvent += (record) => {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtSetSecurityObject(File)", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(setSecurityFilter);

            // QuerySecurity
            var querySecurityFilter = new EventFilter(Filter.EventIdIs(32));
            querySecurityFilter.OnEvent += (record) => {
                var callStack = record.GetStackTrace();
                if (MemoryMap.IsMonitored(record.ProcessId))
                {
                    var (callingModule, calledApi, callStackSummary) = MemoryMap.FinalUserModule(record.ProcessId, callStack);
                    if (callingModule == "ntdll" && calledApi == "ntdll!LdrpInitializeProcess" && callStackSummary.Contains("kernelbase!ConsoleAllocate"))
                        return; // ignore console side-effects
                }

                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "NtQuerySecurityObject(File)", callStack);
                if (value is null || 
                    value.Contains("->kernelbase!CreateFile") ||
                    value.Contains("->kernelbase!GetFileVersionInfo") ||
                    value.Contains("->kernelbase!CreateProcessAsUser")
                    )
                    return;
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(querySecurityFilter);

            // SetEA
            var setEAFilter = new EventFilter(Filter.EventIdIs(33));
            setEAFilter.OnEvent += (record) => {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, "File-SetEA", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            };
            fileProvider.AddFilter(setEAFilter);

            // QueryEA
            //var queryEAFilter = new EventFilter(Filter.EventIdIs(34));
            //queryEAFilter.OnEvent += (record) => {
            //    var value = TraitsProfiler.EnrichFeature(record.ProcessId, "File-QueryEA", record.GetStackTrace());
            //    TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            //};
            //fileProvider.AddFilter(queryEAFilter);

            this.trace.Enable(fileProvider);
        }


        internal static readonly string[] interestingFileExtensions = { "sys", "dll", "exe" };
        // Monitor more types?
        // "com", "bat", "scr", "cpl", "xll", "msi", "msp", "vb", "vbs", "vbe", "js", "jse", "ws", "wsf", "ps1", "inf", "jar", "hta"

        private static void CreateFileEventHandler(IEventRecord record, string method) {
            var type = "File";
            var path = new WindowsPath(record.GetUnicodeString("FileName", string.Empty));
            
            if (!interestingFileExtensions.Contains(path.FileExtension))
                return;

            if (string.IsNullOrEmpty(path.NormalisedRoot))
                Log.WarnWrite($"NormalisedRoot={path.NormalisedRoot} Raw={path.Raw}");

            string attributes = string.Empty;
            try {
                attributes = string.Concat(File.GetAttributes(path.DrivePath).ToString().Where(c => !Char.IsWhiteSpace(c))).Replace(",", "|");

                if (attributes.Contains("Directory")) {
                    type = "Directory";
                    attributes = attributes.Replace("Directory", "").Replace("||", "|");
                    path.FileExtension = string.Empty;  // eliminate directory false positives
                }
            } catch {
                attributes = "Temp"; // file is deleted???
                return; // don't risk bad data
            }

            var target = $"{path.FileExtension}";
            if (!string.IsNullOrEmpty(path.AlternateDataStream))
                target += $", :{path.AlternateDataStream}";
            if (!string.IsNullOrEmpty(attributes))
                target += $", {attributes}";

            if (type == "File")
            {
                var value = TraitsProfiler.EnrichFeature(record.ProcessId, $"{method}({target})", record.GetStackTrace());
                TraitsProfiler.LogFeature(record.ProcessId, "Syscalls", value);
            }
        }

        private static string FileInformationClass(UInt32 infoClass) {
            if (infoClass < _FileInformationClass.Length)
                return _FileInformationClass[infoClass];

            return $"{infoClass}";
        }

        // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ne-wdm-_file_information_class
        private static readonly string[] _FileInformationClass =
        {
            "FileDirectoryInformation",
            "FileFullDirectoryInformation",
            "FileBothDirectoryInformation",
            "FileBasicInformation",
            "FileStandardInformation",
            "FileInternalInformation",
            "FileEaInformation",
            "FileAccessInformation",
            "FileNameInformation",
            "FileRenameInformation",
            "FileLinkInformation",
            "FileNamesInformation",
            "FileDispositionInformation",
            "FilePositionInformation",
            "FileFullEaInformation",
            "FileModeInformation",
            "FileAlignmentInformation",
            "FileAllInformation",
            "FileAllocationInformation",
            "FileEndOfFileInformation",
            "FileAlternateNameInformation",
            "FileStreamInformation",
            "FilePipeInformation",
            "FilePipeLocalInformation",
            "FilePipeRemoteInformation",
            "FileMailslotQueryInformation",
            "FileMailslotSetInformation",
            "FileCompressionInformation",
            "FileObjectIdInformation",
            "FileCompletionInformation",
            "FileMoveClusterInformation",
            "FileQuotaInformation",
            "FileReparsePointInformation",
            "FileNetworkOpenInformation",
            "FileAttributeTagInformation",
            "FileTrackingInformation",
            "FileIdBothDirectoryInformation",
            "FileIdFullDirectoryInformation",
            "FileValidDataLengthInformation",
            "FileShortNameInformation",
            "FileIoCompletionNotificationInformation",
            "FileIoStatusBlockRangeInformation",
            "FileIoPriorityHintInformation",
            "FileSfioReserveInformation",
            "FileSfioVolumeInformation",
            "FileHardLinkInformation",
            "FileProcessIdsUsingFileInformation",
            "FileNormalizedNameInformation",
            "FileNetworkPhysicalNameInformation",
            "FileIdGlobalTxDirectoryInformation",
            "FileIsRemoteDeviceInformation",
            "FileUnusedInformation",
            "FileNumaNodeInformation",
            "FileStandardLinkInformation",
            "FileRemoteProtocolInformation",
            "FileRenameInformationBypassAccessCheck",
            "FileLinkInformationBypassAccessCheck",
            "FileVolumeNameInformation",
            "FileIdInformation",
            "FileIdExtdDirectoryInformation",
            "FileReplaceCompletionInformation",
            "FileHardLinkFullIdInformation",
            "FileIdExtdBothDirectoryInformation",
            "FileDispositionInformationEx",
            "FileRenameInformationEx",
            "FileRenameInformationExBypassAccessCheck",
            "FileDesiredStorageClassInformation",
            "FileStatInformation",
            "FileMemoryPartitionInformation",
            "FileStatLxInformation",
            "FileCaseSensitiveInformation",
            "FileLinkInformationEx",
            "FileLinkInformationExBypassAccessCheck",
            "FileStorageReserveIdInformation",
            "FileCaseSensitiveInformationForceAccessCheck"
        };

        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc02779-9d95-43f8-bba4-8d4ce4961458
        // TODO(jdu) plus many more in winioctl.h...
        enum FSCTL : uint
        {
            CREATE_OR_GET_OBJECT_ID = 0x900C0,
            DELETE_OBJECT_ID = 0x900A0,
            DELETE_REPARSE_POINT = 0x900AC,
            DUPLICATE_EXTENTS_TO_FILE = 0x98344,
            DUPLICATE_EXTENTS_TO_FILE_EX = 0x983E8,
            FILESYSTEM_GET_STATISTICS = 0x90060,
            FILE_LEVEL_TRIM = 0x98208,
            FIND_FILES_BY_SID = 0x9008F,
            GET_COMPRESSION = 0x9003C,
            GET_INTEGRITY_INFORMATION = 0x9027C,
            GET_NTFS_VOLUME_DATA = 0x90064,
            GET_REFS_VOLUME_DATA = 0x902D8,
            GET_OBJECT_ID = 0x9009C,
            GET_REPARSE_POINT = 0x900A8,
            GET_RETRIEVAL_POINTER_COUNT = 0x9042B,
            GET_RETRIEVAL_POINTERS = 0x90073,
            GET_RETRIEVAL_POINTERS_AND_REFCOUNT = 0x903D3,
            IS_PATHNAME_VALID = 0x9002C,
            LMR_SET_LINK_TRACKING_INFORMATION = 0x1400EC,
            MARK_HANDLE = 0x900FC,
            OFFLOAD_READ = 0x94264,
            OFFLOAD_WRITE = 0x98268,
            PIPE_PEEK = 0x11400C,
            PIPE_TRANSCEIVE = 0x11C017,
            PIPE_WAIT = 0x110018,
            QUERY_ALLOCATED_RANGES = 0x940CF,
            QUERY_FAT_BPB = 0x90058,
            QUERY_FILE_REGIONS = 0x90284,
            QUERY_ON_DISK_VOLUME_INFO = 0x9013C,
            QUERY_SPARING_INFO = 0x90138,
            READ_USN_JOURNAL = 0x900BB,
            READ_FILE_USN_DATA = 0x900EB,
            RECALL_FILE = 0x90117,
            REFS_STREAM_SNAPSHOT_MANAGEMENT = 0x90440,
            REQUEST_OPLOCK = 0x90240,
            SET_COMPRESSION = 0x9C040,
            SET_DEFECT_MANAGEMENT = 0x98134,
            SET_ENCRYPTION = 0x900D7,
            SET_INTEGRITY_INFORMATION = 0x9C280,
            SET_INTEGRITY_INFORMATION_EX = 0x90380,
            SET_OBJECT_ID = 0x90098,
            SET_OBJECT_ID_EXTENDED = 0x900BC,
            SET_REPARSE_POINT = 0x900A4,
            SET_SPARSE = 0x900C4,
            SET_ZERO_DATA = 0x980C8,
            SET_ZERO_ON_DEALLOCATION = 0x90194,
            SIS_COPYFILE = 0x90100,
            WRITE_USN_CLOSE_RECORD = 0x900EF
        }
    }
}