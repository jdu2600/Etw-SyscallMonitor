namespace SyscallSummariser {
    using System;
    using System.Collections;
    using System.Diagnostics;
    using System.IO;
    using System.IO.Compression;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;

    using Win32;

    public class WindowsPath {
        public const int MAX_PATH = 32767;  // extended MAX_PATH;

        private static readonly string WINDIR = Environment.GetEnvironmentVariable("WINDIR").ToLower();
        private static readonly string SYSTEMROOT = Environment.GetEnvironmentVariable("SYSTEMROOT").ToLower();
        private static readonly string USERPUBLIC = Environment.GetEnvironmentVariable("PUBLIC").ToLower();
        private static readonly string SYSTEMDRIVE = Environment.GetEnvironmentVariable("SYSTEMDRIVE").ToLower();
        private static readonly string PROGRAMFILES = Environment.GetEnvironmentVariable("PROGRAMFILES").ToLower();
        private static readonly string PROGRAMFILESx86 = Environment.GetEnvironmentVariable("PROGRAMFILES(X86)").ToLower();
        private static readonly string PROGRAMDATA = Environment.GetEnvironmentVariable("PROGRAMDATA").ToLower();
        private static readonly string PROFILE = new Regex(@"^(?<profile>\w:\\[\w\\]+)\\[\w]+").Match(USERPUBLIC).Groups["profile"].Value;
        private static string NETWORKPROFILE = string.Empty;
        private static readonly Regex FilePathRegex = new Regex(@"^(?<drivepath>(\w:)?[^:]+\\(?<filename>[^:\\]+?(\.(?<fileExtension>[^\.\\\:,]+))?))(?<alternateDataStream>\:[^\.\\\:,]+)?$");

        public string Raw { get; set; }
        public string DrivePath { get; set; }
        public string NormalisedPath { get; set; }
        public string NormalisedRoot { get; set; }
        public string FileExtension { get; set; }
        public string AlternateDataStream { get; set; }

        public WindowsPath(string rawPath) {
            Raw = rawPath;
            DrivePath = rawPath;
            NormalisedPath = rawPath;
            NormalisedRoot = rawPath;

            if (string.IsNullOrEmpty(rawPath))
                return;

            // DrivePath - e.g. C:\Windows\system32\ntdll.dll
            DrivePath = rawPath.ToLower();
            DrivePath = Regex.Replace(DrivePath, @"^\\\\?\\", string.Empty);
            // adapted from https://stackoverflow.com/questions/48320430/convert-from-windows-nt-device-path-to-drive-letter-path
            if (DrivePath.StartsWith(@"\device\")) {
                var drive = Array.Find(DriveInfo.GetDrives(), d => DrivePath.StartsWith(d.GetDevicePath(), StringComparison.InvariantCultureIgnoreCase));
                if (drive != null)
                    DrivePath = Regex.Replace(DrivePath, drive.GetDevicePath().Replace(@"\", @"\\"), drive.GetDriveLetter().ToLower(), RegexOptions.IgnoreCase);
            }

            // we need to strip an Alternate Data Stream names from the DrivePath
            // we also extract the (likely) file extension at the same time
            // :TODO: due to NTFS design file extension logic is best effort only...and can produce false positives
            // so... do we only log 'interesting' file types?
            var fileExtensionMatches = FilePathRegex.Match(DrivePath);
            if (fileExtensionMatches.Success) {
                DrivePath = fileExtensionMatches.Groups["drivepath"].Value;
                FileExtension = fileExtensionMatches.Groups["fileExtension"].Value;
                AlternateDataStream = fileExtensionMatches.Groups["alternateDataStream"].Value;
            }

            // NormalisedPath - e.g. %windir%\system32\ntdll.dll
            NormalisedPath = DrivePath;
            // note - the order of replacements is important

            NormalisedPath = Regex.Replace(NormalisedPath, @"\\systemroot", SYSTEMROOT);
            NormalisedPath = NormalisedPath.Replace(WINDIR, "%windir%");

            NormalisedPath = NormalisedPath.Replace(PROGRAMFILESx86, "%programfiles(x86)%");
            NormalisedPath = NormalisedPath.Replace(PROGRAMFILES, "%programfiles%");
            NormalisedPath = NormalisedPath.Replace(PROGRAMDATA, "%programdata%");

            NormalisedPath = NormalisedPath.Replace(USERPUBLIC, "%public%");
            NormalisedPath = NormalisedPath.Replace(PROFILE, "%profile%");
            NormalisedPath = Regex.Replace(NormalisedPath, @"^%profile%\\[^;\\]+", "%userprofile%");

            NormalisedPath = Regex.Replace(NormalisedPath, "^" + SYSTEMDRIVE, "%drive-system%");
            NormalisedPath = Regex.Replace(NormalisedPath, @"^\w:", "%drive%");

            NormalisedPath = Regex.Replace(NormalisedPath, @"^\\fi_unknown", "%fi_unknown%");

            if (NormalisedPath.StartsWith(@"\device\")) {
                // best effort detection of roaming profiles / folder redirection
                var appdata = new Regex(@"^(?<profile>\\device\\mup\\.+)\\appdata\\(local|locallow|roaming)\\").Match(NormalisedPath);
                if (appdata.Success)
                    NETWORKPROFILE = appdata.Groups["profile"].Value;

                if (NETWORKPROFILE != string.Empty)
                    NormalisedPath = NormalisedPath.Replace(NETWORKPROFILE, "%userprofile%");

                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\harddisk\d+", "%drive-physical%");

                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\;csc\\", @"%clientsidecache%\");

                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\[^;\\]+\\pipe\\", @"%pipe%\");
                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\[^;\\]+\\sysvol\\[^;\\]+", "%sysvol%");

                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\;lanmanredirector\\;[a-z]:[0-9a-f]+\\[^;\\]+", "%drive-network%");
                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\dfsclient\\;[a-z]:[0-9a-f]+\\[^;\\]+\\dfs\\", @"%drive-network%\");
                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\dfsclient\\;[a-z]:[0-9a-f]+\\[^;\\]+", "%drive-network%");

                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\[^;\\]+\\dfs\\", @"%drive-network%\");
                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\[^;\\]+", "%drive-network%");

                NormalisedPath = Regex.Replace(NormalisedPath, @"^\\device\\mup\\", @"%mup%\");
            }

            NormalisedPath = Regex.Replace(NormalisedPath, @"^%userprofile%\\appdata\\local\\temp\\[a-z0-9]{8}\.[a-z0-9]{3}\\", @"%userprofile%\\appdata\\local\\temp\\%8.3%");
            NormalisedPath = Regex.Replace(NormalisedPath, @"\\[a-f0-9]{32}}\\", @"\\%32x%\\");

            // NormalisedRoot - e.g. %windir%
            var root = new Regex(@"^(?<root>%[^%]+%)").Match(NormalisedPath);
            if (root.Success)
                NormalisedRoot = root.Groups["root"].Value;
        }

        internal bool IsDevicePath() {
            return NormalisedPath.StartsWith(@"\device\");
        }

        internal bool IsNullOrEmpty() {
            return string.IsNullOrEmpty(Raw);
        }

        public string FileName() {
            return Path.GetFileName(DrivePath);
        }
    }
    public static class DriveInfoExtensions {

        public static string GetDriveLetter(this DriveInfo driveInfo) {
            return driveInfo.Name.Substring(0, 2);
        }

        public static string GetDevicePath(this DriveInfo driveInfo) {
            var devicePathBuilder = new StringBuilder(128);
            return Kernel32.QueryDosDevice(driveInfo.GetDriveLetter(), devicePathBuilder, devicePathBuilder.Capacity + 1) != 0 ?
                devicePathBuilder.ToString() :
                null;
        }
    }

    public static class PathUtils {
        public static void PruneDirectory(string directory, long maximumSize) {
            Trace.Assert(maximumSize > 0, "maximum directory size is not sane");
            Trace.Assert(Directory.Exists(directory), "directory does not exist");

            var files = new Stack(new DirectoryInfo(directory).EnumerateFiles().OrderByDescending(f => f.CreationTime).ToList());

            long directorySize = 0;
            foreach (FileInfo file in files)
                directorySize += file.Length;

            while (directorySize > maximumSize) {
                var oldestFile = (FileInfo)files.Pop();
                directorySize -= oldestFile.Length;
                Log.Write($"[log] deleted oldest file in directory - {oldestFile.FullName}");
                oldestFile.Delete();
            }
        }

        private static readonly object _zipLock = new object();
        public static void CompressAndDeleteFile(string filename) {
            lock (_zipLock) {
                if (File.Exists(filename)) {
                    var zipfile = filename + ".zip";
                    if (File.Exists(zipfile))
                        File.Delete(zipfile);

                    using (ZipArchive archive = ZipFile.Open(zipfile, ZipArchiveMode.Create))
                        archive.CreateEntryFromFile(filename, Path.GetFileName(filename));

                    File.Delete(filename);
                    Log.Write($"archived {filename} to {zipfile}");
                }
            }
        }
    }
}
