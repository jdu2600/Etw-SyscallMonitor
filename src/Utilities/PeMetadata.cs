using PeNet;
using PortableExecutable.Extensions;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection.PortableExecutable;

namespace SyscallSummariser.Utilities
{
    class PeMetadata
    {
        internal static ConcurrentDictionary<string, string> originalFilenames = new ConcurrentDictionary<string, string>();
        internal static ConcurrentDictionary<string, string> signers = new ConcurrentDictionary<string, string>();
        private static readonly Dictionary<string, Dictionary<UInt64, string>> _PeExportCache = new Dictionary<string, Dictionary<UInt64, string>>();
        private static readonly Dictionary<string, ImmutableArray<SectionHeader>> _PeSectionCache = new Dictionary<string, ImmutableArray<SectionHeader>>();

        internal static string GetOriginalFilename(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            if(!originalFilenames.ContainsKey(path))
                ParsePe(path);
            
            return originalFilenames[path];
        }

        internal static string GetSigner(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            if (!signers.ContainsKey(path))
                ParsePe(path);

            return signers[path];
        }

        private static void ParsePe(string path)
        {
            string originalFilename = "<none>";
            string signer = "<unsigned>";
            try
            {
                var peFile = new PeFile(path);
                if (peFile.Resources != null)
                {
                    var vsVersionInfo = peFile.Resources.VsVersionInfo.StringFileInfo.StringTable[0];
                    originalFilename = vsVersionInfo.OriginalFilename;

                    // TODO(jdu) handle catalog signatures etc
                    // For now, just approximate with CompanyName...
                    signer = vsVersionInfo.CompanyName;
                    // var certificate = peFile.Authenticode.SigningCertificate;
                    //if (certificate != null)
                    //{
                    //    signer = certificate.Subject;
                    //}
                }

            }
            catch (AccessViolationException) { } // bug in PeNet?
            catch (FileNotFoundException) { }  // continue
            catch (ArgumentException) { }  // continue
            catch (NullReferenceException) { } // continue
            catch (Exception e) {
                Log.WarnWrite($"PeFile({path}) failed - {e.Message}");
            }

            originalFilenames.TryAdd(path, originalFilename);
            signers.TryAdd(path, signer);
        }


        public static Dictionary<UInt64, string> ExportedFunctions(string path)
        {
            var exportedFunctions = new Dictionary<UInt64, string>();
            var name = Path.GetFileNameWithoutExtension(path);

            // handle file not exists
            try
            {
                using (var peFile = new PEReader(File.Open(new WindowsPath(path).DrivePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                    foreach (var export in peFile.ExportedFunctions())
                        if (export.Address != 0) // deprecated/unused export
                                                 // just keep the first export name if multiples exist
                            if (!exportedFunctions.ContainsKey(export.Address))
                                exportedFunctions.Add(export.Address, $"{name}!{export}");
            }
            catch (Exception e)
            {
                Log.WarnWrite($"Exception parsing {path} - {e.Message}");
            }
            return exportedFunctions;
        }

        public static ImmutableArray<SectionHeader> Sections(string path)
        {
            var sections = new ImmutableArray<SectionHeader>();

            // handle file not exists
            try
            {
                using (var peFile = new PEReader(File.Open(new WindowsPath(path).DrivePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                {
                    sections = peFile.PEHeaders.SectionHeaders;
                }
            }
            catch (Exception e)
            {
                Log.WarnWrite($"Exception parsing {path} - {e.Message}");
            }
            return sections;
        }

        internal static string GetSectionName(string imagePath, ulong offset)
        {
            var shortName = Path.GetFileNameWithoutExtension(imagePath);
            if (!_PeSectionCache.ContainsKey(imagePath))
            {
                _PeSectionCache.Add(imagePath, Sections(imagePath));
            }
            _PeSectionCache.TryGetValue(imagePath, out var sections);
            foreach (SectionHeader section in sections)
                if ((int)offset >= section.VirtualAddress && (int)offset < section.VirtualAddress + section.VirtualSize)
                    return $"{shortName}/{section.Name}";
            return shortName;
        }

        internal static string GetExportName(string imagePath, ulong offset)
        {
            if (!_PeExportCache.ContainsKey(imagePath))
            {
                _PeExportCache.Add(imagePath, ExportedFunctions(imagePath));
            }
            _PeExportCache.TryGetValue(imagePath, out var exports);
            if (exports.ContainsKey(offset))
                return exports[offset];

            return Path.GetFileNameWithoutExtension(imagePath);
        }
    }
}
