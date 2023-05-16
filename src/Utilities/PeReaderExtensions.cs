namespace PortableExecutable.Extensions
{
    using System;
    using System.Diagnostics;
    using System.Reflection.Metadata;
    using System.Reflection.PortableExecutable;
    using System.Text;

        public struct IMAGE_EXPORT_DIRECTORY
    {
        public UInt32 Characteristics;
        public UInt32 TimeDateStamp;
        public UInt16 MajorVersion;
        public UInt16 MinorVersion;
        public UInt32 Name;
        public UInt32 Base;
        public UInt32 NumberOfFunctions;
        public UInt32 NumberOfNames;
        public UInt32 AddressOfFunctions;     // RVA from base of image
        public UInt32 AddressOfNames;         // RVA from base of image
        public UInt32 AddressOfNameOrdinals;  // RVA from base of image
    }
    public class ExportFunction
    {
        public ExportFunction(string name, UInt32 address, UInt16 ordinal)
        {
            Name = name;
            Address = address;
            Ordinal = ordinal;
        }

        public string Name { get; }
        public uint Address { get; }
        public ushort Ordinal { get; }

        public override string ToString()
        {
            return !string.IsNullOrEmpty(Name) ? Name : $"ORDINAL({Ordinal})";
        }
    }

    public static class PeReaderExtensions
    {
        public static ExportFunction[] ExportedFunctions(this PEReader pe)
        {
            var exports = new ExportFunction[0];

            var et = pe.PEHeaders.PEHeader.ExportTableDirectory;
            if (et.Size < 40) // sizeof(IMAGE_EXPORT_DIRECTORY)
                return exports;

            try
            {
                var etReader = pe.GetSectionData(et.RelativeVirtualAddress).GetReader(0, et.Size);
                var exportDirectory = new IMAGE_EXPORT_DIRECTORY
                {
                    Characteristics = etReader.ReadUInt32(),
                    TimeDateStamp = etReader.ReadUInt32(),
                    MajorVersion = etReader.ReadUInt16(),
                    MinorVersion = etReader.ReadUInt16(),
                    Name = etReader.ReadUInt32(),
                    Base = etReader.ReadUInt32(),
                    NumberOfFunctions = etReader.ReadUInt32(),
                    NumberOfNames = etReader.ReadUInt32(),
                    AddressOfFunctions = etReader.ReadUInt32(),
                    AddressOfNames = etReader.ReadUInt32(),
                    AddressOfNameOrdinals = etReader.ReadUInt32()
                };

                exports = new ExportFunction[exportDirectory.NumberOfFunctions];
                var exportAddressTableReader = pe.GetSectionData((int)exportDirectory.AddressOfFunctions).GetReader();
                for (var i = 0; i < exportDirectory.NumberOfFunctions; i++)
                    exports[i] = new ExportFunction(null, exportAddressTableReader.ReadUInt32(), (UInt16)(i + exportDirectory.Base));

                if (exportDirectory.NumberOfNames > 0) // add export names (if they exist)
                {
                    var exportNameTableReader = pe.GetSectionData((int)exportDirectory.AddressOfNames).GetReader();
                    var exportIndexReader = pe.GetSectionData((int)exportDirectory.AddressOfNameOrdinals).GetReader();

                    for (uint i = 0; i < exportDirectory.NumberOfNames; i++)
                    {
                        var nameReader = pe.GetSectionData(exportNameTableReader.ReadInt32()).GetReader();
                        var exportName = nameReader.ReadCString(256);
                        var exportIndex = exportIndexReader.ReadUInt16();

                        exports[exportIndex] = new ExportFunction(exportName, exports[exportIndex].Address, exports[exportIndex].Ordinal);
                    }
                }
            }
            catch (BadImageFormatException) { } // :TODO: log failures (if any)

            Debug.Assert(et.Size > 0 == exports.Length > 0);
            return exports;
        }

        public static string ReadCString(this BlobReader reader, int maxLength)
        {
            var sb = new StringBuilder(maxLength);
            if (reader.RemainingBytes > 0)
            {
                var nextChar = Convert.ToChar(reader.ReadByte());
                while (nextChar != '\0' && reader.RemainingBytes > 0 && sb.Length < maxLength)
                {
                    sb.Append(nextChar);
                    nextChar = Convert.ToChar(reader.ReadByte());
                }
            }

            return sb.ToString();
        }
    }
}
