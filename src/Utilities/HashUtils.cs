using System.Security.Cryptography;
using System.Text;

namespace SyscallSummariser
{
    class HashUtils
    {
        public static string SHA1(string data)
        {
            return SHA1(Encoding.UTF8.GetBytes(data));
        }

        public static string SHA1(byte[] data)
        {
            return SHA1(data, 0, data.Length);
        }

        public static string SHA1(byte[] data, int offset, int count)
        {
            var strHash = string.Empty;
            try
            {
                StringBuilder sbHash = new StringBuilder();
                using (SHA1 hash = System.Security.Cryptography.SHA1.Create())
                {
                    byte[] hash_bytes = hash.ComputeHash(data, offset, count);
                    for (int i = 0; i < hash_bytes.Length; i++)
                    {
                        sbHash.AppendFormat("{0:x2}", hash_bytes[i]);
                    }
                }
                strHash = sbHash.ToString();
            }
            catch { }

            return strHash;
        }

        public static string SHA256(string data)
        {
            return SHA256(Encoding.UTF8.GetBytes(data));
        }

        public static string SHA256(byte[] data)
        {
            return SHA256(data, 0, data.Length);
        }

        public static string SHA256(byte[] data, int offset, int count)
        {
            var strHash = string.Empty;
            try
            {
                StringBuilder sbHash = new StringBuilder();
                using (SHA256 hash = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] hash_bytes = hash.ComputeHash(data, offset, count);
                    for (int i = 0; i < hash_bytes.Length; i++)
                    {
                        sbHash.AppendFormat("{0:x2}", hash_bytes[i]);
                    }
                }
                strHash = sbHash.ToString();
            }
            catch { }

            return strHash;
        }
    }
}
