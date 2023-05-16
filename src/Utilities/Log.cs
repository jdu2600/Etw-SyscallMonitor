namespace SyscallSummariser
{
    using System;
    using System.Collections.Generic;
    using System.IO;
        using System.Windows.Media;

    class Log
    {
        public const string logfile = "SyscallSummariser.log";
        private const long logfileMaximumSize = 10 * 1024 * 1024;  // 10 MB
        private static readonly object _logLock = new object();
        internal static SortedSet<string> consoleMessages = new SortedSet<string>();

        public static void Write(string message)
        {
            Write(message, Brushes.LightGray);
        }

        public static void Write(string message, Brush colour)
        {
            var logMessage = $"[{DateTime.UtcNow:u}] {message}" + Environment.NewLine;

            if (!consoleMessages.Contains(message) || (colour == Brushes.Red))
            {
                consoleMessages.Add(message);
                Program.mainWindow.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        Program.mainWindow.AddLine(message, colour);
                    }));
            }

            lock (_logLock)
            {
                // TODO(jdu) handle file locked scenario
                File.AppendAllText(logfile, logMessage);
                if (new FileInfo(logfile).Length > logfileMaximumSize)
                    PathUtils.CompressAndDeleteFile(logfile);
            }
        }

        public static void ErrorWrite(string message)
        {
            Write("[!] " + message, Brushes.Red);
        }
        public static void WarnWrite(string message)
        {
            Write("[!] " + message, Brushes.Orange);
        }

        public static void VerboseWrite(string message)
        {
#if DEBUG
            Write("[*] " + message, Brushes.White);
#endif
        }
    }
}
