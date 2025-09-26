using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace CupGen.UI.Services
{
    internal static class RvglSigInterop
    {
        // Native P/Invoke — the DLL must be next to CupGen.exe or in PATH
        [DllImport("RvglSigHelper.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern int ScanRvglOnDisk(string rvglRootOrExe, string outJsonPath);

        // Canonical JSON spot used by the app
        public static string GetAddrsJsonPath(string rvglRoot) =>
            Path.Combine(rvglRoot ?? "", "packs", "rvgl_assets", "cups", "cupgen", "rvgl_addrs.json");

        // Try to find rvgl.exe (same logic as native helper)
        private static string ResolveRvglExeFromRoot(string root)
        {
            if (string.IsNullOrWhiteSpace(root)) return null;
            var cands = new[]
            {
                Path.Combine(root, "rvgl.exe"),
                Path.Combine(root, "packs", "rvgl_win64", "rvgl.exe"),
                Path.Combine(root, "packs", "rvgl_win32", "rvgl.exe"),
                Path.Combine(root, "packs", "game_files", "rvgl.exe"),
            };
            foreach (var c in cands)
                if (File.Exists(c)) return c;
            return null;
        }

        // Compare the exe write timestamp with the JSON's "rvgl_last_write"
        public static bool IsJsonUpToDate(string rvglRoot, string jsonPath)
        {
            try
            {
                if (!File.Exists(jsonPath)) return false;

                var exe = ResolveRvglExeFromRoot(rvglRoot);
                if (exe == null) return false;

                var exeUtc = File.GetLastWriteTimeUtc(exe);
                var json = File.ReadAllText(jsonPath);

                var m = Regex.Match(json, "\"rvgl_last_write\"\\s*:\\s*\"([^\"]+)\"");
                if (!m.Success) return false;

                if (!DateTime.TryParse(m.Groups[1].Value, null, System.Globalization.DateTimeStyles.AdjustToUniversal, out var isoUtc))
                    return false;

                // Consider equal to the nearest second (the native code writes second precision)
                exeUtc = new DateTime(exeUtc.Year, exeUtc.Month, exeUtc.Day, exeUtc.Hour, exeUtc.Minute, exeUtc.Second, DateTimeKind.Utc);
                return exeUtc == isoUtc;
            }
            catch { return false; }
        }

        private static void EnsureJsonDirectory(string jsonPath)
        {
            var dir = Path.GetDirectoryName(jsonPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        }

        /// <summary>
        /// Ensures the addresses JSON exists and is fresh. Returns (ok, message, jsonPath).
        /// </summary>
        public static (bool ok, string message, string jsonPath) EnsureOnDiskSignatures(string rvglRoot)
        {
            if (string.IsNullOrWhiteSpace(rvglRoot) || !Directory.Exists(rvglRoot))
                return (false, "Invalid RVGL root.", null);

            var jsonPath = GetAddrsJsonPath(rvglRoot);
            if (IsJsonUpToDate(rvglRoot, jsonPath))
                return (true, "Signatures are up to date.", jsonPath);

            // Write to a temp path first, then atomically move in place
            var tempPath = jsonPath + ".tmp";
            try
            {
                EnsureJsonDirectory(jsonPath);

                // Pass the **root** to the native scanner; it resolves the exe internally
                var rc = ScanRvglOnDisk(rvglRoot, tempPath);
                if (rc != 0)
                {
                    if (File.Exists(tempPath)) File.Delete(tempPath);
                    return (false, $"Signature scan failed (code {rc}).", jsonPath);
                }

                // Replace existing JSON atomically
                if (File.Exists(jsonPath))
                {
                    var bak = jsonPath + ".bak";
                    try { if (File.Exists(bak)) File.Delete(bak); } catch { }
                    File.Replace(tempPath, jsonPath, bak, ignoreMetadataErrors: true);
                    try { File.Delete(bak); } catch { }
                }
                else
                {
                    File.Move(tempPath, jsonPath);
                }

                return (true, "Signature scan complete.", jsonPath);
            }
            catch (Exception ex)
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                return (false, "Signature scan error: " + ex.Message, jsonPath);
            }
        }
    }
}
