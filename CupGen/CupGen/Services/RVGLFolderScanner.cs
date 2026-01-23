using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using static CupGen.UI.MainWindow;

namespace CupGen.UI.Services
{
    public static class RvglFolderScanner
    {

        private static readonly HashSet<string> FilteredStockCarFolders =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "misc","q","ufo","trolley","wincar","wincar2","wincar3","wincar4"
}       ;

        private static readonly HashSet<string> FilteredTrackFolders =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "bot_bat","frontend","markar","muse_bat","nhood1_battle","stunts"
        };

        public static IEnumerable<CupGen.UI.MainWindow.CupRef> ScanCups(string rvglRoot)
        {
            var cupsDir = ResolveCupsDir(rvglRoot);
            if (string.IsNullOrEmpty(cupsDir) || !Directory.Exists(cupsDir))
                yield break;

            var cupFiles =
                Directory.EnumerateFiles(cupsDir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.EnumerateFiles(cupsDir, "*.cup", SearchOption.TopDirectoryOnly));

            foreach (var path in cupFiles)
            {
                var id = Path.GetFileNameWithoutExtension(path);
                var display = TryReadCupName(path) ?? id;
                yield return new CupGen.UI.MainWindow.CupRef
                {
                    Id = id,
                    Display = display,
                    FullPath = path
                };
            }
        }

        // Match the same directory that CupGenGlobals builds: <rvglRoot>\packs\rvgl_assets\cups
        private static string ResolveCupsDir(string rvglRoot)
        {
            if (string.IsNullOrWhiteSpace(rvglRoot)) return null;

            // 1) Preferred (exact match with your mod)
            var p1 = Path.Combine(rvglRoot, "packs", "rvgl_assets", "cups");
            if (Directory.Exists(p1)) return p1;

            // 2) If user selected a launcher subfolder accidentally (e.g., packs\rvgl_win64),
            //    try to go up to the base and check again.
            try
            {
                var dir = new DirectoryInfo(rvglRoot);
                if (dir.Parent != null && dir.Parent.Parent != null)
                {
                    var p2 = Path.Combine(dir.Parent.Parent.FullName, "packs", "rvgl_assets", "cups");
                    if (Directory.Exists(p2)) return p2;
                }
            }
            catch { /* ignore */ }

            // 3) Fallback: search shallowly for a packs\rvgl_assets\cups under the chosen root
            try
            {
                var packs = Directory.EnumerateDirectories(rvglRoot, "packs", SearchOption.AllDirectories)
                                     .FirstOrDefault();
                if (packs != null)
                {
                    var p3 = Path.Combine(packs, "rvgl_assets", "cups");
                    if (Directory.Exists(p3)) return p3;
                }
            }
            catch { /* ignore */ }

            return null;
        }

        private static string TryResolvePrettyTrackName(string rvglRoot, string trackDir, string key)
        {
            // 1) INF ‘NAME’ if it isn’t just the folder key
            var fromInf = ReadTrackDisplayName(trackDir);
            if (!string.IsNullOrWhiteSpace(fromInf) &&
                !fromInf.Equals(key, StringComparison.OrdinalIgnoreCase))
                return fromInf;

            // 2) strings files in packs
            var fromStrings = ReadPrettyFromStringsFiles(rvglRoot, key);
            if (!string.IsNullOrWhiteSpace(fromStrings))
                return fromStrings;

            // 3) readme/info simple title
            var fromDocs = ReadPrettyFromDocs(trackDir);
            if (!string.IsNullOrWhiteSpace(fromDocs) &&
                !fromDocs.Equals(key, StringComparison.OrdinalIgnoreCase))
                return fromDocs;

            // 4) user overrides
            var fromOverrides = ReadPrettyFromOverrides(rvglRoot, key);
            if (!string.IsNullOrWhiteSpace(fromOverrides))
                return fromOverrides;

            // 5) fallback
            return key;
        }
        private static string ReadPrettyFromStringsFiles(string rvglRoot, string key)
        {
            try
            {
                var packsDir = Path.Combine(rvglRoot ?? "", "packs");
                if (!Directory.Exists(packsDir)) return null;

                // match:  track.dtown1 = Downtown 1  OR  dtown1: Downtown 1
                var rx = new Regex($@"^\s*(?:level\.|track\.)?{Regex.Escape(key)}\s*(?:=|:)\s*(.+?)\s*$",
                                   RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                foreach (var stringsDir in Directory.EnumerateDirectories(packsDir, "strings", SearchOption.AllDirectories))
                    foreach (var f in Directory.EnumerateFiles(stringsDir, "*.txt", SearchOption.TopDirectoryOnly))
                        foreach (var raw in File.ReadLines(f))
                        {
                            var line = raw;
                            var sc = line.IndexOf(';');
                            if (sc >= 0)
                                line = line.Substring(0, sc); // <-- replace `line[..sc]` with Substring for older C# targets
                            line = line.Trim();
                            if (line.Length == 0) continue;

                            var m = rx.Match(line);
                            if (m.Success)
                            {
                                var v = m.Groups[1].Value.Trim().Trim('"', '\'');
                                if (!string.IsNullOrWhiteSpace(v)) return v;
                            }
                        }
            }
            catch { }
            return null;
        }

        private static string ReadPrettyFromDocs(string trackDir)
        {
            try
            {
                foreach (var name in new[] { "readme.txt", "info.txt" })
                {
                    var p = Path.Combine(trackDir ?? "", name);
                    if (!File.Exists(p)) continue;

                    foreach (var raw in File.ReadLines(p))
                    {
                        var line = raw.Trim();
                        if (line.Length == 0) continue;

                        // crude: use first short, human-ish line
                        if (line.Length <= 64 && !line.Contains('\\') && !line.Contains('/') && !line.Contains(':'))
                            return line.Trim('"', '\'');
                        break;
                    }
                }
            }
            catch { }
            return null;
        }

        private static string ReadPrettyFromOverrides(string rvglRoot, string key)
        {
            try
            {
                var p = Path.Combine(rvglRoot ?? "", "packs", "rvgl_assets", "cups", "cupgen", "track_name_overrides.json");
                if (!File.Exists(p)) return null;
                var json = File.ReadAllText(p);
                var rx = new Regex(@$"""\s*{Regex.Escape(key)}\s*""\s*:\s*""([^""]+)""",
                                   RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                var m = rx.Match(json);
                if (m.Success) return m.Groups[1].Value.Trim();
            }
            catch { }
            return null;
        }


        private static string TryReadCupName(string path)
        {
            // Looks for lines like:
            //   Name = My Cup
            //   Name My Cup
            // Ignores comments after ';'
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw;
                var sc = line.IndexOf(';');
                if (sc >= 0) line = line.Substring(0, sc);
                line = line.Trim();
                if (line.Length == 0) continue;

                if (line.StartsWith("Name", StringComparison.OrdinalIgnoreCase))
                {
                    // Split on '=' first, fallback to the rest of the line
                    var idx = line.IndexOf('=');
                    var val = (idx >= 0) ? line.Substring(idx + 1) : line.Substring(4);
                    var cupName = val.Trim();
                    if (!string.IsNullOrEmpty(cupName))
                        return cupName;
                }
            }
            return null;
        }
        private static int ReadRatingFromParameters(string carDir)
        {
            try
            {
                var p = Path.Combine(carDir ?? "", "parameters.txt");
                if (!File.Exists(p)) return 0; // default Rookie if missing

                foreach (var raw in File.ReadLines(p))
                {
                    var line = raw.Trim();
                    if (line.Length == 0) continue;
                    if (line.StartsWith(";")) continue;  // comments
                    if (line.StartsWith(";)")) continue;  // disabled/commented-out lines

                    // Expect lines like: Rating      2         or Rating   2  ; comment
                    // Split by whitespace; we just need key + first value
                    var parts = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && parts[0].Equals("Rating", StringComparison.OrdinalIgnoreCase))
                    {
                        if (int.TryParse(parts[1], out var r))
                            return Math.Max(0, Math.Min(5, r)); // clamp 0..5
                    }
                }
            }
            catch { /* ignore and fallback */ }

            return 0; // default
        }

        public static IEnumerable<CarItem> ScanCars(string root)
        {
            List<string> carDirs = new List<string>();
            carDirs.Add(Path.Combine(root, "cars"));

            foreach (var d in Directory.EnumerateDirectories(Path.Combine(root, "packs")))
            {
                List<string> blacklist = ["io_skins"];
                var currentFolder = Path.GetFileName(d);

                if (!Directory.Exists(d) || blacklist.Contains(currentFolder))
                {
                    continue;
                }

                var carsPath = Path.Combine(d, "cars");

                if (Directory.Exists(carsPath))
                {
                    carDirs.Add(carsPath);
                }
            }

            foreach (var dir in carDirs)
            {
                if (!Directory.Exists(dir))
                    continue;

                foreach (var d in Directory.EnumerateDirectories(dir))
                {
                    var key = Path.GetFileName(d);               // folder name
                    var cat = Categorize(d);
                    var parentFolder = Directory.GetParent(dir).Name;

                    // Filter: skip certain stock cars (if you maintain this list)
                    if (cat.Equals("Stock", StringComparison.OrdinalIgnoreCase) &&
                        FilteredStockCarFolders.Contains(key))   // HashSet<string> with OrdIgnore comparer recommended
                    {
                        continue;
                    }

                    // Pretty name if parameters.txt has one; fallback to folder key
                    var pretty = ReadPrettyNameFromParameters(d);
                    var disp = !string.IsNullOrWhiteSpace(pretty) ? pretty : key;

                    // Read Rating only
                    int rating = ReadRatingFromParameters(d);

                    yield return new CarItem
                    {
                        Display = disp,
                        FolderKey = key,
                        Category = cat,
                        FullPath = d,
                        Rating = rating,
                        ParentFolder = parentFolder,
                    };
                }
            }
        }

        private static void TryReadClassAndRating(string carDir, out int rating)
        {
            rating = 0;

            try
            {
                var paramPath = Path.Combine(carDir ?? "", "parameters.txt");
                if (!File.Exists(paramPath)) return;

                // Simple line scan; ignores lines starting with ';' or ';)'
                foreach (var raw in File.ReadLines(paramPath))
                {
                    var line = raw.Trim();
                    if (line.Length == 0) continue;
                    if (line.StartsWith(";")) continue;         // comment
                    if (line.StartsWith(";)")) continue;        // disabled/commented

                    // Tokens are like: "Rating     2"
                    // Split on whitespace, honor quotes not needed here.
                    var parts = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;

                    else if (parts[0].Equals("Rating", StringComparison.OrdinalIgnoreCase))
                    {
                        if (int.TryParse(parts[1], out var v)) rating = v;
                    }
                }
            }
            catch
            {
                // keep defaults on parse error
            }
        }
        private static string ReadTrackDisplayName(string trackFolder)
        {
            if (string.IsNullOrWhiteSpace(trackFolder) || !Directory.Exists(trackFolder))
                return null;

            // Common filenames; we’ll try these first.
            string[] candidates =
            {
        Path.Combine(trackFolder, "levelname.inf"),
        Path.Combine(trackFolder, "trackname.inf"),
        Path.Combine(trackFolder, "level.inf"),
    };

            string TryParseName(string infPath)
            {
                // Accept: NAME = "Foo", NAME 'Foo', NAME Foo
                var rx = new Regex(@"\bNAME\b\s*(?:=|\s+)\s*(?:""([^""]+)""|'([^']+)'|(.+))",
                                   RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                foreach (var raw in File.ReadLines(infPath))
                {
                    var line = raw;
                    var sc = line.IndexOf(';');
                    if (sc >= 0) line = line.Substring(0, sc);
                    line = line.Trim();
                    if (line.Length == 0) continue;

                    var m = rx.Match(line);
                    if (!m.Success) continue;

                    var val = m.Groups[1].Success ? m.Groups[1].Value
                            : m.Groups[2].Success ? m.Groups[2].Value
                            : m.Groups[3].Value?.Trim();

                    if (!string.IsNullOrWhiteSpace(val))
                        return val;
                }
                return null;
            }

            // 1) Known names
            foreach (var p in candidates)
                if (File.Exists(p))
                {
                    var name = TryParseName(p);
                    if (!string.IsNullOrWhiteSpace(name)) return name;
                }

            // 2) Fallback: any *.inf that contains NAME
            foreach (var inf in Directory.EnumerateFiles(trackFolder, "*.inf", SearchOption.TopDirectoryOnly))
            {
                var name = TryParseName(inf);
                if (!string.IsNullOrWhiteSpace(name)) return name;
            }

            return null;
        }

        public static IEnumerable<TrackItem> ScanTracks(string rvglRoot)
        {
            if (string.IsNullOrWhiteSpace(rvglRoot) || !Directory.Exists(rvglRoot))
                return Enumerable.Empty<TrackItem>();

            // Each tuple is (relative levels dir, Category label for your UI filter)
            var candidates = new (string relLevels, string category)[]
            {
        (Path.Combine("packs","game_files","levels"),      "Stock"),
        (Path.Combine("packs","rvgl_dcpack","levels"),     "Stock"),  // <— NEW
        (Path.Combine("packs","io_tracks","levels"),       "Main"),
        (Path.Combine("packs","io_tracks_bonus","levels"), "Bonus"),
        ("levels",                                         "Stock"),  // legacy
            };

            var items = new List<TrackItem>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var (rel, cat) in candidates)
            {
                var levelsDir = Path.Combine(rvglRoot, rel);
                if (!Directory.Exists(levelsDir)) continue;

                // Each subdirectory under .../levels is a track id (e.g., "muse2").
                foreach (var trackDir in Directory.EnumerateDirectories(levelsDir))
                {
                    var key = Path.GetFileName(trackDir);
                    if (string.IsNullOrWhiteSpace(key)) continue;
                    if (!seen.Add(key)) continue; // de-dup

                    // Filter these tracks globally (stock/main/bonus)
                    if (FilteredTrackFolders.Contains(key))
                        continue;

                    // Keep underscores in UI; no prettifying for the displayed id
                    var display = TryResolvePrettyTrackName(rvglRoot, trackDir, key);

                    items.Add(new TrackItem
                    {
                        FolderKey = key,   // "felling_yard"
                        Display = display,
                        Category = cat,
                        FullPath = trackDir
                    });
                }
            }

            items.Sort((a, b) => string.Compare(a.FolderKey, b.FolderKey, StringComparison.OrdinalIgnoreCase));
            return items;
        }

        private static IEnumerable<string> FindDirs(string root, IEnumerable<string> rels)
        {
            foreach (var rel in rels)
            {
                var p = Path.Combine(root, rel);
                if (Directory.Exists(p)) yield return p;
            }
        }

        private static string Categorize(string path)
        {
            var p = path.Replace('/', '\\').ToLowerInvariant();
            if (p.Contains("\\packs\\game_files\\")) return "Stock";
            if (p.Contains("\\packs\\rvgl_dcpack\\")) return "Stock";   // <— NEW
            if (p.Contains("io_cars_bonus")) return "Bonus";
            if (p.Contains("io_cars")) return "Main";
            return "Other";
        }

        private static string ReadPrettyNameFromParameters(string dir)
        {
            string p = Path.Combine(dir, "parameters.txt");
            if (!File.Exists(p)) return null;

            foreach (var raw in File.ReadAllLines(p))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith(";")) continue;
                var noComment = line.Split(';')[0].Trim();
                int colon = noComment.IndexOf(':');
                int eq = noComment.IndexOf('=');
                string key, val;
                if (colon > 0) { key = noComment.Substring(0, colon); val = noComment.Substring(colon + 1); }
                else if (eq > 0) { key = noComment.Substring(0, eq); val = noComment.Substring(eq + 1); }
                else
                {
                    var parts = noComment.Split(new[] { ' ', '\t' }, 2, System.StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;
                    key = parts[0]; val = parts[1];
                }
                if (key.Trim().Equals("name", System.StringComparison.OrdinalIgnoreCase))
                    return val.Trim().Trim('"');
            }
            return null;
        }
    }
}
