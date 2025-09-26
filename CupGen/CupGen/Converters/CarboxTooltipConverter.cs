using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace CupGen.UI.Converters
{
    public sealed class CarboxTooltipMultiConverter : IMultiValueConverter
    {
        // Cache sheets so we don’t re-read bitmaps repeatedly
        private static readonly Dictionary<string, BitmapImage> _sheetCache =
            new(StringComparer.OrdinalIgnoreCase);

        // Folder-key map (case-insensitive). Include common long/short variants.
        private static readonly Dictionary<string, (int sheet, int cell)> _stockByFolder =
            new(StringComparer.OrdinalIgnoreCase)
            {
                // carbox1.bmp
                ["rcbandit"] = (1, 0),
                ["dustmite"] = (1, 1),
                ["phatslug"] = (1, 2),
                ["colmoss"] = (1, 3),
                ["harvester"] = (1, 4),   // fixed
                ["drgrudge"] = (1, 5),
                ["volkent"] = (1, 6),
                ["sprinter"] = (1, 7),
                ["rcsan"] = (1, 8),

                // carbox2.bmp
                ["candypeb"] = (2, 0),
                ["candypebbles"] = (2, 0),
                ["genghis"] = (2, 1),
                ["aqua"] = (2, 2),
                ["aquasonic"] = (2, 2),
                ["mouse"] = (2, 3),
                ["evil"] = (2, 4),
                ["evilweasel"] = (2, 4),
                ["pangatc"] = (2, 5),
                ["r6t"] = (2, 6),
                ["r6turbo"] = (2, 6),
                ["ny54"] = (2, 7),
                ["bertha"] = (2, 8),

                // carbox3.bmp
                ["pest"] = (3, 0),
                ["pestctrl"] = (3, 0),
                ["adeon"] = (3, 1),
                ["polepoz"] = (3, 2),
                ["zipper"] = (3, 3),
                ["rotor"] = (3, 4),
                ["cougar"] = (3, 5),
                ["humma"] = (3, 6),
                ["toyeca"] = (3, 7),
                ["amw"] = (3, 8),

                // carbox4.bmp
                ["rcphink"] = (4, 0),
                ["la54"] = (4, 1),
                ["matraxl"] = (4, 2),
                ["shocker"] = (4, 3),
                ["splat"] = (4, 4),
                ["groov"] = (4, 5),
                ["groovster"] = (4, 5),
                ["jg7"] = (4, 6),
                ["rg1"] = (4, 7),
                ["rvloco"] = (4, 8),

                // carbox5.bmp
                ["snw35"] = (5, 0),
                ["purpxl"] = (5, 1),
                ["fulonx"] = (5, 2),
                ["bigvolt"] = (5, 3),
                ["bossvolt"] = (5, 4),
                ["panga"] = (5, 5),
                // ["mystery"] = (5,6) // intentionally skipped
            };

        // Display-name map (case-insensitive)
        private static readonly Dictionary<string, (int sheet, int cell)> _stockByDisplay =
            new(StringComparer.OrdinalIgnoreCase)
            {
                // carbox1.bmp
                ["RC Bandit"] = (1, 0),
                ["Dust Mite"] = (1, 1),
                ["Phat Slug"] = (1, 2),
                ["Col. Moss"] = (1, 3),
                ["Harvester"] = (1, 4),
                ["Dr. Grudge"] = (1, 5),
                ["Volken Turbo"] = (1, 6),
                ["Sprinter XL"] = (1, 7),
                ["RC San"] = (1, 8),

                // carbox2.bmp
                ["Candy Pebbles"] = (2, 0),
                ["Genghis Kar"] = (2, 1),
                ["Aquasonic"] = (2, 2),
                ["Mouse"] = (2, 3),
                ["Evil Weasel"] = (2, 4),
                ["Panga TC"] = (2, 5),
                ["R6 Turbo"] = (2, 6),
                ["NY 54"] = (2, 7),
                ["Bertha Ballistics"] = (2, 8),

                // carbox3.bmp
                ["Pest Control"] = (3, 0),
                ["Adeon"] = (3, 1),
                ["Pole Poz"] = (3, 2),
                ["Zipper"] = (3, 3),
                ["Rotor"] = (3, 4),
                ["Cougar"] = (3, 5),
                ["Humma"] = (3, 6),
                ["Toyeca"] = (3, 7),
                ["AMW"] = (3, 8),

                // carbox4.bmp
                ["RC Phink"] = (4, 0),
                ["LA 54"] = (4, 1),
                ["Matra XL"] = (4, 2),
                ["Shocker"] = (4, 3),
                ["Splat"] = (4, 4),
                ["Groovster"] = (4, 5),
                ["JG-7"] = (4, 6),
                ["RG 1"] = (4, 7),
                ["RV Loco"] = (4, 8),

                // carbox5.bmp
                ["SNW 35"] = (5, 0),
                ["Purp XL"] = (5, 1),
                ["Fulon X"] = (5, 2),
                ["Big Volt"] = (5, 3),
                ["BossVolt"] = (5, 4),
                ["Panga"] = (5, 5),
            };

        private static string NormalizeDisplay(string s)
        {
            s = (s ?? "").Trim();

            int i = s.IndexOf(" – ", StringComparison.Ordinal);
            if (i >= 0)
                s = s.Substring(0, i);

            i = s.IndexOf(" (", StringComparison.Ordinal);
            if (i >= 0)
                s = s.Substring(0, i);

            return s;
        }

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            var carDir = values.Length > 0 ? values[0] as string : null;
            var displayNameRaw = values.Length > 1 ? values[1] as string : null;
            var rvglRoot = values.Length > 2 ? values[2] as string : null;
            var folderKeyIn = values.Length > 3 ? values[3] as string : null;

            var displayName = NormalizeDisplay(displayNameRaw);

            // ----- 0) quick sanity on root
            if (string.IsNullOrWhiteSpace(rvglRoot))
                return TryPerCarCarbox(carDir); // no root => fallback only

            // ----- 1) FolderKey first (most reliable)
            if (!string.IsNullOrWhiteSpace(folderKeyIn))
            {
                var fk = folderKeyIn.Trim();
                if (_stockByFolder.TryGetValue(fk, out var hit) ||
                    _stockByFolder.TryGetValue(fk.Replace("_", ""), out hit))
                {
                    var spath = TryGetSheetPath(rvglRoot, hit.sheet);  // <— new helper below
                    var cropped = TryLoadCropped(spath, hit.cell);
                    System.Diagnostics.Debug.WriteLine($"[carbox] by FolderKey: '{fk}' -> sheet {hit.sheet}, cell {hit.cell}, exists={File.Exists(spath)}");
                    if (cropped != null) return MakeImage(cropped);
                }
            }

            // ----- 2) Display-name mapping
            if (!string.IsNullOrWhiteSpace(displayName) &&
                _stockByDisplay.TryGetValue(displayName, out var dd))
            {
                var spath = TryGetSheetPath(rvglRoot, dd.sheet);
                var cropped = TryLoadCropped(spath, dd.cell);
                System.Diagnostics.Debug.WriteLine($"[carbox] by Display: '{displayName}' -> sheet {dd.sheet}, cell {dd.cell}, exists={File.Exists(spath)}");
                if (cropped != null) return MakeImage(cropped);
            }

            // ----- 3) Derive folder from carDir (last resort)
            string folderFromPath = null;
            if (!string.IsNullOrWhiteSpace(carDir))
                try { folderFromPath = Path.GetFileName(carDir)?.Trim(); } catch { }

            if (!string.IsNullOrWhiteSpace(folderFromPath) &&
                (_stockByFolder.TryGetValue(folderFromPath, out var ff) ||
                 _stockByFolder.TryGetValue(folderFromPath.Replace("_", ""), out ff)))
            {
                var spath = TryGetSheetPath(rvglRoot, ff.sheet);
                var cropped = TryLoadCropped(spath, ff.cell);
                System.Diagnostics.Debug.WriteLine($"[carbox] by carDir: '{folderFromPath}' -> sheet {ff.sheet}, cell {ff.cell}, exists={File.Exists(spath)}");
                if (cropped != null) return MakeImage(cropped);
            }

            // ----- 4) Fallback to per-car carbox.bmp
            var fb = TryPerCarCarbox(carDir);
            if (fb != null) return fb;

            // Nothing -> null (small empty tooltip chrome)
            System.Diagnostics.Debug.WriteLine($"[carbox] no match for Display='{displayNameRaw}', FolderKey='{folderKeyIn}', Dir='{carDir}'");
            return null;
        }

        // Helper: accept carbox1.bmp or carbox01.bmp
        private static string TryGetSheetPath(string rvglRoot, int sheetIndex)
        {
            // Candidate base directories where misc/ might live
            // 1) <root>\packs\rvgl_assets\cars\misc     (normal)
            // 2) <root>\..\packs\rvgl_assets\cars\misc  (if RvglRoot points to packs\rvgl_win64)
            // 3) <root>\cars\misc                       (paranoid fallback)
            var bases = new List<string>();

            if (!string.IsNullOrWhiteSpace(rvglRoot))
            {
                bases.Add(Path.Combine(rvglRoot, "packs", "rvgl_assets", "cars", "misc"));

                try
                {
                    var parent = Directory.GetParent(rvglRoot)?.FullName;
                    if (!string.IsNullOrWhiteSpace(parent))
                        bases.Add(Path.Combine(parent, "packs", "rvgl_assets", "cars", "misc"));
                }
                catch { /* ignore */ }

                bases.Add(Path.Combine(rvglRoot, "cars", "misc"));
            }

            // Try both naming styles: carbox1.bmp and carbox01.bmp
            var names = new[]
            {
        $"carbox{sheetIndex}.bmp",
        $"carbox0{sheetIndex}.bmp"
    };

            foreach (var b in bases)
            {
                foreach (var n in names)
                {
                    var p = Path.Combine(b, n);
                    if (File.Exists(p)) return p;
                }
            }

            // If nothing found, return the most likely path for logging/debug info
            return Path.Combine(rvglRoot ?? "", "packs", "rvgl_assets", "cars", "misc", $"carbox{sheetIndex}.bmp");
        }

        // Fallback loader as a reusable method
        private static Image TryPerCarCarbox(string carDir)
        {
            if (string.IsNullOrWhiteSpace(carDir)) return null;
            var path = Path.Combine(carDir, "carbox.bmp");
            if (!File.Exists(path)) return null;

            try
            {
                var bmp = new BitmapImage();
                bmp.BeginInit();
                bmp.CacheOption = BitmapCacheOption.OnLoad;
                bmp.CreateOptions = BitmapCreateOptions.IgnoreImageCache;
                bmp.UriSource = new Uri(path, UriKind.Absolute);
                bmp.EndInit();
                bmp.Freeze();
                return MakeImage(bmp);
            }
            catch { return null; }
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
            => throw new NotSupportedException();

        private static Image MakeImage(ImageSource src) => new Image
        {
            Source = src,
            MaxWidth = 512,
            MaxHeight = 384,
            Stretch = Stretch.Uniform
        };

        private static ImageSource TryLoadCropped(string sheetPath, int cellIndex)
        {
            try
            {
                if (!File.Exists(sheetPath))
                {
                    System.Diagnostics.Debug.WriteLine($"[TryLoadCropped] Missing sheet: {sheetPath}");
                    return null;
                }

                if (!_sheetCache.TryGetValue(sheetPath, out var sheet))
                {
                    var bmp = new BitmapImage();
                    bmp.BeginInit();
                    bmp.CacheOption = BitmapCacheOption.OnLoad;
                    bmp.CreateOptions = BitmapCreateOptions.IgnoreImageCache;
                    bmp.UriSource = new Uri(sheetPath, UriKind.Absolute);
                    bmp.EndInit();
                    bmp.Freeze();
                    _sheetCache[sheetPath] = bmp;
                    sheet = bmp;
                }

                // Debug info
                System.Diagnostics.Debug.WriteLine(
                    $"[TryLoadCropped] sheet={Path.GetFileName(sheetPath)} size={sheet.PixelWidth}x{sheet.PixelHeight}, " +
                    $"cellIndex={cellIndex}");

                int cols = 3, rows = 3; // 3x3 grid
                int w = sheet.PixelWidth / cols;
                int h = sheet.PixelHeight / rows;
                int r = cellIndex / cols;
                int c = cellIndex % cols;

                System.Diagnostics.Debug.WriteLine(
                    $"[TryLoadCropped] crop rect: x={c * w}, y={r * h}, w={w}, h={h}");

                var rect = new System.Windows.Int32Rect(c * w, r * h, w, h);
                var cropped = new CroppedBitmap(sheet, rect);
                cropped.Freeze();
                return cropped;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TryLoadCropped] Error: {ex}");
                return null;
            }
        }
    }
}
