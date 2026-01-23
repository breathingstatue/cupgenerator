using CupGen.UI.Services;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Timers;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Shapes;
using Forms = System.Windows.Forms;
using IOPath = System.IO.Path;
using CupGenerator.Models;

namespace CupGen.UI
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        void OnPropertyChanged([CallerMemberName] string prop = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));

        // ---- RVGL root ----
        public string RvglRoot
        {
            get => _rvglRoot;
            set
            {
                _rvglRoot = value;
                OnPropertyChanged();
                SaveLastRoot(_rvglRoot);
                RefreshProfiles();
                WriteActiveProfileFile();

                // NEW: run the on-disk RVGL signature scan via the helper DLL
                var sig = Services.RvglSigInterop.EnsureOnDiskSignatures(_rvglRoot);
                Status = sig.message;
                Debug.WriteLine(sig.message);
            }
        }

        private string _rvglRoot = "";

        private CarItem _selectedCarItem;
        public CarItem SelectedCarItem
        {
            get => _selectedCarItem;
            set { if (_selectedCarItem == value) return; _selectedCarItem = value; OnPropertyChanged(); }
        }

        private TrackItem _selectedTrackItem;
        public TrackItem SelectedTrackItem
        {
            get => _selectedTrackItem;
            set { if (_selectedTrackItem == value) return; _selectedTrackItem = value; OnPropertyChanged(); }
        }

        private CupRef _selectedCupListItem;
        public CupRef SelectedCupListItem
        {
            get => _selectedCupListItem;
            set
            {
                if (_selectedCupListItem == value) return;
                _selectedCupListItem = value;
                OnPropertyChanged();
                if (value != null) LoadCupFromRef(value);
            }
        }
        public ObservableCollection<CupRef> Cups { get; } = new ObservableCollection<CupRef>();

        public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }
        private string _status = "Ready.";

        private static string SettingsDir =>
            IOPath.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CupGenerator");
        private static string LastRootPathFile => IOPath.Combine(SettingsDir, "last_rvgl_root.txt");

        private static void EnsureSettingsDir()
        {
            try { Directory.CreateDirectory(SettingsDir); } catch { /* ignore */ }
        }
        private void SaveLastRoot(string path)
        {
            try { EnsureSettingsDir(); File.WriteAllText(LastRootPathFile, path ?? ""); } catch { /* ignore */ }
        }
        private string LoadLastRoot()
        {
            try
            {
                if (File.Exists(LastRootPathFile))
                    return File.ReadAllText(LastRootPathFile).Trim();
            }
            catch { /* ignore */ }
            return "";
        }

        private static string LastProfileFile => IOPath.Combine(SettingsDir, "last_profile.txt");

        private void SaveLastProfile(string profile)
        {
            try { EnsureSettingsDir(); File.WriteAllText(LastProfileFile, profile ?? ""); } catch { /* ignore */ }
        }
        private string LoadLastProfile()
        {
            try
            {
                if (File.Exists(LastProfileFile))
                    return File.ReadAllText(LastProfileFile).Trim();
            }
            catch { /* ignore */ }
            return "";
        }

        private string ProfilesBase()
        {
            // Matches CupGenGlobals: gProfiles = join2(gRoot, "save\\profiles");
            return IOPath.Combine(RvglRoot ?? "", "save", "profiles");
        }

        private string CupGenDir()
        {
            // <root>\packs\rvgl_assets\cups\cupgen
            var p = IOPath.Combine(RvglRoot ?? "", "packs", "rvgl_assets", "cups", "cupgen");
            Directory.CreateDirectory(p);
            return p;
        }

        private string ActiveProfileTxtPath() => IOPath.Combine(CupGenDir(), "active_profile.txt");

        private void WriteActiveProfileFile()
        {
            try
            {
                var p = ActiveProfileTxtPath();
                Directory.CreateDirectory(IOPath.GetDirectoryName(p));
                File.WriteAllText(p, SelectedProfile ?? "", new UTF8Encoding(false));
            }
            catch { /* ignore */ }
        }

        // Pull counts for Randomizer from the currently loaded Cup
        private void SyncRandomizerFromCup()
        {
            if (Cup?.Stages == null || Cup.Stages.Count == 0)
            {
                RandomAmount = 0;
                CountNormal = CountReverse = CountMirror = CountMirrorReverse = 0;
                return;
            }

            int normal = 0, reverse = 0, mirror = 0, mirrorReverse = 0;

            foreach (var s in Cup.Stages)
            {
                if (s.Mirrored)
                {
                    if (s.Reversed) mirrorReverse++;
                    else mirror++;
                }
                else
                {
                    if (s.Reversed) reverse++;
                    else normal++;
                }
            }

            // Set the Randomizer knobs to reflect this cup
            CountNormal = normal;
            CountReverse = reverse;
            CountMirror = mirror;
            CountMirrorReverse = mirrorReverse;

            // Amount is the total number of stages
            RandomAmount = Cup.Stages.Count;
        }

        // If your ObtainCustom args TextBox is named differently, update this reference in InsertTokenIntoObtainArgs.
        private TextBox ObtainArgsTextBox => ObtainCustomArgsBox; // <— ensure your XAML TextBox has x:Name="ObtainCustomArgsBox"

        // Extract IDs shown in .cup files:
        //  - Track: folder key (e.g., "toy1")
        //  - Cup:   filename without extension (CupRef.Id)
        private static string? TokenFromTrack(object? o)
        {
            return (o as TrackItem)?.FolderKey?.Trim();
        }
        private static string? TokenFromCup(object? o)
        {
            return (o as CupRef)?.Id?.Trim();
        }

        // Insert at caret into the visible TextBox when possible; otherwise append to the bound property.
        private void InsertTokenIntoObtainArgs(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) return;

            var tb = ObtainArgsTextBox;
            if (tb != null)
            {
                // prefer caret insert for better UX
                var text = tb.Text ?? string.Empty;
                int pos = tb.IsKeyboardFocusWithin ? tb.CaretIndex : text.Length;

                var insert = token;
                if (pos > 0 && pos <= text.Length && text[pos - 1] != ' ')
                    insert = " " + insert;

                tb.Text = text.Insert(pos, insert);
                tb.CaretIndex = pos + insert.Length;
                tb.Focus();

                // keep the view-model in sync if bound TwoWay
                Cup.ObtainCustomArgsRaw = tb.Text;   // not the MainWindow property
                return;
            }

            // fallback: append to the bound property
            var parts = (ObtainCustomArgsRaw ?? "").Trim();
            ObtainCustomArgsRaw = string.IsNullOrEmpty(parts) ? token : parts + " " + token;
        }

        // ---- auto-inject toggle ----
        public bool AutoInject
        {
            get => _autoInject;
            set { _autoInject = value; OnPropertyChanged(); ToggleWatcher(_autoInject); }
        }
        private bool _autoInject = true;

        // Which tab is selected: 0 = Cars, 1 = Tracks, 2 = Cups
        private int _activeTabIndex;
        public int ActiveTabIndex
        {
            get => _activeTabIndex;
            set
            {
                if (_activeTabIndex == value) return;
                _activeTabIndex = value;
                OnPropertyChanged();
                // Refresh all three (cheap)
                CarsView?.Refresh();
                TracksView?.Refresh();
                CupsView?.Refresh();
            }
        }

        // Shared search text for all tabs
        private string _searchText = "";
        public string SearchText
        {
            get => _searchText;
            set
            {
                if (_searchText == value) return;
                _searchText = value ?? "";
                OnPropertyChanged();
                CarsView?.Refresh();
                TracksView?.Refresh();
                CupsView?.Refresh();
            }
        }
        private static bool ContainsAllTokens(string haystack, string tokens)
        {
            if (string.IsNullOrWhiteSpace(tokens)) return true;
            if (string.IsNullOrEmpty(haystack)) return false;

            foreach (var tok in tokens.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (haystack.IndexOf(tok, StringComparison.OrdinalIgnoreCase) < 0)
                    return false;
            }
            return true;
        }

        // ---- scanned models ----
        public ObservableCollection<CarItem> Cars { get; } = new ObservableCollection<CarItem>();
        public ObservableCollection<TrackItem> Tracks { get; } = new ObservableCollection<TrackItem>();

        // Filterable views for the Library UI
        public ICollectionView CarsView { get; private set; }
        public ICollectionView TracksView { get; private set; }
        public ICollectionView CupsView { get; private set; }

        // ----- Randomizer options (with defaults) -----
        private bool _noRepeats = false;
        public bool NoRepeats
        {
            get => _noRepeats;
            set { _noRepeats = value; OnPropertyChanged(); }
        }

        private int _randomAmount = 4;
        public int RandomAmount
        {
            get => _randomAmount;
            set { _randomAmount = Math.Max(0, value); OnPropertyChanged(); }
        }
        private void SelectJoker_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedCarItem is CarItem ci)
            {
                Cup.JokerLine = $"Joker 1 {ci.FolderKey}";
                OnPropertyChanged(nameof(Cup));
                UpdatePreview();
                Status = $"Joker set to {ci.FolderKey}";
            }
            else
            {
                Status = "Select a car first to set as Joker.";
            }
        }

        private void RemoveJoker_Click(object sender, RoutedEventArgs e)
        {
            Cup.JokerLine = "Joker 0";
            OnPropertyChanged(nameof(Cup));
            UpdatePreview();
            Status = "Joker removed.";
        }

        private bool _includeStock = true, _includeMain = true, _includeBonus = false;
        public bool IncludeStock { get => _includeStock; set { _includeStock = value; OnPropertyChanged(); } }
        public bool IncludeMain { get => _includeMain; set { _includeMain = value; OnPropertyChanged(); } }
        public bool IncludeBonus { get => _includeBonus; set { _includeBonus = value; OnPropertyChanged(); } }

        private int _countNormal = 4, _countReverse = 0, _countMirror = 0, _countMirrorReverse = 0;
        public int CountNormal { get => _countNormal; set { _countNormal = Math.Max(0, value); OnPropertyChanged(); } }
        public int CountReverse { get => _countReverse; set { _countReverse = Math.Max(0, value); OnPropertyChanged(); } }
        public int CountMirror { get => _countMirror; set { _countMirror = Math.Max(0, value); OnPropertyChanged(); } }
        public int CountMirrorReverse { get => _countMirrorReverse; set { _countMirrorReverse = Math.Max(0, value); OnPropertyChanged(); } }

        private CupRef _selectedCup;
        private string _tempPreviewPath = IOPath.Combine(
            IOPath.GetTempPath(), "CupGen", "preview.cup");

        public string SelectedCarCategory
        {
            get => _selCarCat;
            set { _selCarCat = value; OnPropertyChanged(); CarsView?.Refresh(); }
        }
        private string _selCarCat = "All";

        public string SelectedTrackCategory
        {
            get => _selTrkCat;
            set { _selTrkCat = value; OnPropertyChanged(); TracksView?.Refresh(); }
        }
        private string _selTrkCat = "All";

        // ---- cup model ----
        public CupModel Cup { get; } = new CupModel();
        public ObservableCollection<string> StagesDisplay { get; } = new ObservableCollection<string>();

        public int StageLaps { get => _stageLaps; set { _stageLaps = Math.Max(1, value); OnPropertyChanged(); } }
        private int _stageLaps = 3;
        public bool StageMirrored { get => _stageMirrored; set { _stageMirrored = value; OnPropertyChanged(); } }
        private bool _stageMirrored;
        public bool StageReversed { get => _stageReversed; set { _stageReversed = value; OnPropertyChanged(); } }
        private bool _stageReversed;

        public class CupRef
        {
            public string Id { get; set; }      // filename without extension
            public string Display { get; set; } // Name from inside the cup file (fallback to Id)
            public string FullPath { get; set; }
        }
        private void LoadCupFromRef(CupRef cr)
        {
            try
            {
                if (cr == null || string.IsNullOrWhiteSpace(cr.FullPath) || !File.Exists(cr.FullPath))
                {
                    Status = "Cup not found.";
                    return;
                }

                var cup = Services.CupFileIO.Load(cr.FullPath);
                Cup.CopyFrom(cup);

                // IMPORTANT: rewire CollectionChanged to the (possibly) new collection
                HookStagesCollection(Cup.Stages);

                // (optional, you already do per-stage PropertyChanged subscription)
                foreach (var st in Cup.Stages)
                    st.PropertyChanged += (_, __) => UpdatePreview();

                RebuildStagesDisplay();
            }

            catch (Exception ex)
            {
                Status = "Load error: " + ex.Message;
            }
        }

        private void CupsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (SelectedCupListItem is CupRef cr)
            {
                _selectedCup = cr;
                LoadCupFromRef(cr);   // instant load -> Review
            }
        }

        // ---- classes CSV passthrough ----
        public string ClassesCsv
        {
            get { return string.Join(",", Cup.Classes); }
            set
            {
                var parts = value.Split(',', ' ', '\t')
                                 .Select(s => s.Trim())
                                 .Where(s => s.Length > 0);
                Cup.Classes.Clear();
                foreach (var p in parts)
                {
                    if (int.TryParse(p, out int n))
                        Cup.Classes.Add(n);
                }
                OnPropertyChanged(nameof(ClassesCsv));
                UpdatePreview();
            }
        }

        // ---- scoring CSV passthrough ----
        public string PointsCsv
        {
            get { return string.Join(",", Cup.Points); }
            set
            {
                var parts = value.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0);
                int[] parsed = parts.Select(p => { int n; return int.TryParse(p, out n) ? n : 0; }).ToArray();
                if (parsed.Length > 0) Cup.Points = parsed.ToList();
                OnPropertyChanged(nameof(PointsCsv));
                UpdatePreview();
            }
        }

        // ---- profiles ----
        public ObservableCollection<string> Profiles { get; } = new ObservableCollection<string>();

        public string SelectedProfile
        {
            get => _selectedProfile;
            set
            {
                if (_selectedProfile == value) return;
                _selectedProfile = value ?? "";
                OnPropertyChanged();
                SaveLastProfile(_selectedProfile);
                WriteActiveProfileFile();   // keep the mod in sync
                Status = string.IsNullOrWhiteSpace(_selectedProfile)
                    ? "Profile cleared."
                    : $"Profile set: {_selectedProfile}";
            }
        }
        private string _selectedProfile = "";
        private void RefreshProfiles()
        {
            Profiles.Clear();

            try
            {
                var baseDir = ProfilesBase();
                if (Directory.Exists(baseDir))
                {
                    foreach (var dir in Directory.EnumerateDirectories(baseDir))
                    {
                        var name = IOPath.GetFileName(dir);
                        if (!string.IsNullOrWhiteSpace(name))
                            Profiles.Add(name);
                    }
                }
            }
            catch { /* ignore */ }

            // Restore last profile if still available; else pick the first; else clear
            var last = LoadLastProfile();
            if (!string.IsNullOrWhiteSpace(last) && Profiles.Contains(last))
                SelectedProfile = last;
            else if (Profiles.Count > 0)
                SelectedProfile = Profiles[0];
            else
                SelectedProfile = "";
        }

        private void StagesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            int i = StagesList.SelectedIndex;
            if (i >= 0 && i < Cup.Stages.Count)
            {
                var st = Cup.Stages[i];
                StageLaps = st.Laps;
                StageMirrored = st.Mirrored;
                StageReversed = st.Reversed;
                Status = $"Editing Stage {i}: {st.TrackKey}";
            }
        }

        // ---- ObtainCustom (UI-facing fields) ----
        public int ObtainCustomMode
        {
            get => _obtainMode;
            set { _obtainMode = value; OnPropertyChanged(); UpdatePreview(); }
        }
        private int _obtainMode = 0;

        // Space-separated track folder keys
        public string ObtainCustomArgsRaw
        {
            get => _obtainArgs;
            set { _obtainArgs = value ?? ""; OnPropertyChanged(); UpdatePreview(); }
        }
        private string _obtainArgs = "";

        // ---- preview text ----
        public string Preview { get => _preview; set { _preview = value; OnPropertyChanged(); } }
        private string _preview = "";

        // ---- watcher state ----
        private readonly System.Windows.Threading.DispatcherTimer _watchTimer =
            new System.Windows.Threading.DispatcherTimer() { Interval = TimeSpan.FromSeconds(1) };
        private readonly HashSet<int> _injectedPids = new HashSet<int>();

        // (+Track)
        private void AddObtainLevel_Click(object sender, RoutedEventArgs e)
        {
            var tok = TokenFromTrack(SelectedTrackItem);
            if (string.IsNullOrWhiteSpace(tok))
            {
                Status = "Select a track first.";
                return;
            }
            InsertTokenIntoObtainArgs(tok);
        }

        // (+Cup)
        private void AddObtainCup_Click(object sender, RoutedEventArgs e)
        {
            var tok = TokenFromCup(SelectedCupListItem);
            if (string.IsNullOrWhiteSpace(tok))
            {
                Status = "Select a cup first.";
                return;
            }
            InsertTokenIntoObtainArgs(tok);
        }

        // Replace the existing method entirely with this version.
        private List<TrackItem> GetTrackCandidatesByFlags(bool includeStock, bool includeMain, bool includeBonus)
        {
            var source = Tracks ?? new ObservableCollection<TrackItem>();

            // If TrackItem has Category strings like "Stock", "Main", "Bonus":
            bool CatOk(TrackItem t)
                => (includeStock && t.Category.Equals("Stock", StringComparison.OrdinalIgnoreCase))
                || (includeMain && t.Category.Equals("Main", StringComparison.OrdinalIgnoreCase))
                || (includeBonus && t.Category.Equals("Bonus", StringComparison.OrdinalIgnoreCase));

            // If your categories differ, adjust the three literals above accordingly.

            // Distinct by FolderKey (polyfill for DistinctBy)
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<TrackItem>();
            foreach (var t in source.Where(CatOk))
            {
                var key = t.FolderKey ?? "";
                if (key.Length == 0) continue;
                if (seen.Add(key))
                    result.Add(t);
            }
            return result;
        }

        // Simple Fisher–Yates
        private static void ShuffleInPlace<T>(IList<T> list, Random rng)
        {
            for (int i = list.Count - 1; i > 0; i--)
            {
                int j = rng.Next(i + 1);
                (list[i], list[j]) = (list[j], list[i]);
            }
        }

        // Decide laps per track; adapt if you have per-track defaults
        private int InferDefaultLaps(TrackItem t)
        {
            // If you have a laps hint on TrackItem, return that.
            // e.g., if (t.DefaultLaps > 0) return t.DefaultLaps;
            return 3;
        }

        private void RebuildStagesDisplay()
        {
            StagesDisplay.Clear();
            for (int i = 0; i < Cup.Stages.Count; i++)
            {
                var s = Cup.Stages[i];
                StagesDisplay.Add($"{i:D2}  {s.TrackKey}  {s.Laps}  {s.Mirrored}  {s.Reversed}");
            }
        }

        private void Stage_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            // When user edits laps/mirror/reverse, refresh the display + preview
            RebuildStagesDisplay();
            UpdatePreview();
        }

        private void RandomizeTracks_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // 1) Validate counts
                int requested = Math.Max(0, RandomAmount);
                int modesSum = CountNormal + CountReverse + CountMirror + CountMirrorReverse;
                if (modesSum != requested)
                {
                    // auto-fix: clamp to requested and fill remainder into Normal
                    int remainder = Math.Max(0, requested - Math.Max(0, CountReverse + CountMirror + CountMirrorReverse));
                    CountNormal = remainder;
                    modesSum = CountNormal + CountReverse + CountMirror + CountMirrorReverse;
                }

                // 2) Build candidate set based on filters
                var candidates = GetTrackCandidatesByFlags(
                    includeStock: IncludeStock,
                    includeMain: IncludeMain,
                    includeBonus: IncludeBonus);

                if (candidates.Count == 0)
                {
                    MessageBox.Show("No tracks match the selected Include filters.", "Random Tracks",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (requested > candidates.Count)
                {
                    // Without repeats, cap at available candidates
                    requested = candidates.Count;
                }

                // 3) Shuffle candidates
                var rng = new Random();
                ShuffleInPlace(candidates, rng);

                // 4) Build and shuffle mode bag
                var modes = new List<(bool mirrored, bool reversed)>(requested);
                modes.AddRange(Enumerable.Repeat((false, false), CountNormal));
                modes.AddRange(Enumerable.Repeat((false, true), CountReverse));
                modes.AddRange(Enumerable.Repeat((true, false), CountMirror));
                modes.AddRange(Enumerable.Repeat((true, true), CountMirrorReverse));
                ShuffleInPlace(modes, rng);

                // 5) Pick allowing duplicates across modes, but unique per Track+Mode
                var newStages = new ObservableCollection<CupModel.Stage>();

                // Uniqueness keys
                var usedTrackMode = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // key: track:mir:rev
                var usedBaseTrack = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // key: track (FolderKey) only

                int iMode = 0;
                int guard = requested * 10; // a bit higher if NoRepeats shrinks options

                while (newStages.Count < requested && guard-- > 0)
                {
                    var t = candidates[rng.Next(candidates.Count)];
                    var m = modes[iMode];

                    // If "No Repeats" is ON, ensure the base track hasn't been used in any mode.
                    if (NoRepeats && usedBaseTrack.Contains(t.FolderKey))
                        continue;

                    string sig = $"{t.FolderKey}:{m.mirrored}:{m.reversed}";
                    if (!usedTrackMode.Add(sig))
                        continue;

                    // Reserve the base track if NoRepeats
                    if (NoRepeats) usedBaseTrack.Add(t.FolderKey);

                    int laps = InferDefaultLaps(t);
                    newStages.Add(new CupModel.Stage
                    {
                        TrackKey = t.FolderKey,
                        Laps = laps,
                        Mirrored = m.mirrored,
                        Reversed = m.reversed
                    });

                    iMode++;
                    if (iMode >= modes.Count) break;
                }

                AssignStagesToCup(newStages);

                // Optional: Scroll your Stages list into view or refresh bindings if needed
                // e.g., StagesList.ItemsSource = Cup.Stages;  // if you use a named control
            }
            catch (Exception ex)
            {
                MessageBox.Show("Randomize failed:\n" + ex.Message, "Random Tracks",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public MainWindow()
        {
            InitializeComponent();

            StagesList.PreviewKeyDown += (s, e) =>
            {
                if (e.Key == System.Windows.Input.Key.Delete)
                {
                    RemoveStage_Click(StagesList, new RoutedEventArgs());
                    e.Handled = true;
                }
            };

            // Rebuild preview when Cup's scalar props change
            Cup.PropertyChanged += (_, __) => UpdatePreview();

            // Rebuild when Opponents list changes
            Cup.Opponents.CollectionChanged += (_, __) => UpdatePreview();

            HookStagesCollection(Cup.Stages);

            // also attach for already-existing stages (e.g., after Load)
            foreach (var st in Cup.Stages)
                st.PropertyChanged += (_, __) => UpdatePreview();

            DataContext = this;

            // Create filterable views exactly once
            CarsView = CollectionViewSource.GetDefaultView(Cars);
            CarsView.SortDescriptions.Clear();
            CarsView.SortDescriptions.Add(new SortDescription(nameof(CarItem.Rating), ListSortDirection.Ascending));
            CarsView.SortDescriptions.Add(new SortDescription(nameof(CarItem.SortName), ListSortDirection.Ascending));
            TracksView = CollectionViewSource.GetDefaultView(Tracks);
            CupsView = CollectionViewSource.GetDefaultView(Cups);

            // Cars
            CarsView.Filter = o =>
            {
                if (o is not CarItem c) return false;
                bool catOK = (SelectedCarCategory == "All") ||
                             c.Category.Equals(SelectedCarCategory, StringComparison.OrdinalIgnoreCase);
                if (!catOK) return false;

                var name = c.Display ?? "";
                var key = c.FolderKey ?? "";
                var parentFolder = c.ParentFolder ?? "";
                return ContainsAllTokens(name + " " + key + " " + parentFolder, SearchText);
            };

            // Tracks
            TracksView.Filter = o =>
            {
                if (o is not TrackItem t) return false;
                bool catOK = (SelectedTrackCategory == "All") ||
                             t.Category.Equals(SelectedTrackCategory, StringComparison.OrdinalIgnoreCase);
                if (!catOK) return false;

                var name = t.Display ?? t.FolderKey ?? "";
                var key = t.FolderKey ?? "";
                var parentFolder = t.ParentFolder ?? "";
                return ContainsAllTokens(name + " " + key + " " + parentFolder, SearchText);
            };

            // Cups
            CupsView.Filter = o =>
            {
                if (o is not CupRef cup) return false;
                var disp = cup.Display ?? "";
                var id = cup.Id ?? "";
                return ContainsAllTokens(disp + " " + id, SearchText);
            };

            // Refresh views when their backing collections change
            ((INotifyCollectionChanged)Cars).CollectionChanged += (_, __) => CarsView.Refresh();
            ((INotifyCollectionChanged)Tracks).CollectionChanged += (_, __) => TracksView.Refresh();
            ((INotifyCollectionChanged)Cups).CollectionChanged += (_, __) => CupsView.Refresh();

            // Restore last root and optionally auto-scan
            var last = LoadLastRoot();
            if (!string.IsNullOrWhiteSpace(last) && Directory.Exists(last))
            {
                RvglRoot = last;
                Scan_Click(this, new RoutedEventArgs());
            }

            _watchTimer.Tick += WatchTick;
            if (AutoInject) _watchTimer.Start();

            UpdatePreview();
        }

        private void UpdatePreview()
        {
            try
            {
                Preview = Services.CupFileIO.FormatPreview(Cup);
            }
            catch { /* keep UI responsive */ }
        }

        // ---- UI handlers ----

        private static void DeleteOldAddrsJsonIfAny(string rvglRoot)
        {
            try
            {
                var jsonPath = RvglSigInterop.GetAddrsJsonPath(rvglRoot);
                if (File.Exists(jsonPath))
                {
                    var attr = File.GetAttributes(jsonPath);
                    if ((attr & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                        File.SetAttributes(jsonPath, attr & ~FileAttributes.ReadOnly);
                    File.Delete(jsonPath);
                    Debug.WriteLine($"Deleted old rvgl_addrs.json at: {jsonPath}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"DeleteOldAddrsJsonIfAny: {ex}");
                // non-fatal; proceed
            }
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            using (var dlg = new Forms.FolderBrowserDialog())
            {
                dlg.Description = "Select RVGL root";
                if (dlg.ShowDialog() == Forms.DialogResult.OK)
                    RvglRoot = dlg.SelectedPath;
            }
        }

        private void Scan_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(RvglRoot) || !Directory.Exists(RvglRoot))
            {
                Status = "Invalid path.";
                return;
            }

            try
            {
                Status = "Scanning…";

                // 1) Signatures: run native scan via RvglSigInterop (produces/refreshes rvgl_addrs.json)
                // NEW: clear old rvgl_addrs.json so the helper DLL writes a fresh one
                DeleteOldAddrsJsonIfAny(_rvglRoot);

                // run the on-disk RVGL signature scan via the helper DLL
                var sig = Services.RvglSigInterop.EnsureOnDiskSignatures(_rvglRoot);
                System.Diagnostics.Debug.WriteLine(sig.message);

                // Optional: surface failures but still continue with folder scan
                if (!sig.ok)
                    Status = $"Signatures: {sig.message}";
                else
                    Status = "Signatures up to date.";

                // 2) Folder scan: Cups / Cars / Tracks
                Cups.Clear();
                Cars.Clear();
                Tracks.Clear();

                foreach (var c in Services.RvglFolderScanner.ScanCups(RvglRoot)) Cups.Add(c);
                foreach (var c in Services.RvglFolderScanner.ScanCars(RvglRoot)) Cars.Add(c);
                foreach (var t in Services.RvglFolderScanner.ScanTracks(RvglRoot)) Tracks.Add(t);

                CupsView?.Refresh();
                CarsView?.Refresh();
                TracksView?.Refresh();

                Status = $"Signatures: {(sig.ok ? "OK" : "WARN")} — Found {Cars.Count} cars, {Tracks.Count} tracks.";
            }
            catch (Exception ex)
            {
                Status = "Scan error: " + ex.Message;
            }
        }

        // Watcher on/off
        private void ToggleWatcher(bool on)
        {
            if (on) _watchTimer.Start();
            else _watchTimer.Stop();
        }

        // Poll for rvgl.exe and inject once per PID (your DLL path + profile file refresh)
        private void WatchTick(object sender, EventArgs e)
        {
            try
            {
                var procs = Process.GetProcessesByName("rvgl");
                foreach (var p in procs)
                {
                    if (_injectedPids.Contains(p.Id)) continue;

                    string dllPath = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, "RVGLCupOpponents.dll");
                    if (!File.Exists(dllPath))
                    {
                        Status = "DLL not found next to the EXE.";
                        return;
                    }

                    // Mark as handled if your external injector is used elsewhere.
                    _injectedPids.Add(p.Id);
                }

                // prune dead PIDs
                _injectedPids.RemoveWhere(pid => Process.GetProcesses().All(pp => pp.Id != pid));
            }
            catch (Exception ex)
            {
                Status = "Watcher error: " + ex.Message;
            }
        }

        private void AddOpponent_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedCarItem is CarItem ci)
            {
                Cup.Opponents.Add(ci.FolderKey);
                OnPropertyChanged(nameof(Cup));
                UpdatePreview();
            }
        }

        private void RemoveOpponent_Click(object sender, RoutedEventArgs e)
        {
            if (OpponentsList.SelectedItem is string key)
            {
                Cup.Opponents.Remove(key);
                UpdatePreview();
            }
        }

        private void OpponentsList_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Delete)
            {
                var selected = OpponentsList.SelectedItems.Cast<string>().ToList();
                if (selected.Count > 0)
                {
                    foreach (var key in selected)
                        Cup.Opponents.Remove(key);

                    UpdatePreview();
                    e.Handled = true; // prevent system beep
                }
            }
        }

        private void AddStage_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedTrackItem is not TrackItem ti)
            {
                Status = "Select a track first.";
                return;
            }

            var st = new CupModel.Stage
            {
                TrackKey = ti.FolderKey,
                Laps = StageLaps,
                Mirrored = StageMirrored,
                Reversed = StageReversed
            };

            Cup.Stages.Add(st);       // <-- only update the model
                                      // NO manual StagesDisplay.Add(...) here

            // select the newly added stage and sync editor fields
            int idx = Cup.Stages.Count - 1;
            if (idx >= 0)
            {
                StagesList.SelectedIndex = idx;
                StageLaps = st.Laps;
                StageMirrored = st.Mirrored;
                StageReversed = st.Reversed;
            }

            UpdatePreview();
        }

        private ObservableCollection<CupModel.Stage> _stagesHooked;

        private void HookStagesCollection(ObservableCollection<CupModel.Stage> coll)
        {
            if (_stagesHooked != null)
                _stagesHooked.CollectionChanged -= Stages_CollectionChanged;

            _stagesHooked = coll;

            if (_stagesHooked != null)
                _stagesHooked.CollectionChanged += Stages_CollectionChanged;
        }

        private void Stages_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.NewItems != null)
                foreach (CupModel.Stage st in e.NewItems)
                    st.PropertyChanged += Stage_PropertyChanged;

            if (e.OldItems != null)
                foreach (CupModel.Stage st in e.OldItems)
                    st.PropertyChanged -= Stage_PropertyChanged;

            RebuildStagesDisplay();
            UpdatePreview();
        }

        private void AssignStagesToCup(ObservableCollection<CupModel.Stage> stages)
        {
            Cup.Stages = stages;
            HookStagesCollection(Cup.Stages);
            OnPropertyChanged(nameof(Cup));
            RebuildStagesDisplay();
        }

        private void UpdateStage_Click(object sender, RoutedEventArgs e)
        {
            int i = StagesList.SelectedIndex;
            if (i < 0 || i >= Cup.Stages.Count) { Status = "Select a stage to update."; return; }

            var st = Cup.Stages[i];
            st.Laps = StageLaps;
            st.Mirrored = StageMirrored;
            st.Reversed = StageReversed;

            // Keep the side list in sync and preserve selection
            int keep = i;
            RebuildStagesDisplay();
            if (keep >= 0 && keep < StagesList.Items.Count)
                StagesList.SelectedIndex = keep;

            UpdatePreview();
            Status = $"Stage {i} updated.";
        }

        private void RemoveStage_Click(object sender, RoutedEventArgs e)
        {
            int i = StagesList.SelectedIndex;
            if (i < 0 || i >= Cup.Stages.Count)
            {
                Status = "Select a track in the added list to remove.";
                return;
            }

            // Remove the selected stage
            Cup.Stages.RemoveAt(i);

            // Side list mirrors Cup.Stages; you can either rebuild or surgically remove:
            // StagesDisplay.RemoveAt(i);
            RebuildStagesDisplay();

            // Pick a sensible next selection
            if (Cup.Stages.Count > 0)
            {
                int newIndex = Math.Min(i, Cup.Stages.Count - 1);
                StagesList.SelectedIndex = newIndex;

                // Refresh the per-stage editor fields to match the new selection
                var st = Cup.Stages[newIndex];
                StageLaps = st.Laps;
                StageMirrored = st.Mirrored;
                StageReversed = st.Reversed;
                Status = $"Removed stage {i}. Now editing stage {newIndex}: {st.TrackKey}";
            }
            else
            {
                // No items left; clear editor fields
                StageLaps = 3;
                StageMirrored = false;
                StageReversed = false;
                Status = "All stages removed.";
            }

            UpdatePreview(); // (also triggered by CollectionChanged, but fine to call)
        }

        // Bottom-right "Load Cup"
        private void LoadSelectedCup_Click(object sender, RoutedEventArgs e)
        {
            if (SelectedCupListItem is CupRef cr)
            {
                _selectedCup = cr;
                LoadCupFromRef(cr);
            }
            else
            {
                Status = "Pick a cup in the list first.";
            }
        }

        private void RefreshProfiles_Click(object sender, RoutedEventArgs e)
        {
            RefreshProfiles();
        }
        private void SaveCupToOriginal_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var cupsDir = IOPath.Combine(RvglRoot ?? "", "packs", "rvgl_assets", "cups");
                Directory.CreateDirectory(cupsDir);

                var suggested = (_selectedCup?.Id ?? Cup?.Name ?? "cup").Trim();
                foreach (var c in IOPath.GetInvalidFileNameChars()) suggested = suggested.Replace(c, '_');
                if (string.IsNullOrWhiteSpace(suggested)) suggested = "cup";

                var sfd = new Microsoft.Win32.SaveFileDialog
                {
                    Title = "Save cup",
                    Filter = "Cup files (*.txt)|*.txt|All files (*.*)|*.*",
                    DefaultExt = ".txt",
                    AddExtension = true,
                    OverwritePrompt = true,
                    ValidateNames = true,
                    InitialDirectory = cupsDir,
                    FileName = suggested + ".txt"
                };

                if (sfd.ShowDialog() != true) { Status = "Save canceled."; return; }

                // Use the exact path the user chose (no forced folder).
                var finalPath = sfd.FileName;

                // Generate fresh from model at save-time (safer than relying on Preview text).
                File.WriteAllText(finalPath, Services.CupFileIO.FormatPreview(Cup), new UTF8Encoding(false));

                Status = $"Saved: {finalPath}";
                // Optional refresh if saved under cups/
                if (finalPath.StartsWith(cupsDir, StringComparison.OrdinalIgnoreCase))
                    Scan_Click(this, new RoutedEventArgs());
            }
            catch (Exception ex)
            {
                Status = "Save error: " + ex.Message;
            }
        }
    }

    public partial class App
    {
        private static Mutex _injectorMutex;

        protected override void OnStartup(System.Windows.StartupEventArgs e)
        {
            base.OnStartup(e);
            TryStartAutoInjector();
        }

        private static void TryStartAutoInjector()
        {
            // Ensure we only spawn one injector per user session
            bool createdNew = false;
            _injectorMutex = new Mutex(initiallyOwned: true, name: "Global\\RVGLAutoInjector_Singleton", createdNew: out createdNew);
            if (!createdNew)
                return;

            try
            {
                // Resolve path next to CupGenerator.exe
                string exeDir = AppDomain.CurrentDomain.BaseDirectory;
                string injectorPath = IOPath.Combine(exeDir, "RVGLAutoInjector.exe");

                if (!File.Exists(injectorPath))
                    return; // silently skip if not shipped

                // If already running, don't start another
                if (Process.GetProcessesByName("RVGLAutoInjector").Any())
                    return;

                var psi = new ProcessStartInfo
                {
                    FileName = injectorPath,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                Process.Start(psi);
            }
            catch
            {
                // swallow – injector is a convenience, not critical to UI
            }
        }
        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);

            try
            {
                // Best effort: terminate any running injectors
                foreach (var p in Process.GetProcessesByName("RVGLAutoInjector"))
                {
                    try
                    {
                        if (!p.HasExited)
                        {
                            // Optional grace:
                            p.CloseMainWindow();    // no-op for windowless, but cheap
                            if (!p.WaitForExit(300))
                                p.Kill();           // .NET Framework overload (no entireProcessTree)
                        }
                    }
                    catch { /* ignore */ }
                }
            }
            catch { /* ignore */ }

            try
            {
                _injectorMutex?.ReleaseMutex();
                _injectorMutex?.Dispose();
            }
            catch { /* ignore */ }
        }
    }
}