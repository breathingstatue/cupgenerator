#nullable enable
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace CupGenerator.Models
{
    public class CupModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? prop = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));

        protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? prop = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            OnPropertyChanged(prop);
            return true;
        }

        // ---------------- Core fields ----------------

        private string _name = "";
        public string Name
        {
            get => _name;
            set => SetProperty(ref _name, value ?? "");
        }

        private int _difficulty;
        public int Difficulty
        {
            get => _difficulty;
            set => SetProperty(ref _difficulty, value);
        }

        private int _obtain;
        public int Obtain
        {
            get => _obtain;
            set => SetProperty(ref _obtain, value);
        }

        private int _obtainCustomMode;
        public int ObtainCustomMode
        {
            get => _obtainCustomMode;
            set => SetProperty(ref _obtainCustomMode, value);
        }

        private string _obtainCustomArgsRaw = "";
        public string ObtainCustomArgsRaw
        {
            get => _obtainCustomArgsRaw;
            set => SetProperty(ref _obtainCustomArgsRaw, value ?? "");
        }

        private ObservableCollection<int> _classes = new();
        /// <summary>Collection is settable so parsers can replace it (avoids CS0200).</summary>
        public ObservableCollection<int> Classes
        {
            get => _classes;
            set => SetProperty(ref _classes, value ?? new ObservableCollection<int>());
        }

        private int _qualifyPos;   // default 0
        public int QualifyPos
        {
            get => _qualifyPos;
            set => SetProperty(ref _qualifyPos, value);
        }

        private int _unlockPos;
        public int UnlockPos
        {
            get => _unlockPos;
            set => SetProperty(ref _unlockPos, value);
        }

        private int _numCars = 8;
        public int NumCars
        {
            get => _numCars;
            set => SetProperty(ref _numCars, value);
        }

        private int _numTries = 3;
        public int NumTries
        {
            get => _numTries;
            set => SetProperty(ref _numTries, value);
        }

        private List<int> _points = new() { 10, 8, 6, 5, 4, 3, 2, 1 };
        /// <summary>List is settable to fire a single PropertyChanged on bulk updates.</summary>
        public List<int> Points
        {
            get => _points;
            set => SetProperty(ref _points, value ?? new List<int>());
        }

        private ObservableCollection<string> _opponents = new();
        public ObservableCollection<string> Opponents
        {
            get => _opponents;
            set => SetProperty(ref _opponents, value ?? new ObservableCollection<string>());
        }

        private ObservableCollection<Stage> _stages = new();
        public ObservableCollection<Stage> Stages
        {
            get => _stages;
            set => SetProperty(ref _stages, value ?? new ObservableCollection<Stage>());
        }

        // Randomize player's car (affects DLL mod at runtime)
        private bool _randomCars;
        public bool RandomCars
        {
            get => _randomCars;
            set => SetProperty(ref _randomCars, value);
        }

        // NEW: RandomCars source flags (default: all true)
        private bool _randomCarsStock = true;
        public bool RandomCarsStock
        {
            get => _randomCarsStock;
            set => SetProperty(ref _randomCarsStock, value);
        }

        private bool _randomCarsMain = true;
        public bool RandomCarsMain
        {
            get => _randomCarsMain;
            set => SetProperty(ref _randomCarsMain, value);
        }

        private bool _randomCarsBonus = false;
        public bool RandomCarsBonus
        {
            get => _randomCarsBonus;
            set => SetProperty(ref _randomCarsBonus, value);
        }

        // Full Joker line as written in the cup, e.g. "Joker 0" or "Joker 1 toyeca"
        // Keep it as a single line to preserve any explicit car folder the user types.
        private string _jokerLine = "Joker 0";
        public string JokerLine
        {
            get => _jokerLine;
            set => SetProperty(ref _jokerLine, string.IsNullOrWhiteSpace(value) ? "Joker 0" : value);
        }

        // ---------------- Nested Stage ----------------

        public class Stage : INotifyPropertyChanged
        {
            public event PropertyChangedEventHandler? PropertyChanged;
            protected void OnPropertyChanged([CallerMemberName] string? prop = null)
                => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));

            protected bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? prop = null)
            {
                if (EqualityComparer<T>.Default.Equals(field, value)) return false;
                field = value;
                OnPropertyChanged(prop);
                return true;
            }

            private string _trackKey = "";
            public string TrackKey
            {
                get => _trackKey;
                set => SetProperty(ref _trackKey, value ?? "");
            }

            private int _laps = 3;
            public int Laps
            {
                get => _laps;
                set => SetProperty(ref _laps, value);
            }

            private bool _mirrored;
            public bool Mirrored
            {
                get => _mirrored;
                set => SetProperty(ref _mirrored, value);
            }

            private bool _reversed;
            public bool Reversed
            {
                get => _reversed;
                set => SetProperty(ref _reversed, value);
            }
        }

        // ---------------- Copy / helpers ----------------

        public void CopyFrom(CupModel other)
        {
            if (other is null) return;

            Name = other.Name;
            Difficulty = other.Difficulty;
            Obtain = other.Obtain;
            ObtainCustomMode = other.ObtainCustomMode;
            ObtainCustomArgsRaw = other.ObtainCustomArgsRaw;

            NumCars = other.NumCars;
            NumTries = other.NumTries;

            QualifyPos = other.QualifyPos;
            UnlockPos = other.UnlockPos;

            // NEW: carry over RandomCars + JokerLine
            RandomCars = other.RandomCars;
            JokerLine = other.JokerLine;

            Points = other.Points != null ? new List<int>(other.Points) : new List<int>();

            Classes = other.Classes != null ? new ObservableCollection<int>(other.Classes)
                                            : new ObservableCollection<int>();
            Opponents = other.Opponents != null ? new ObservableCollection<string>(other.Opponents)
                                                : new ObservableCollection<string>();

            var newStages = new ObservableCollection<Stage>();
            foreach (var s in other.Stages)
            {
                newStages.Add(new Stage
                {
                    TrackKey = s.TrackKey,
                    Laps = s.Laps,
                    Mirrored = s.Mirrored,
                    Reversed = s.Reversed
                });
            }
            Stages = newStages;
        }

        // Convenience for IO:
        public List<int> GetClassesAsList() => new(Classes);

        public void SetOpponentsFromList(IEnumerable<string>? src)
        {
            Opponents = src is null
                ? new ObservableCollection<string>()
                : new ObservableCollection<string>(src);
        }

        public void SetClassesFromList(IEnumerable<int>? src)
        {
            Classes = src is null
                ? new ObservableCollection<int>()
                : new ObservableCollection<int>(src);
        }
    }
}
