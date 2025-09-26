using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using CupGenerator.Models;

namespace CupGen.UI.Services
{
    public static class CupFileIO
    {
        // ----------------- helpers -----------------
        private static (int? mode, string argsRaw) ParseObtainCustom(string val)
        {
            var s = (val ?? string.Empty).Trim();   // defensive
            if (s.Length == 0) return (null, "");

            // split first token (mode) and the rest (args)
            int space = s.IndexOfAny(new[] { ' ', '\t' });
            if (space < 0)
            {
                if (int.TryParse(s, out var modeParsed)) return (modeParsed, "");
                return (null, s); // only-args (unlikely)
            }

            var first = s.Substring(0, space).Trim();
            var rest = s.Substring(space).Trim();

            int? mode = null;
            if (int.TryParse(first, out var modeParsed2)) mode = modeParsed2;

            return (mode, rest);
        }

        private static int ParseI(string s)
        {
            int n; return int.TryParse((s ?? "").Trim(), out n) ? n : 0;
        }

        private static bool TrySplitKeyVal(string line, out string keyLower, out string val)
        {
            keyLower = null; val = null;
            if (string.IsNullOrWhiteSpace(line)) return false;

            // strip trailing comment
            var sc = line.IndexOf(';');
            if (sc >= 0) line = line.Substring(0, sc);
            line = line.Trim();
            if (line.Length == 0) return false;

            int eq = line.IndexOf('=');
            if (eq >= 0)
            {
                keyLower = line.Substring(0, eq).Trim().ToLowerInvariant();
                val = line.Substring(eq + 1).Trim();
                return keyLower.Length > 0;
            }

            var parts = line.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return false;

            keyLower = parts[0].Trim().ToLowerInvariant();
            val = parts[1].Trim();
            return keyLower.Length > 0;
        }

        private static List<int> ParseIntListOrSingle(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return new List<int>();
            if (input.Contains(","))
                return input.Split(',').Select(s => ParseI(s)).ToList();
            return input.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(ParseI).ToList();
        }

        // Classes can be "7,0,0,0,0,0" or "7 0 0 0 0 0"
        private static List<int> ParseClasses(string val)
        {
            var list = ParseIntListOrSingle(val);
            // keep as-is; RVGL typically expects 6 values, but don’t force it
            return list;
        }

        // ----------------- LOAD -----------------
        public static CupModel Load(string path)
        {
            var cup = new CupModel();
            if (!File.Exists(path)) return cup;

            foreach (var raw in File.ReadAllLines(path))
            {
                // strip trailing ';' comments and trim once
                var line = raw;
                var sc = line.IndexOf(';');
                if (sc >= 0) line = line.Substring(0, sc);
                line = line.Trim();
                if (line.Length == 0) continue;

                // General keys
                string key, val;
                if (!TrySplitKeyVal(line, out key, out val)) continue;

                switch (key)
                {
                    case "name": cup.Name = (val ?? "").Trim().Trim('"'); break;
                    case "difficulty": cup.Difficulty = ParseI(val); break;
                    case "obtain": cup.Obtain = ParseI(val); break;
                    case "numcars": cup.NumCars = ParseI(val); break;
                    case "numtries": cup.NumTries = ParseI(val); break;

                    case "qualifypos":
                        cup.QualifyPos = ParseI(val);
                        break;

                    case "unlockpos":
                        cup.UnlockPos = ParseI(val);
                        break;

                    case "obtaincustom":
                        {
                            var (mode, argsRaw) = ParseObtainCustom(val);
                            if (mode.HasValue) cup.ObtainCustomMode = mode.Value;
                            cup.ObtainCustomArgsRaw = argsRaw;   // may be empty for mode 0
                            break;
                        }

                    case "randomcars":
                        {
                            // Accept: "0" or "1 [stock] [main] [bonus]"
                            var v = (val ?? "").Trim();
                            if (string.IsNullOrEmpty(v))
                            {
                                cup.RandomCars = false;
                                break;
                            }

                            var toks = v.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            int n = 0;
                            int.TryParse(toks[0], out n);
                            cup.RandomCars = (n != 0);

                            // defaults if not specified: all true
                            bool wantStock = true, wantMain = true, wantBonus = true;

                            if (toks.Length > 1)
                            {
                                // If any token beyond the first exists, default off then enable listed ones.
                                wantStock = wantMain = wantBonus = false;
                                for (int i = 1; i < toks.Length; i++)
                                {
                                    var t = toks[i].Trim().ToLowerInvariant();
                                    if (t == "stock") wantStock = true;
                                    else if (t == "main") wantMain = true;
                                    else if (t == "bonus") wantBonus = true;
                                }
                            }

                            cup.RandomCarsStock = wantStock;
                            cup.RandomCarsMain = wantMain;
                            cup.RandomCarsBonus = wantBonus;
                            break;
                        }

                    case "joker":
                        {
                            var rest = (val ?? "").Trim();
                            // Preserve full rest of the line as-is
                            cup.JokerLine = string.IsNullOrWhiteSpace(rest) ? "Joker 0" : "Joker " + rest;
                            break;
                        }

                    case "classes":
                        {
                            // ParseClasses can return IEnumerable<int> or List<int>; both are fine
                            var parsed = ParseClasses(val);
                            cup.SetClassesFromList(parsed);
                            break;
                        }

                    case "points":
                        cup.Points = ParseIntListOrSingle(val);  // stays List<int>, OK
                        break;

                    case "opponents":
                        {
                            var oppList = (val ?? "")
                                .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                                .Select(s => s.Trim())
                                .Where(s => s.Length > 0);
                            cup.SetOpponentsFromList(oppList);
                            break;
                        }

                    case "stage":
                        {
                            var toks = (val ?? "")
                                       .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (toks.Length >= 4)
                            {
                                // allow with or without index token
                                int idxMaybe;
                                string track;
                                int laps; bool mirrored = false, reversed = false;

                                if (int.TryParse(toks[0], out idxMaybe) && toks.Length >= 5)
                                {
                                    track = toks[1];
                                    laps = ParseI(toks[2]);
                                    bool.TryParse(toks[3], out mirrored);
                                    bool.TryParse(toks[4], out reversed);
                                }
                                else
                                {
                                    track = toks[0];
                                    laps = ParseI(toks[1]);
                                    bool.TryParse(toks[2], out mirrored);
                                    bool.TryParse(toks[3], out reversed);
                                }

                                cup.Stages.Add(new CupModel.Stage
                                {
                                    TrackKey = track,
                                    Laps = Math.Max(1, laps),
                                    Mirrored = mirrored,
                                    Reversed = reversed
                                });
                            }
                            break;
                        }

                    default:
                        // ignore unknown keys
                        break;
                }
            }

            return cup;
        }

        // ----------------- SAVE / PREVIEW -----------------
        public static void Save(string path, CupModel c)
        {
            File.WriteAllText(path, FormatPreview(c), new UTF8Encoding(false));
        }

        public static string FormatPreview(CupModel c)
        {
            var w = new StringBuilder();

            w.AppendLine(";===============================================================================");
            w.AppendLine(";                                RVGL Cup File");
            w.AppendLine(";===============================================================================");

            w.AppendLine($"Name        \"{c.Name}\"");
            w.AppendLine($"Difficulty  {c.Difficulty}");
            w.AppendLine($"Obtain      {c.Obtain}");
            if (c.ObtainCustomMode != 0 || !string.IsNullOrWhiteSpace(c.ObtainCustomArgsRaw))
            {
                var args = string.IsNullOrWhiteSpace(c.ObtainCustomArgsRaw) ? "" : " " + c.ObtainCustomArgsRaw.Trim();
                w.AppendLine($"ObtainCustom {c.ObtainCustomMode}{args}");
            }
            w.AppendLine();

            w.AppendLine($"NumCars     {c.NumCars}  ; Number of cars [4 - 16]");
            w.AppendLine($"NumTries    {c.NumTries}  ; Number of retry attempts");

            if (c.QualifyPos != 0)
                w.AppendLine($"QualifyPos  {c.QualifyPos}");
            if (c.UnlockPos != 0)
                w.AppendLine($"UnlockPos   {c.UnlockPos}");
            w.AppendLine();

            // RandomCars + explicit source flags (always show)
            if (c.RandomCars)
            {
                var parts = new List<string> { "RandomCars  1" };

                if (c.RandomCarsStock) parts.Add("stock");
                if (c.RandomCarsMain) parts.Add("main");
                if (c.RandomCarsBonus) parts.Add("bonus");

                w.AppendLine(string.Join(" ", parts));
            }

            // NEW: Joker – print only when non-zero; accept either "Joker 1 car" or "1 car"
            if (!string.IsNullOrWhiteSpace(c.JokerLine))
            {
                var jl = c.JokerLine.Trim();

                // Extract the part after "Joker"
                string rest = jl.StartsWith("Joker", StringComparison.OrdinalIgnoreCase)
                    ? jl.Substring(5).Trim()
                    : jl;

                // If empty or "0" -> skip entirely
                if (!string.IsNullOrWhiteSpace(rest) && !rest.Equals("0", StringComparison.OrdinalIgnoreCase))
                {
                    // Normalize to "Joker <rest>"
                    w.AppendLine("Joker " + rest);
                }
            }

            if (c.Classes != null && c.Classes.Count > 0)
                w.AppendLine($"Classes     {string.Join(",", c.Classes)}       ; Number of CPU cars picked from each rating");

            if (c.Opponents != null && c.Opponents.Count > 0)
                w.AppendLine($"Opponents   {string.Join(" ", c.Opponents)}");

            var pts = (c.Points ?? new List<int>()).Select(p => p.ToString()).ToArray();
            w.AppendLine($"Points      {string.Join(",", pts)}  ; Points obtained for each position");

            w.AppendLine();
            w.AppendLine();

            w.AppendLine("; Stages [0 - 15]: level laps mirrored reversed");
            w.AppendLine();

            for (int i = 0; i < (c.Stages?.Count ?? 0); i++)
            {
                var s = c.Stages[i];
                w.AppendLine(string.Format(
                    "STAGE {0,-5} {1} {2} {3} {4}",
                    i,
                    s.TrackKey,
                    s.Laps,
                    s.Mirrored.ToString().ToLowerInvariant(),
                    s.Reversed.ToString().ToLowerInvariant()
                ));
            }

            return w.ToString();
        }
    }
}
