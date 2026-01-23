namespace CupGen.UI
{
    public class CarItem
    {
        public string Display { get; set; }
        public string FolderKey { get; set; }
        public string Category { get; set; }
        public string FullPath { get; set; }
        public string ParentFolder { get; set; }

        // NEW: Rating (0..5) + name
        public int Rating { get; set; }
        public string RatingName => Rating switch
        {
            0 => "Rookie",
            1 => "Amateur",
            2 => "Advanced",
            3 => "Semi-Pro",
            4 => "Pro",
            5 => "Super Pro",
            _ => "Unknown"
        };

        // Convenient one-line display
        public string RatingDisplay => RatingName == "Unknown"
            ? $"{Rating}"
            : $"{Rating} – {RatingName}";

        public string SortName => string.IsNullOrWhiteSpace(Display) ? (FolderKey ?? "") : Display;

    }
}
