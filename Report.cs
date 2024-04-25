public class Report
{
    public string? id { get; set; }
    public string? scheduleId { get; set; }
    public string? status { get; set; }
    public string? reportType { get; set; }
    public string? reportFormat { get; set; }
    public string? compression { get; set; }
    public string? entityType { get; set; }
    public DateTime? scheduledAt { get; set; }
    public DateTime? startedAt { get; set; }
    public DateTime? completedAt { get; set; }
    public DateTime? reportLastCompletedAt { get; set; }
}