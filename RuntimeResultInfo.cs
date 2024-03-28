using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

public class RuntimeResultInfo
{
    public string? K8SClusterName { get; set; }
    public string? K8SNamespaceName { get; set; }
    public string? K8SWorkloadType { get; set; }
    public string? K8SWorkloadName { get; set; }
    public string? K8SContainerName { get; set; }
    public string? Image { get; set; }
    public string? ImageId { get; set; }
}
