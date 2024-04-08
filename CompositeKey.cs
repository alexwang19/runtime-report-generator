public class CompositeKey
{
    public string? K8SClusterName { get; set; }
    public string? K8SNamespaceName { get; set; }
    public string? K8SWorkloadType { get; set; }
    public string? K8SWorkloadName { get; set; }
    public string? K8SContainerName { get; set; }
    public string? Image { get; set; }
    public string? ImageID { get; set; }

    // Override GetHashCode and Equals methods to ensure correct comparison and hashing
    public override int GetHashCode()
    {
        unchecked
        {
            // Choosing prime numbers to reduce potential collisions when generating hash codes
            int hash = 17;
            hash = hash * 23 + (K8SClusterName?.GetHashCode() ?? 0);
            hash = hash * 23 + (K8SNamespaceName?.GetHashCode() ?? 0);
            hash = hash * 23 + (K8SWorkloadType?.GetHashCode() ?? 0);
            hash = hash * 23 + (K8SWorkloadName?.GetHashCode() ?? 0);
            hash = hash * 23 + (K8SContainerName?.GetHashCode() ?? 0);
            hash = hash * 23 + (Image?.GetHashCode() ?? 0);
            hash = hash * 23 + (ImageID?.GetHashCode() ?? 0);
            return hash;
        }
    }

    public override bool Equals(object? obj)
    {
        if (!(obj is CompositeKey))
            return false;

        var other = (CompositeKey)obj;
        return K8SClusterName == other.K8SClusterName &&
               K8SNamespaceName == other.K8SNamespaceName &&
               K8SWorkloadType == other.K8SWorkloadType &&
               K8SWorkloadName == other.K8SWorkloadName &&
               K8SContainerName == other.K8SContainerName &&
               Image == other.Image &&
               ImageID == other.ImageID;
    }
}