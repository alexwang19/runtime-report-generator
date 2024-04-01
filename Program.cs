using Newtonsoft.Json;
using System;
using Microsoft.Extensions.Logging;
using System.Diagnostics;


class Program
{
    static async Task Main(string[] args)
    {

        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();

        using ILoggerFactory factory = LoggerFactory.Create(builder => builder.AddConsole());
        ILogger logger = factory.CreateLogger("Program");

        // Parse the command line arguments
        var (secureUrlAuthority, apiToken, outputFileName, reportID) = ParseArgs(args, logger);

        // Pass accessKey as environment variable
        // Return Code expected

        var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken);

        ApiService apiService = new ApiService();
        

        try{
            Stream csvFileStream = await apiService.DownloadReport(secureUrlAuthority, httpClient, reportID, logger);
            List<RuntimeResultInfo> runtimeResults = new List<RuntimeResultInfo>();
            // csvFileStream = new MemoryStream();
            
            if (csvFileStream != null)
            {
                var lastCompletedAt = await apiService.GetLastCompletedReportDateTime(secureUrlAuthority, httpClient, reportID, logger);
                if (lastCompletedAt.HasValue)
                    Console.WriteLine($"Last completed report: {lastCompletedAt.Value}");
                else
                    Console.WriteLine("Failed to fetch the last completed report date.");
                logger.LogInformation("Beginning matching process...");
                List<Vulnerability> vulnerabilities = new List<Vulnerability>();

                using (StreamReader reader = new StreamReader(csvFileStream))
                {
                    // Read the header line
                    string headerLine = await reader.ReadLineAsync() ?? "";

                    // Split headers and find column indexes
                    string[] headers = headerLine?.Split(',') ?? new string[0];

                    // Expected column names
                    string[] expectedColumns = {
                        "Vulnerability ID", "Severity", "Package name", "Package version", "Package type", "Package path", "Image", "OS Name",
                        "CVSS version", "CVSS score", "CVSS vector", "Vuln link", "Vuln Publish date", "Vuln Fix date", "Fix version",
                        "Public Exploit", "K8S cluster name", "K8S namespace name", "K8S workload type", "K8S workload name",
                        "K8S container name", "Image ID", "K8S POD count", "Package suggested fix", "In use", "Risk accepted",
                        "NVD Vuln Publish date"
                    };

                    // Validate headers
                    if (!expectedColumns.All(header => headers.Contains(header)))
                    {
                        logger.LogError("CSV file does not contain all expected column headers.");
                        return;
                    }

                    runtimeResults = await apiService.GetRuntimeWorkloadScanResultsList(secureUrlAuthority, httpClient, logger);

                    Dictionary<string, int> columnIndexMap = new Dictionary<string, int>();
                    for (int i = 0; i < headers.Length; i++)
                    {
                        columnIndexMap.Add(headers[i], i);
                    }


                    // Read data lines
                    while (!reader.EndOfStream)
                    {
                        var line = await reader.ReadLineAsync();
                        var values = line?.Split(',') ?? new string[0];

                        var vulnerability = new Vulnerability
                        {
                            VulnerabilityID = values[columnIndexMap["Vulnerability ID"]],
                            Severity = values[columnIndexMap["Severity"]],
                            PackageName = values[columnIndexMap["Package name"]],
                            PackageVersion = values[columnIndexMap["Package version"]],
                            PackageType = values[columnIndexMap["Package type"]],
                            PackagePath = values[columnIndexMap["Package path"]],
                            Image = values[columnIndexMap["Image"]],
                            OSName = values[columnIndexMap["OS Name"]],
                            CVSSVersion = values[columnIndexMap["CVSS version"]],
                            CVSSScore = values[columnIndexMap["CVSS score"]],
                            CVSSVector = values[columnIndexMap["CVSS vector"]],
                            VulnLink = values[columnIndexMap["Vuln link"]],
                            VulnPublishDate = values[columnIndexMap["Vuln Publish date"]],
                            VulnFixDate = values[columnIndexMap["Vuln Fix date"]],
                            FixVersion = values[columnIndexMap["Fix version"]],
                            PublicExploit = values[columnIndexMap["Public Exploit"]],
                            K8SClusterName = values[columnIndexMap["K8S cluster name"]],
                            K8SNamespaceName = values[columnIndexMap["K8S namespace name"]],
                            K8SWorkloadType = values[columnIndexMap["K8S workload type"]],
                            K8SWorkloadName = values[columnIndexMap["K8S workload name"]],
                            K8SContainerName = values[columnIndexMap["K8S container name"]],
                            ImageID = values[columnIndexMap["Image ID"]],
                            K8SPODCount = values[columnIndexMap["K8S POD count"]],
                            PackageSuggestedFix = values[columnIndexMap["Package suggested fix"]],
                            InUse = values[columnIndexMap["In use"]],
                            RiskAccepted = values[columnIndexMap["Risk accepted"]]
                        };
                        vulnerabilities.Add(vulnerability);
                    }
                }

                List<RuntimeResultInfo> unmatchedRuntimeResults = new List<RuntimeResultInfo>(runtimeResults);
                List<Vulnerability> unmatchedReportResults = new List<Vulnerability>(vulnerabilities);
                var writer = new StreamWriter(outputFileName);
                int counter = 0;

                foreach (var result in runtimeResults){
                    counter += 1;
                    if (counter % 1000 == 0)
                    {
                        logger.LogInformation("Processed this many entries: " + counter);
                    }

                    // logger.LogInformation("Runtime data: " + result.K8SClusterName + "," + result.K8SNamespaceName + "," + result.K8SWorkloadType + "," + result.K8SWorkloadName + "," + result.K8SContainerName + "," + result.Image);
                    // foreach (var vulnerability in vulnerabilities){
                    //     if (vulnerability.K8SClusterName == result.K8SClusterName &&
                    //     vulnerability.K8SNamespaceName == result.K8SNamespaceName &&
                    //     vulnerability.K8SWorkloadType == result.K8SWorkloadType &&
                    //     vulnerability.K8SWorkloadName == result.K8SWorkloadName &&
                    //     vulnerability.K8SContainerName == result.K8SContainerName &&
                    //     vulnerability.Image == result.Image){
                    //         matchingVulnerabilities.Add(vulnerability);
                    //         writer.WriteLine($"{vulnerability.VulnerabilityID},{vulnerability.Severity},{vulnerability.PackageName},{vulnerability.PackageVersion},{vulnerability.PackageType},{vulnerability.PackagePath},{vulnerability.Image},{vulnerability.OSName},{vulnerability.CVSSVersion},{vulnerability.CVSSScore},{vulnerability.CVSSVector},{vulnerability.VulnLink},{vulnerability.VulnPublishDate},{vulnerability.VulnFixDate},{vulnerability.FixVersion},{vulnerability.PublicExploit},{vulnerability.K8SClusterName},{vulnerability.K8SNamespaceName},{vulnerability.K8SWorkloadType},{vulnerability.K8SWorkloadName},{vulnerability.K8SContainerName},{vulnerability.ImageID},{vulnerability.K8SPODCount},{vulnerability.PackageSuggestedFix},{vulnerability.InUse},{vulnerability.RiskAccepted}");
                    //         unmatchedRuntimeResults.Remove(result);
                    //     }
                    // }

                    var matchingVulnerabilities = vulnerabilities.Where(v =>
                        v.K8SClusterName == result.K8SClusterName &&
                        v.K8SNamespaceName == result.K8SNamespaceName &&
                        v.K8SWorkloadType == result.K8SWorkloadType &&
                        v.K8SWorkloadName == result.K8SWorkloadName &&
                        v.K8SContainerName == result.K8SContainerName &&
                        v.Image == result.Image &&
                        v.ImageID == result.ImageId
                    ).ToList();;

                    // if (matchingVulnerabilities.Any())
                    // {
                    //     foreach (var vulnerability in matchingVulnerabilities)
                    //     {
                    //         // writer.WriteLine($"{vulnerability.VulnerabilityID},{vulnerability.Severity},{vulnerability.PackageName},{vulnerability.PackageVersion},{vulnerability.PackageType},{vulnerability.PackagePath},{vulnerability.Image},{vulnerability.OSName},{vulnerability.CVSSVersion},{vulnerability.CVSSScore},{vulnerability.CVSSVector},{vulnerability.VulnLink},{vulnerability.VulnPublishDate},{vulnerability.VulnFixDate},{vulnerability.FixVersion},{vulnerability.PublicExploit},{vulnerability.K8SClusterName},{vulnerability.K8SNamespaceName},{vulnerability.K8SWorkloadType},{vulnerability.K8SWorkloadName},{vulnerability.K8SContainerName},{vulnerability.ImageID},{vulnerability.K8SPODCount},{vulnerability.PackageSuggestedFix},{vulnerability.InUse},{vulnerability.RiskAccepted}");
                    //         vulnerabilities.Remove(vulnerability); // Remove matched vulnerability
                    //     }
                    //     unmatchedRuntimeResults.Remove(result); // Remove matched runtime result
                    // }

                    foreach (var vulnerability in matchingVulnerabilities)
                    {
                        unmatchedReportResults.Remove(vulnerability);
                        writer.WriteLine($"{vulnerability.VulnerabilityID},{vulnerability.Severity},{vulnerability.PackageName},{vulnerability.PackageVersion},{vulnerability.PackageType},{vulnerability.PackagePath},{vulnerability.Image},{vulnerability.OSName},{vulnerability.CVSSVersion},{vulnerability.CVSSScore},{vulnerability.CVSSVector},{vulnerability.VulnLink},{vulnerability.VulnPublishDate},{vulnerability.VulnFixDate},{vulnerability.FixVersion},{vulnerability.PublicExploit},{vulnerability.K8SClusterName},{vulnerability.K8SNamespaceName},{vulnerability.K8SWorkloadType},{vulnerability.K8SWorkloadName},{vulnerability.K8SContainerName},{vulnerability.ImageID},{vulnerability.K8SPODCount},{vulnerability.PackageSuggestedFix},{vulnerability.InUse},{vulnerability.RiskAccepted}");
                    }

                    if (matchingVulnerabilities.Count > 0){
                        unmatchedRuntimeResults.Remove(result);
                    }
                }

                logger.LogInformation("Total running workloads processed: " + counter);

                // Find duplicates
                var duplicates = runtimeResults
                    .GroupBy(r => new { r.K8SClusterName, r.K8SNamespaceName, r.K8SWorkloadType, r.K8SWorkloadName, r.K8SContainerName, r.Image })
                    .Where(g => g.Count() > 1)
                    .SelectMany(g => g);
                
                if (duplicates.Any())
                {
                    foreach (var duplicate in duplicates)
                    {
                        logger.LogInformation($"Duplicate found: {duplicate.K8SClusterName}, {duplicate.K8SNamespaceName}, {duplicate.K8SWorkloadType}, {duplicate.K8SWorkloadName}, {duplicate.K8SContainerName}, {duplicate.Image}");
                    }
                }

                int totalDuplicatesCount = duplicates.Count();
                logger.LogInformation("Total count of duplicates found: " + totalDuplicatesCount);

                // foreach (var vulnerability in matchingVulnerabilities)
                // {
                //     // writer.WriteLine($"{vulnerability.VulnerabilityID},{vulnerability.Severity},{vulnerability.PackageName},{vulnerability.PackageVersion},{vulnerability.PackageType},{vulnerability.PackagePath},{vulnerability.Image},{vulnerability.OSName},{vulnerability.CVSSVersion},{vulnerability.CVSSScore},{vulnerability.CVSSVector},{vulnerability.VulnLink},{vulnerability.VulnPublishDate},{vulnerability.VulnFixDate},{vulnerability.FixVersion},{vulnerability.PublicExploit},{vulnerability.K8SClusterName},{vulnerability.K8SNamespaceName},{vulnerability.K8SWorkloadType},{vulnerability.K8SWorkloadName},{vulnerability.K8SContainerName},{vulnerability.ImageID},{vulnerability.K8SPODCount},{vulnerability.PackageSuggestedFix},{vulnerability.InUse},{vulnerability.RiskAccepted}");
                //     vulnerabilities.Remove(vulnerability); // Remove matched vulnerability
                // }

                    // Output remaining vulnerabilities (not matched to any runtime result)
                using (StreamWriter unmatchedWriter = new StreamWriter("unmatched_vulnerabilities.csv"))
                {
                    foreach (var unmatchedResult in unmatchedRuntimeResults)
                    {
                        // Output the fields of unmatched runtime results
                        // Modify this according to the structure of your RuntimeResult class
                        unmatchedWriter.WriteLine($"UNMATCHED_RUNTIME_RESULT,{unmatchedResult.K8SClusterName},{unmatchedResult.K8SNamespaceName},{unmatchedResult.K8SWorkloadType},{unmatchedResult.K8SWorkloadName},{unmatchedResult.K8SContainerName},{unmatchedResult.Image}");
                    }
                }

                using (StreamWriter reportUnmatchedWriter = new StreamWriter("reportingMissing_vulnerabilities.csv"))
                {
                    foreach (var unmatchedVulnerability in unmatchedReportResults)
                    {
                        reportUnmatchedWriter.WriteLine($"{unmatchedVulnerability.VulnerabilityID},{unmatchedVulnerability.Severity},{unmatchedVulnerability.PackageName},{unmatchedVulnerability.PackageVersion},{unmatchedVulnerability.PackageType},{unmatchedVulnerability.PackagePath},{unmatchedVulnerability.Image},{unmatchedVulnerability.OSName},{unmatchedVulnerability.CVSSVersion},{unmatchedVulnerability.CVSSScore},{unmatchedVulnerability.CVSSVector},{unmatchedVulnerability.VulnLink},{unmatchedVulnerability.VulnPublishDate},{unmatchedVulnerability.VulnFixDate},{unmatchedVulnerability.FixVersion},{unmatchedVulnerability.PublicExploit},{unmatchedVulnerability.K8SClusterName},{unmatchedVulnerability.K8SNamespaceName},{unmatchedVulnerability.K8SWorkloadType},{unmatchedVulnerability.K8SWorkloadName},{unmatchedVulnerability.K8SContainerName},{unmatchedVulnerability.ImageID},{unmatchedVulnerability.K8SPODCount},{unmatchedVulnerability.PackageSuggestedFix},{unmatchedVulnerability.InUse},{unmatchedVulnerability.RiskAccepted}");
                    }
                }

                logger.LogInformation("Runtime report generation completed...");

                stopwatch.Stop();
                TimeSpan runtime = stopwatch.Elapsed;
                logger.LogInformation("Total runtime of the script: " + runtime);
            }
        }
        catch (Exception ex)
        {
            // Log the exception or perform any necessary cleanup
            // Exit the program
            logger.LogInformation($"Error: {ex.Message}");
            Environment.Exit(1);
        }
    }

    static (string secureUrlAuthority, string apiToken, string outputFileName, string reportID) ParseArgs(string[] args, ILogger logger)
    {
        if (args.Length < 4)
        {
            logger.LogInformation("Error: Not enough arguments provided.");
            Console.WriteLine("");
            Environment.Exit(1);
        }

        return (args[0], args[1], args[2], args[3]);
    }

}

