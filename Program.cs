using Newtonsoft.Json;
using System;
using Microsoft.Extensions.Logging;

class Program
{
    static async Task Main(string[] args)
    {

        using ILoggerFactory factory = LoggerFactory.Create(builder => builder.AddConsole());
        ILogger logger = factory.CreateLogger("Program");

        // Parse the command line arguments
        var (secureUrlAuthority, apiToken, outputFileName, reportID) = ParseArgs(args, logger);

        // Add the authentication header
        var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiToken);

        ApiService apiService = new ApiService();
        

        try{
            Stream csvFileStream = await apiService.DownloadReportAsync(secureUrlAuthority, httpClient, reportID, logger);
            List<RuntimeResultInfo> runtimeResults = await apiService.GetRuntimeWorkloadScanResultsList(secureUrlAuthority, httpClient, logger);

            if (csvFileStream != null)
            {
                logger.LogInformation("Beginning matching process...");
                List<Vulnerability> vulnerabilities = new List<Vulnerability>();

                using (StreamReader reader = new StreamReader(csvFileStream))
                {
                    // Skip the header line
                    reader.ReadLine();

                    while (!reader.EndOfStream)
                    {
                        var line = reader.ReadLine();
                        var values = line.Split(',');

                        var vulnerability = new Vulnerability
                        {
                            VulnerabilityID = values[0],
                            Severity = values[1],
                            PackageName = values[2],
                            PackageVersion = values[3],
                            PackageType = values[4],
                            PackagePath = values[5],
                            Image = values[6],
                            OSName = values[7],
                            CVSSVersion = values[8],
                            CVSSScore = values[9],
                            CVSSVector = values[10],
                            VulnLink = values[11],
                            VulnPublishDate = values[12],
                            VulnFixDate = values[13],
                            FixVersion = values[14],
                            PublicExploit = values[15],
                            K8SClusterName = values[16],
                            K8SNamespaceName = values[17],
                            K8SWorkloadType = values[18],
                            K8SWorkloadName = values[19],
                            K8SContainerName = values[20],
                            ImageID = values[21],
                            K8SPODCount = values[22],
                            PackageSuggestedFix = values[23],
                            InUse = values[24],
                            RiskAccepted = values[25]
                        };
                        vulnerabilities.Add(vulnerability);
                    }
                }

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
                else
                {
                    logger.LogInformation("No duplicates found.");
                }

                List<RuntimeResultInfo> unmatchedRuntimeResults = new List<RuntimeResultInfo>(runtimeResults);
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
                        writer.WriteLine($"{vulnerability.VulnerabilityID},{vulnerability.Severity},{vulnerability.PackageName},{vulnerability.PackageVersion},{vulnerability.PackageType},{vulnerability.PackagePath},{vulnerability.Image},{vulnerability.OSName},{vulnerability.CVSSVersion},{vulnerability.CVSSScore},{vulnerability.CVSSVector},{vulnerability.VulnLink},{vulnerability.VulnPublishDate},{vulnerability.VulnFixDate},{vulnerability.FixVersion},{vulnerability.PublicExploit},{vulnerability.K8SClusterName},{vulnerability.K8SNamespaceName},{vulnerability.K8SWorkloadType},{vulnerability.K8SWorkloadName},{vulnerability.K8SContainerName},{vulnerability.ImageID},{vulnerability.K8SPODCount},{vulnerability.PackageSuggestedFix},{vulnerability.InUse},{vulnerability.RiskAccepted}");
                    }

                    if (matchingVulnerabilities.Count > 0){
                        unmatchedRuntimeResults.Remove(result);
                    }
                }

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

                // using (StreamWriter reportUnmatchedWriter = new StreamWriter("reportingMissing_vulnerabilities.csv"))
                // {
                //     foreach (var unmatchedVulnerability in vulnerabilities)
                //     {
                //         reportUnmatchedWriter.WriteLine($"{unmatchedVulnerability.VulnerabilityID},{unmatchedVulnerability.Severity},{unmatchedVulnerability.PackageName},{unmatchedVulnerability.PackageVersion},{unmatchedVulnerability.PackageType},{unmatchedVulnerability.PackagePath},{unmatchedVulnerability.Image},{unmatchedVulnerability.OSName},{unmatchedVulnerability.CVSSVersion},{unmatchedVulnerability.CVSSScore},{unmatchedVulnerability.CVSSVector},{unmatchedVulnerability.VulnLink},{unmatchedVulnerability.VulnPublishDate},{unmatchedVulnerability.VulnFixDate},{unmatchedVulnerability.FixVersion},{unmatchedVulnerability.PublicExploit},{unmatchedVulnerability.K8SClusterName},{unmatchedVulnerability.K8SNamespaceName},{unmatchedVulnerability.K8SWorkloadType},{unmatchedVulnerability.K8SWorkloadName},{unmatchedVulnerability.K8SContainerName},{unmatchedVulnerability.ImageID},{unmatchedVulnerability.K8SPODCount},{unmatchedVulnerability.PackageSuggestedFix},{unmatchedVulnerability.InUse},{unmatchedVulnerability.RiskAccepted}");
                //     }
                // }


                logger.LogInformation("Filtered lines have been written to the output file.");
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

