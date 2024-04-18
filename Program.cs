using Newtonsoft.Json;
using System;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Reflection;


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
            
            if (csvFileStream != null)
            {
                var lastCompletedAt = await apiService.GetLastCompletedReportDateTime(secureUrlAuthority, httpClient, reportID, logger);

                List<Dictionary<string, string>> vulnerabilities = new List<Dictionary<string, string>>();

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

                        var vulnerability = new Dictionary<string, string>();
                        foreach (var header in columnIndexMap.Keys)
                        {
                            if (columnIndexMap.TryGetValue(header, out int columnIndex) && columnIndex < values.Length)
                            {
                                vulnerability[header] = values[columnIndex];
                            }
                            else
                            {
                                vulnerability[header] = ""; // default value if empty
                            }
                        }
                        vulnerabilities.Add(vulnerability);
                    }
                }

                List<Dictionary<string, string>> matchedVulnsList = new List<Dictionary<string, string>>();

                int counter = 0;
                int totalRuntimeEntries = vulnerabilities.Count + 1;

                logger.LogInformation("Beginning matching process...");
                var vulnerabilityDictionary = vulnerabilities
                    .GroupBy(v => new CompositeKey
                    {
                        K8SClusterName = v["K8S cluster name"],
                        K8SNamespaceName = v["K8S namespace name"],
                        K8SWorkloadType = v["K8S workload type"],
                        K8SWorkloadName = v["K8S workload name"],
                        K8SContainerName = v["K8S container name"],
                        Image = v["Image"],
                        ImageID = v["Image ID"]
                    })
                    .ToDictionary(g => g.Key, g => g.ToList());


                // Iterate through runtimeResults and perform matching
                foreach (var result in runtimeResults)
                {
                    counter++;
                    if (counter % 1000 == 0)
                    {
                        logger.LogInformation("Processed this many entries: " + counter);
                    }

                    // Construct the composite key for the current result
                    var key = new CompositeKey
                    {
                        K8SClusterName = result.K8SClusterName,
                        K8SNamespaceName = result.K8SNamespaceName,
                        K8SWorkloadType = result.K8SWorkloadType,
                        K8SWorkloadName = result.K8SWorkloadName,
                        K8SContainerName = result.K8SContainerName,
                        Image = result.Image,
                        ImageID = result.ImageId
                    };

                    // Look up matching vulnerabilities from the dictionary
                    if (vulnerabilityDictionary.TryGetValue(key, out var matchingVulnerabilities))
                    {
                        // Process matchingVulnerabilities
                        foreach (var vulnerability in matchingVulnerabilities)
                        {
                            matchedVulnsList.Add(vulnerability); // Adding dictionary directly
                        }

                        // Remove matched vulnerabilities from the dictionary
                        // vulnerabilityDictionary.Remove(key);
                    }
                }

                using (StreamWriter writer = new StreamWriter(outputFileName))
                {
                    // Writing headers
                    writer.WriteLine(string.Join(",", matchedVulnsList[0].Keys));

                    // Writing data
                    foreach (var vulnerability in matchedVulnsList)
                    {
                        // Writing values
                        writer.WriteLine(string.Join(",", vulnerability.Values));
                    }
                }

                // Find duplicates
                var duplicates = runtimeResults
                    .GroupBy(r => new { r.K8SClusterName, r.K8SNamespaceName, r.K8SWorkloadType, r.K8SWorkloadName, r.K8SContainerName, r.Image })
                    .Where(g => g.Count() > 1)
                    .SelectMany(g => g);
        
                logger.LogInformation("Total workloads with identical runtime context: " + duplicates.Count());
                logger.LogInformation("Total runtime report entries: " + totalRuntimeEntries);
                logger.LogInformation("Total entries for final report: " + matchedVulnsList.Count);
                logger.LogInformation("Total inactive runtime entries trimmed: " + (totalRuntimeEntries - matchedVulnsList.Count));
                logger.LogInformation("Total assets scanned:  " + counter);

                if (lastCompletedAt.HasValue)
                    logger.LogInformation($"Last completed report: {lastCompletedAt.Value} UTC");
                else
                    logger.LogInformation("Failed to fetch the last completed report date.");

                stopwatch.Stop();
                TimeSpan runtime = stopwatch.Elapsed;
                logger.LogInformation("Total runtime of the script: " + runtime);
                logger.LogInformation("Runtime report generation completed...");
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

