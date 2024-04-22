using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime;


class Program
{
    static int totalEntries = 0;
    static async Task Main(string[] args)
    {
        // // Set the large object heap compaction mode
        // GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;

        // // Set the maximum heap size to 500MB
        // const long maxHeapSize = 500L * 1024 * 1024;

        // // Set latency mode to LowLatency to limit GC pauses
        // GCSettings.LatencyMode = GCLatencyMode.LowLatency;

        // Start monitoring memory usage
        long startMemory = GC.GetTotalMemory(true);


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
        

        try
        {    
            var lastCompletedAt = await apiService.GetLastCompletedReportDateTime(secureUrlAuthority, httpClient, reportID, logger);
            await apiService.DownloadReport(secureUrlAuthority, httpClient, reportID ,"/Users/alex.wang/workspace/test/runtime-report-generator/test.csv", logger);
            // Dictionary<CompositeKey, System.Collections.Generic.List<System.Collections.Generic.Dictionary<string, string>>> vulnerabilityDictionary;
            int totalRuntimeEntries = 0;
            string filePath = "/Users/alex.wang/workspace/test/runtime-report-generator/test.csv";
            Dictionary<CompositeKey, List<Dictionary<string, string>>> vulnerabilityDictionary  = await ProcessCSV(filePath, logger);
            // List<Dictionary<string, string>> matchedVulnsList = new List<Dictionary<string, string>>();
        
            

            logger.LogInformation("Beginning matching process...");


            List<RuntimeResultInfo> runtimeResults = new List<RuntimeResultInfo>();
            runtimeResults = await apiService.GetRuntimeWorkloadScanResultsList(secureUrlAuthority, httpClient, logger);
            // List<Dictionary<string, string>> matchedVulnsList = new List<Dictionary<string, string>>();
            int matchedCounter = 0;
            int counter = 0;
            // Open the StreamWriter outside the loop to avoid overwriting the file in each iteration
            using (StreamWriter writer = new StreamWriter(outputFileName))
            {
                // Writing headers
                writer.WriteLine(string.Join(",", vulnerabilityDictionary.Values.First().First().Keys));

                // Iterate through runtimeResults and perform matching
                foreach (var result in runtimeResults)
                {
                    counter++;
                    if (counter % 5000 == 0)
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
                        // Process matchingVulnerabilities directly and write to CSV
                        foreach (var vulnerability in matchingVulnerabilities)
                        {
                            // Writing values to CSV
                            writer.WriteLine(string.Join(",", vulnerability.Values));
                            matchedCounter++;
                        }
                        // Remove the key from the dictionary as it's processed
                        vulnerabilityDictionary.Remove(key);
                    }
                }
            }

            logger.LogInformation("Total runtime report entries: " + totalEntries);
            logger.LogInformation("Total entries for final report: " + matchedCounter);
            logger.LogInformation("Total inactive runtime entries trimmed: " + (totalEntries - matchedCounter));
            logger.LogInformation("Total assets scanned:  " + counter);

            if (lastCompletedAt.HasValue)
                logger.LogInformation($"Last completed report: {lastCompletedAt.Value} UTC");
            else
                logger.LogInformation("Failed to fetch the last completed report date.");

            stopwatch.Stop();
            TimeSpan runtime = stopwatch.Elapsed;
            logger.LogInformation("Total runtime of the script: " + runtime);
            logger.LogInformation("Runtime report generation completed...");
            // Stop monitoring memory usage
            long endMemory = GC.GetTotalMemory(true);
            long memoryUsed = endMemory - startMemory;
            logger.LogInformation($"Memory end used: {endMemory} bytes");
            logger.LogInformation($"Memory started used: {startMemory} bytes");
            logger.LogInformation($"Memory used: {memoryUsed} bytes");
            logger.LogInformation($"Memory used: {memoryUsed / (1024 * 1024 * 1024)} GB");
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

    static async Task<Dictionary<CompositeKey, List<Dictionary<string, string>>>> ProcessCSV(string filePath, ILogger logger)
    {
        // Dictionary to store unique string keys
        Dictionary<string, string> uniqueKeys = new Dictionary<string, string>();

        List<Dictionary<string, string>> vulnerabilities = new List<Dictionary<string, string>>();

        try
        {
            using (FileStream csvFileStream = File.OpenRead(filePath))
            using (StreamReader reader = new StreamReader(csvFileStream))
            {
                // Read the header line
                string headerLine = await reader.ReadLineAsync() ?? "";

                // Split headers and find column indexes
                string[] headers = headerLine.Split(',');

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
                    return null;
                }

                Dictionary<string, int> columnIndexMap = headers.Select((header, index) => new { Header = header, Index = index })
                    .ToDictionary(item => item.Header, item => item.Index);

                // Read data lines
                while (!reader.EndOfStream)
                {
                    var line = await reader.ReadLineAsync();
                    var values = line.Split(',');

                    var vulnerability = new Dictionary<string, string>();
                    foreach (var header in columnIndexMap.Keys)
                    {
                        if (columnIndexMap.TryGetValue(header, out int columnIndex) && columnIndex < values.Length)
                        {
                            // Reuse existing key or add to the uniqueKeys dictionary
                            string key = GetOrCreateKey(uniqueKeys, values[columnIndex]);
                            vulnerability[header] = key;
                        }
                        else
                        {
                            vulnerability[header] = ""; // default value if empty
                        }
                    }
                    vulnerabilities.Add(vulnerability);
                    totalEntries++;
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError($"An error occurred while processing CSV file: {ex.Message}");
            return null;
        }

        // Group vulnerabilities by composite key
        var vulnerabilityDictionary = vulnerabilities
            .GroupBy(v => new CompositeKey
            {
                K8SClusterName = GetOrCreateKey(uniqueKeys, v["K8S cluster name"]),
                K8SNamespaceName = GetOrCreateKey(uniqueKeys, v["K8S namespace name"]),
                K8SWorkloadType = GetOrCreateKey(uniqueKeys, v["K8S workload type"]),
                K8SWorkloadName = GetOrCreateKey(uniqueKeys, v["K8S workload name"]),
                K8SContainerName = GetOrCreateKey(uniqueKeys, v["K8S container name"]),
                Image = GetOrCreateKey(uniqueKeys, v["Image"]),
                ImageID = GetOrCreateKey(uniqueKeys, v["Image ID"])
            })
            .ToDictionary(g => g.Key, g => g.ToList());

        return vulnerabilityDictionary;
    }

    // Helper method to get or create a key in the uniqueKeys dictionary
    private static string GetOrCreateKey(Dictionary<string, string> uniqueKeys, string value)
    {
        if (!uniqueKeys.TryGetValue(value, out string key))
        {
            key = value;
            uniqueKeys.Add(value, key);
        }
        return key;
    }
}


