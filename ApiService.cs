using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Net;
using Microsoft.Extensions.Logging;
using System.Diagnostics;


public class ApiService
{

    public async Task<bool> RunScheduledReport(string secureUrlAuthority, HttpClient httpClient, string scheduleId, ILogger logger)
    {
        try
        {
            // Check if there are any reports in progress
            var isInProgress = await AreReportsInProgress(secureUrlAuthority, httpClient, scheduleId);
            if (isInProgress)
            {
                throw new InvalidOperationException("Report generation is already in progress. Cannot initiate a new report.");
            }

            // Retrieve latest report prior to running scheduled report
            DateTime? lastCompletedReportTimestamp = await GetLastCompletedReportDateTime(secureUrlAuthority, httpClient, scheduleId, logger);

            // Make the POST request to generate the report
            var apiPath = $"api/scanning/reporting/v2/schedules/{scheduleId}/run";
            var apiUrl = $"https://{secureUrlAuthority}/{apiPath}";
            logger.LogInformation("Making API call to generate scheduled report...");

            HttpResponseMessage response = await httpClient.PostAsync(apiUrl, null);
            response.EnsureSuccessStatusCode();
            // Wait to allow report to be scheduled
            await Task.Delay(TimeSpan.FromSeconds(5));

            // Start timer to track elapsed time
            var timeout = TimeSpan.FromMinutes(30);
            var timer = new Stopwatch();
            timer.Start();

            // Check if there are any reports with status "progress" or "scheduled"
            while (true)
            {
                var reportsInProgress = await AreReportsInProgress(secureUrlAuthority, httpClient, scheduleId);
                if (!reportsInProgress)
                {
                    logger.LogInformation("No reports in progress or scheduled. Scheduled report generated successfully.");
                    DateTime? scheduledReportTimestamp = await GetLastCompletedReportDateTime(secureUrlAuthority, httpClient, scheduleId, logger);
                    bool isNewer = scheduledReportTimestamp > lastCompletedReportTimestamp;
                    timer.Stop();
                    return isNewer;
                }
                logger.LogInformation("Waiting for report generation to complete...");
                

                // Check if timeout is exceeded
                if (timer.Elapsed >= timeout)
                {
                    throw new InvalidOperationException("Timeout exceeded. Scheduled report could not be generated.");

                }

                // Wait for a while before checking again
                await Task.Delay(TimeSpan.FromSeconds(60));
            }
        }
        catch (Exception ex)
        {
            logger.LogError($"Error: {ex.Message}");
            Environment.Exit(1);
            return false;
        }
    }

    private async Task<bool> AreReportsInProgress(string secureUrlAuthority, HttpClient httpClient, string scheduleId)
    {
        var reportsApiPath = $"api/scanning/reporting/v2/schedules/{scheduleId}/reports";
        var reportsApiUrl = $"https://{secureUrlAuthority}/{reportsApiPath}";

        HttpResponseMessage reportsResponse = await httpClient.GetAsync(reportsApiUrl);
        reportsResponse.EnsureSuccessStatusCode();

        var reportsJson = await reportsResponse.Content.ReadAsStringAsync();
        var reports = JsonConvert.DeserializeObject<Report[]>(reportsJson);

        if (reports != null)
        {
            return reports.Any(r => r.status == "progress" || r.status == "scheduled");
        }

        return false;
    }

    public async Task<DateTime?> GetLastCompletedReportDateTime(string secureUrlAuthority, HttpClient httpClient, string reportID, ILogger logger)
    {
        try
        {
            var apiPath = $"api/scanning/reporting/v2/schedules/{reportID}";
            var apiUrl = $"https://{secureUrlAuthority}/{apiPath}";
            logger.LogInformation("Making API call to download last completed report...");
            
            HttpResponseMessage response = await httpClient.GetAsync(apiUrl);
            response.EnsureSuccessStatusCode();
            
            var json = await response.Content.ReadAsStringAsync();
            var report = JsonConvert.DeserializeObject<Report>(json);
            
            return report?.reportLastCompletedAt;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return null;
        }
    }

    public async Task<string> DownloadReport(string secureUrlAuthority, HttpClient httpClient, string reportID, string directoryPath, ILogger logger)
    {
        try
        {
            var apiPath = $"api/scanning/reporting/v2/schedules/{reportID}/download";
            var apiUrl = $"https://{secureUrlAuthority}/{apiPath}";
            logger.LogInformation("Making API call to download latest generated report...");
            
            HttpResponseMessage response = await httpClient.GetAsync(apiUrl);
            response.EnsureSuccessStatusCode(); // Ensure the HTTP request was successful

            logger.LogInformation("API call completed to retrieve report...");

            // Generate a unique filename
            string uniqueFileName = Path.GetFileNameWithoutExtension(Path.GetRandomFileName());
            string fileNameWithPrefix = $"sysdig_{uniqueFileName}.csv";
            string filePath = Path.Combine(directoryPath, fileNameWithPrefix);

            using (Stream contentStream = await response.Content.ReadAsStreamAsync())
            {
                using (Stream decompressedStream = DecompressStream(contentStream))
                {
                    using (FileStream fileStream = File.Create(filePath))
                    {
                        decompressedStream.CopyTo(fileStream);
                    }
                }
            }
            
            logger.LogInformation($"Report downloaded and saved to: {filePath}");
            return filePath; // Return the generated filename
        }
        catch (HttpRequestException ex)
        {
            logger.LogError($"HTTP Request Error: {ex.Message}");
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError($"Error: {ex.Message}");
            throw;
        }
    }

    private Stream DecompressStream(Stream inputStream)
    {
        var decompressionStream = new GZipStream(inputStream, CompressionMode.Decompress);
        var memoryStream = new MemoryStream();
        decompressionStream.CopyTo(memoryStream);
        memoryStream.Seek(0, SeekOrigin.Begin);
        return memoryStream;
    }


    public async Task<List<RuntimeResultInfo>> GetRuntimeWorkloadScanResultsList(string secureUrlAuthority, HttpClient httpClient, ILogger logger)
    {
        var limit = 1000;
        var cursor = "";
        var runtimeWorkloadScanResults = new List<RuntimeResultInfo>();

        const int maxRetries = 3;
        int retryCount = 0;

        try
        {
            while (true)
            {
                var apiPath = "api/scanning/runtime/v2/workflows/results";
                var apiUrl = $"https://{secureUrlAuthority}/{apiPath}?cursor={cursor}&filter=asset.type+%3D+'workload'&limit={limit}";

                logger.LogInformation("Making API call to retrieve runtime scan results...");
                logger.LogInformation(apiUrl);

                var response = await httpClient.GetAsync(apiUrl);

                if (response.StatusCode == HttpStatusCode.TooManyRequests) // 429 status code
                {
                    if (retryCount >= maxRetries)
                    {
                        logger.LogInformation("Maximum retry count reached. Exiting.");
                        throw new Exception("Maximum retry count reached.");
                    }

                    retryCount++;
                    logger.LogInformation($"Rate limited. Retrying in 60 seconds (Retry {retryCount}/{maxRetries})...");
                    await Task.Delay(60000); // Wait for 60 seconds before retrying
                    continue;
                }

                response.EnsureSuccessStatusCode();

                logger.LogInformation("API call completed to retrieve runtime scan results...");

                var responseJson = await response.Content.ReadAsStringAsync();

                dynamic? data = JsonConvert.DeserializeObject(responseJson);
                var objects = data?["data"];

                // Retrieve resultID in case it's needed
                if (objects != null)
                {
                    // Process objects if data is not null
                    foreach (var obj in objects)
                    {
                        var runtimeResultInfo = new RuntimeResultInfo
                        {
                            K8SClusterName = obj["recordDetails"]["labels"]["kubernetes.cluster.name"],
                            K8SNamespaceName = obj["recordDetails"]["labels"]["kubernetes.namespace.name"],
                            K8SWorkloadType = obj["recordDetails"]["labels"]["kubernetes.workload.type"],
                            K8SWorkloadName = obj["recordDetails"]["labels"]["kubernetes.workload.name"],
                            K8SContainerName = obj["recordDetails"]["labels"]["kubernetes.pod.container.name"],
                            Image = obj["recordDetails"]["mainAssetName"],
                            ImageId = obj["resourceId"],
                            ResultId = obj["resultId"]
                        };

                        runtimeWorkloadScanResults.Add(runtimeResultInfo);
                    }
                }
                else {
                    logger.LogError("Error with deserializing object...");
                }


                if (data?["page"]?["next"] != null)
                {
                    cursor = data["page"]["next"].ToString();
                }
                else
                {
                    logger.LogInformation("Next page doesn't exist. Exiting while loop.");
                    break;
                }
            }
        }
        catch (HttpRequestException ex)
        {
            // Catch multiple types of exceptions
            logger.LogError($"HTTP Request Error: {ex.Message}");
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError($"Error: {ex.Message}");
            throw;
        }

        return runtimeWorkloadScanResults;
    }
}