using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Net;
using Microsoft.Extensions.Logging;

public class ApiService
{


    public async Task<DateTime?> GetLastCompletedReportDateTime(string secureUrlAuthority, HttpClient httpClient, string reportID, ILogger logger)
    {
        try
        {
            var apiPath = $"api/scanning/reporting/v2/schedules/{reportID}";
            var apiUrl = $"https://{secureUrlAuthority}/{apiPath}";
            logger.LogInformation("Making API call to download report...");
            
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

    public async Task<Stream> DownloadReport(string secureUrlAuthority, HttpClient httpClient, string reportID, ILogger logger)
    {
        try
        {
            var apiPath = $"api/scanning/reporting/v2/schedules/{reportID}/download";
            var apiUrl = $"https://{secureUrlAuthority}/{apiPath}";
            logger.LogInformation("Making API call to download report...");
            
            HttpResponseMessage response = await httpClient.GetAsync(apiUrl);
            response.EnsureSuccessStatusCode(); // Ensure the HTTP request was successful

            logger.LogInformation("API call completed to retrieve report...");

            Stream contentStream = await response.Content.ReadAsStreamAsync();
            return DecompressStream(contentStream);
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
        using (var decompressionStream = new GZipStream(inputStream, CompressionMode.Decompress))
        {
            var memoryStream = new MemoryStream();
            decompressionStream.CopyTo(memoryStream);
            memoryStream.Seek(0, SeekOrigin.Begin);
            return memoryStream;
        }
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
                        break;
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
                            ImageId = obj["resourceId"]
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