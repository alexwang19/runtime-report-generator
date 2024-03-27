using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO.Compression;
using System.Threading.Tasks;
using System.Text;
using System.Text.Json;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class ApiService
{
    public async Task<Stream> DownloadReportAsync(string secureUrlAuthority, HttpClient httpClient, string reportID)
    {
        try
        {
            var apiPath = $"api/scanning/reporting/v2/schedules/{reportID}/download";
            var apiUrl = $"https://{secureUrlAuthority}/{apiPath}";
            Console.WriteLine("Making api call to download report...");
            HttpResponseMessage response = await httpClient.GetAsync(apiUrl);
            Console.WriteLine("Api call complete to retrieve report...");

            if (response.IsSuccessStatusCode)
            {
                Stream contentStream = await response.Content.ReadAsStreamAsync();
                return DecompressStream(contentStream);
            }
            else
            {
                Console.WriteLine($"Failed to download. Status code: {response.StatusCode}");
                return null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return null;
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

    public async Task<List<RuntimeResultInfo>> GetRuntimeWorkloadScanResultsList(string secureUrlAuthority, HttpClient httpClient)
    {
        var limit = 1000;
        var cursor = "";
        var runtimeWorkloadScanResults = new List<RuntimeResultInfo>();

        while (true)
        {
            // public api
            // var apiPath = "secure/vulnerability/v1beta1/runtime-results";
            // internal api
            var apiPath = "api/scanning/runtime/v2/workflows/results";
            var apiUrl = $"https://{secureUrlAuthority}/{apiPath}?cursor={cursor}&filter=asset.type+%3D+'workload'&limit={limit}";
            Console.WriteLine("Making api call to retrieve runtime scan results...");
            Console.WriteLine(apiUrl);
            var responseJson = await httpClient.GetStringAsync(apiUrl);
            Console.WriteLine("Api call complete to retrieve runtime scan results...");
            // HttpResponseMessage response = await httpClient.GetAsync(apiUrlUpdated);
            // var responseJson = await response.Content.ReadAsStringAsync();
            // var page2 = JsonDocument.Parse(responseJson).RootElement.GetProperty("page");
            // Console.WriteLine(page2);
            var data = JsonDocument.Parse(responseJson).RootElement.GetProperty("data");
            // Console.WriteLine(data.Length);
            List<dynamic> objects = JsonConvert.DeserializeObject<List<dynamic>>(data.ToString());
            // Console.WriteLine(objects.Count);
            foreach (var obj in objects) {
                // Console.WriteLine( obj["recordDetails"]["mainAssetName"] + "," + obj["recordDetails"]["labels"]["kubernetes.cluster.name"] + "," + obj["scope"]["kubernetes.namespace.name"] + "," + obj["scope"]["kubernetes.workload.type"] + "," + obj["scope"]["kubernetes.workload.name"] + "," + obj["scope"]["kubernetes.pod.container.name"]);
                var runtimeResultInfo = new RuntimeResultInfo
                {
                    // K8SClusterName = obj["scope"]["kubernetes.cluster.name"],
                    // K8SNamespaceName = obj["scope"]["kubernetes.namespace.name"],
                    // K8SWorkloadType = obj["scope"]["kubernetes.workload.type"],
                    // K8SWorkloadName = obj["scope"]["kubernetes.workload.name"],
                    // K8SContainerName = obj["scope"]["kubernetes.pod.container.name"],
                    // Image = obj["mainAssetName"],
                    K8SClusterName = obj["recordDetails"]["labels"]["kubernetes.cluster.name"],
                    K8SNamespaceName = obj["recordDetails"]["labels"]["kubernetes.namespace.name"],
                    K8SWorkloadType = obj["recordDetails"]["labels"]["kubernetes.workload.type"],
                    K8SWorkloadName = obj["recordDetails"]["labels"]["kubernetes.workload.name"],
                    K8SContainerName = obj["recordDetails"]["labels"]["kubernetes.pod.container.name"],
                    Image = obj["recordDetails"]["mainAssetName"],
                    ImageId = obj["resourceId"],
                };
                runtimeWorkloadScanResults.Add(runtimeResultInfo);
            }

            var page = JsonDocument.Parse(responseJson).RootElement.GetProperty("page");
            if (page.TryGetProperty("next", out JsonElement nextCursor))
            {
                cursor = nextCursor.ToString();
                Console.WriteLine("This is cursor: " + cursor);
                if(cursor == ""){
                    Console.WriteLine("Next page doesn't exist. Exiting...");
                    break;
                }
            }
            else
            {
                Console.WriteLine("Next page doesn't exist. Exiting while loop.");
                // Console.WriteLine(counter.ToString());
                break;
            }
        }

        return runtimeWorkloadScanResults;
    }
}
