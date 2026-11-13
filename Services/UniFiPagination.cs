using System.Text.Json;

namespace UniFiDnsManager.Services;

internal sealed class UniFiPagination(int offset = 0)
{
    private const int MaximumPages = 500;
    private readonly HashSet<string> _pageSignatures = new(StringComparer.Ordinal);
    private int _pageCount;
    public int Offset { get; private set; } = offset;
    public long? TotalCount { get; private set; }

    public bool Advance(int rows, long? totalCount = null, int? responseLimit = null, int? responseOffset = null, string? signature = null)
    {
        if (responseOffset.HasValue && responseOffset != Offset)
            throw new UniFiApiException("UniFi 返回了错误的分页偏移量，无法读取完整列表。");
        if (rows > 0 && signature is not null && !_pageSignatures.Add(signature))
            throw new UniFiApiException("UniFi 返回了重复的分页，无法读取完整列表。");

        TotalCount = totalCount ?? TotalCount;
        Offset = checked(Offset + rows);
        if (TotalCount is long total)
        {
            if (Offset >= total) return false;
            if (rows == 0)
                throw new UniFiApiException("UniFi 提前返回空页，列表读取不完整。");
        }
        else if (rows == 0 || responseLimit is > 0 && rows < responseLimit.Value)
        {
            return false;
        }

        if (++_pageCount >= MaximumPages)
            throw new UniFiApiException("UniFi 列表超过分页上限，请缩小查询范围后重试。");
        return true;
    }

    public static int? ReadNonNegativeInt(JsonElement root, string key) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(key, out var value)
        && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) && number >= 0
            ? number
            : null;

    public static long? ReadTotalCount(JsonElement root) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty("totalCount", out var value)
        && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number) && number >= 0
            ? number
            : null;
}
