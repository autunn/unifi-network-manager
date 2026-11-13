namespace UniFiDnsManager.Services;

internal static class UniFiPaginationTests
{
    public static Task RunAsync()
    {
        var page = OfficialResourcePresentationService.ParsePage(
            """{"data":[{"id":"a"},{"id":"b"}],"count":2,"offset":0,"limit":2}""", "devices");
        var pagination = new UniFiPagination();
        if (page.Snapshot.HasReportedTotalCount
            || !pagination.Advance(page.Snapshot.Items.Count, page.Total, page.Limit, page.Offset, page.Signature)
            || pagination.Offset != 2
            || pagination.Advance(1, responseLimit: 2, responseOffset: 2, signature: "next"))
            throw new Exception("A page count was treated as a collection total.");

        var noMetadata = new UniFiPagination();
        if (!noMetadata.Advance(1) || noMetadata.Advance(0))
            throw new Exception("A list without pagination metadata did not stop at the empty page.");

        var reportedTotal = new UniFiPagination();
        if (!reportedTotal.Advance(2, totalCount: 4))
            throw new Exception("A known total incorrectly terminated the first page.");
        RequireFailure(() => reportedTotal.Advance(0));

        var repeated = new UniFiPagination();
        repeated.Advance(2, signature: "same");
        RequireFailure(() => repeated.Advance(2, signature: "same"));
        RequireFailure(() => new UniFiPagination(2).Advance(2, responseOffset: 0));
        RequireFailure(() => OfficialResourcePresentationService.ParsePage("""{"data":null}""", "devices"));
        return Task.CompletedTask;
    }

    private static void RequireFailure(Action action)
    {
        try { action(); }
        catch (UniFiApiException) { return; }
        throw new Exception("Incomplete pagination was reported as successful.");
    }
}
