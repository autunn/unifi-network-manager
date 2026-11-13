using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

public static class PolicyChangeService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    static PolicyChangeService()
    {
        JsonOptions.Converters.Add(new JsonStringEnumConverter());
    }

    public static async Task<PolicyBundle> LoadBundleAsync(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new ValidationException("策略文件必须是 JSON 对象。");

            var root = document.RootElement;
            var hasDns = HasObjectArray(root, "dns_records", out _);
            var hasLegacyDns = HasObjectArray(root, "records", out var legacyRecords);
            var hasAcl = HasObjectArray(root, "acl_rules", out _);
            var hasFirewall = HasObjectArray(root, "firewall_policies", out _);
            if (!hasDns && !hasLegacyDns && !hasAcl && !hasFirewall)
                throw new ValidationException("策略文件缺少 DNS、ACL 或防火墙规则数组。");
            ValidateOrdering(root, "acl_ordering", "ordered_acl_rule_ids");
            ValidateOrdering(root, "firewall_ordering", "before_system_defined", "after_system_defined");

            var bundle = root.Deserialize<PolicyBundle>(JsonOptions) ?? new PolicyBundle();
            bundle.HasDnsSection = hasDns || hasLegacyDns;
            bundle.HasAclSection = hasAcl;
            bundle.HasFirewallSection = hasFirewall;
            if (bundle.DnsRecords.Count == 0 && hasLegacyDns)
                bundle.DnsRecords = legacyRecords.Deserialize<List<DnsRecord>>(JsonOptions) ?? [];
            foreach (var record in bundle.DnsRecords.Where(record => record.RecordType == "SRV" && !string.IsNullOrWhiteSpace(record.Key)))
                record.PopulateSrvParts();
            bundle.AclRules = CloneElements(bundle.AclRules);
            bundle.FirewallPolicies = CloneElements(bundle.FirewallPolicies);
            return bundle;
        }
        catch (JsonException exception)
        {
            throw new ValidationException($"无法读取策略 JSON：{exception.Message}");
        }
    }

    public static async Task SaveBundleAsync(string path, PolicyBundle bundle, CancellationToken cancellationToken = default)
    {
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(bundle, JsonOptions), cancellationToken);
    }

    private static bool HasObjectArray(JsonElement root, string name, out JsonElement value)
    {
        if (!TryGetField(root, name, out value)) return false;
        if (value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.Object))
            throw new ValidationException($"策略文件中的 {name} 必须是对象数组。");
        return true;
    }

    private static void ValidateOrdering(JsonElement root, string name, params string[] arrayFields)
    {
        if (!TryGetField(root, name, out var value) || value.ValueKind == JsonValueKind.Null) return;
        if (value.ValueKind != JsonValueKind.Object)
            throw new ValidationException($"策略文件中的 {name} 必须是对象。");
        foreach (var field in arrayFields)
        {
            if (TryGetField(value, field, out var ids) && (ids.ValueKind != JsonValueKind.Array ||
                ids.EnumerateArray().Any(id => id.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(id.GetString()))))
                throw new ValidationException($"策略文件中的 {name}.{field} 必须是有效 ID 数组。");
        }
    }

    private static bool TryGetField(JsonElement element, string name, out JsonElement value)
    {
        value = default;
        foreach (var property in element.EnumerateObject())
        {
            if (!property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            if (value.ValueKind != JsonValueKind.Undefined)
                throw new ValidationException($"策略文件中重复定义了 {name}。");
            value = property.Value;
        }
        return value.ValueKind != JsonValueKind.Undefined;
    }

    public static PolicyChangePlan BuildPlan(PolicyBundle bundle, string sourcePath, PolicyBundle current, bool synchronizeDeletes) =>
        BuildPlan(bundle, sourcePath, current.DnsRecords,
            current.AclRules.Select(item => OfficialPolicyRule.Parse(OfficialPolicyKind.Acl, item)).ToList(),
            current.FirewallPolicies.Select(item => OfficialPolicyRule.Parse(OfficialPolicyKind.Firewall, item)).ToList(),
            synchronizeDeletes, matchSourceIds: IsSameSite(bundle, current.Target, current.SiteId));

    public static bool IsSameSite(PolicyBundle bundle, string? target, string? siteId) =>
        !string.IsNullOrWhiteSpace(bundle.Target) && !string.IsNullOrWhiteSpace(bundle.SiteId) &&
        string.Equals(bundle.Target, target, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(bundle.SiteId, siteId, StringComparison.OrdinalIgnoreCase);

    public static bool PreviewMatches(PolicyChangePlan plan, PolicyBundle preview, PolicyBundle current)
    {
        var bundle = plan.Bundle;
        if (!IsSameSite(preview, current.Target, current.SiteId)) return false;
        if (bundle.HasDnsSection)
        {
            var previousDns = preview.DnsRecords.OrderBy(record => record.Id, StringComparer.OrdinalIgnoreCase).ToList();
            var currentDns = current.DnsRecords.OrderBy(record => record.Id, StringComparer.OrdinalIgnoreCase).ToList();
            if (previousDns.Count != currentDns.Count || previousDns.Zip(currentDns).Any(pair =>
                !string.Equals(pair.First.Id, pair.Second.Id, StringComparison.OrdinalIgnoreCase) || !DnsContentEquals(pair.First, pair.Second)))
                return false;
        }
        if (bundle.HasAclSection && !PolicyListsEqual(preview.AclRules, current.AclRules)) return false;
        if (bundle.HasFirewallSection && !PolicyListsEqual(preview.FirewallPolicies, current.FirewallPolicies)) return false;
        if (!plan.SynchronizeDeletes) return true;
        return (bundle.AclOrdering is null || PolicyOrderingEquals(preview.AclOrdering, current.AclOrdering)) &&
               (bundle.FirewallOrdering is null || PolicyOrderingEquals(preview.FirewallOrdering, current.FirewallOrdering));
    }

    private static bool PolicyListsEqual(IReadOnlyList<JsonElement> left, IReadOnlyList<JsonElement> right) =>
        left.Count == right.Count &&
        left.OrderBy(GetPolicyId, StringComparer.OrdinalIgnoreCase)
            .Zip(right.OrderBy(GetPolicyId, StringComparer.OrdinalIgnoreCase))
            .All(pair => PolicyJsonEquals(pair.First.GetRawText(), pair.Second.GetRawText()));

    private static bool PolicyOrderingEquals(PolicyOrderingSnapshot? left, PolicyOrderingSnapshot? right) =>
        left is null || right is null ? left == right :
        left.OrderedAclRuleIds.SequenceEqual(right.OrderedAclRuleIds, StringComparer.OrdinalIgnoreCase) &&
        left.BeforeSystemDefined.SequenceEqual(right.BeforeSystemDefined, StringComparer.OrdinalIgnoreCase) &&
        left.AfterSystemDefined.SequenceEqual(right.AfterSystemDefined, StringComparer.OrdinalIgnoreCase);

    public static PolicyChangePlan BuildPlan(
        PolicyBundle bundle,
        string sourcePath,
        IReadOnlyList<DnsRecord> currentDns,
        IReadOnlyList<OfficialPolicyRule> currentAcl,
        IReadOnlyList<OfficialPolicyRule> currentFirewall,
        bool synchronizeDeletes,
        bool matchSourceIds = true)
    {
        var items = new List<PolicyChangeItem>();
        if (bundle.HasDnsSection) BuildDnsItems(items, bundle.DnsRecords, currentDns, synchronizeDeletes, matchSourceIds);
        if (bundle.HasAclSection) BuildPolicyItems(items, OfficialPolicyKind.Acl, bundle.AclRules, currentAcl, synchronizeDeletes, matchSourceIds);
        if (bundle.HasFirewallSection) BuildPolicyItems(items, OfficialPolicyKind.Firewall, bundle.FirewallPolicies, currentFirewall, synchronizeDeletes, matchSourceIds);
        foreach (var item in items) item.IsSelected = item.Action is PolicyChangeAction.Add or PolicyChangeAction.Update;
        return new PolicyChangePlan
        {
            Bundle = bundle,
            SourcePath = sourcePath,
            SynchronizeDeletes = synchronizeDeletes,
            Items = items
                .OrderBy(item => ScopeOrder(item.Scope))
                .ThenBy(item => ActionOrder(item.Action))
                .ThenBy(item => item.DesiredIndex)
                .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    public static PolicyBundle CaptureBundle(
        IUniFiClient client,
        IReadOnlyList<DnsRecord> dns,
        IReadOnlyList<OfficialPolicyRule> acl,
        IReadOnlyList<OfficialPolicyRule> firewall,
        PolicyOrderingSnapshot? aclOrdering,
        PolicyOrderingSnapshot? firewallOrdering) => new()
    {
        Target = client.Target,
        Site = client.Site,
        SiteId = client.SiteId,
        NetworkVersion = client.ApplicationVersion,
        DnsRecords = dns.Select(record => record.Clone()).ToList(),
        AclRules = acl.Select(rule => ParseElement(rule.RawResponseJson)).ToList(),
        FirewallPolicies = firewall.Select(rule => ParseElement(rule.RawResponseJson)).ToList(),
        AclOrdering = aclOrdering,
        FirewallOrdering = firewallOrdering
    };

    public static string ToEditablePolicyJson(OfficialPolicyKind kind, JsonElement element)
    {
        var node = JsonNode.Parse(element.GetRawText())?.AsObject()
            ?? throw new ValidationException("策略项不是 JSON 对象。");
        node.Remove("id");
        node.Remove("index");
        node.Remove("metadata");
        return OfficialPolicyJson.NormalizeAndValidate(kind, node.ToJsonString());
    }

    public static string? GetPolicyId(JsonElement element) => GetString(element, "id");

    public static string? GetPolicyName(JsonElement element) => GetString(element, "name");

    private static void BuildDnsItems(
        List<PolicyChangeItem> items,
        IReadOnlyList<DnsRecord> desiredRecords,
        IReadOnlyList<DnsRecord> currentRecords,
        bool synchronizeDeletes,
        bool matchSourceIds)
    {
        var currentByKey = currentRecords
            .GroupBy(ImportService.IdentityKey, ImportService.IdentityComparer)
            .ToDictionary(group => group.Key, group => group.ToList(), ImportService.IdentityComparer);
        var currentById = currentRecords
            .Where(record => !string.IsNullOrWhiteSpace(record.Id))
            .GroupBy(record => record.Id!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var desiredKeys = new HashSet<string>(ImportService.IdentityComparer);
        var matchedCurrent = new HashSet<DnsRecord>();
        var hasInvalid = false;

        foreach (var desiredSource in desiredRecords)
        {
            try
            {
                var desired = DnsValidator.Normalize(desiredSource);
                var key = ImportService.IdentityKey(desired);
                if (!desiredKeys.Add(key))
                {
                    hasInvalid = true;
                    items.Add(Invalid(PolicyChangeScope.Dns, desired.Key, "目标文件中存在重复 DNS 规则。"));
                    continue;
                }

                DnsRecord? current = null;
                if (matchSourceIds && !string.IsNullOrWhiteSpace(desired.Id) && currentById.TryGetValue(desired.Id, out var byId) && !matchedCurrent.Contains(byId))
                    current = byId;
                else if (currentByKey.TryGetValue(key, out var byKey))
                    current = byKey.FirstOrDefault(record => !matchedCurrent.Contains(record));

                if (current is null)
                {
                    items.Add(new PolicyChangeItem
                    {
                        Scope = PolicyChangeScope.Dns,
                        Action = PolicyChangeAction.Add,
                        Name = $"{desired.TypeLabel} · {desired.Key}",
                        Details = ImportService.Describe(desired),
                        DesiredDns = desired
                    });
                }
                else if (!DnsContentEquals(current, desired))
                {
                    matchedCurrent.Add(current);
                    items.Add(new PolicyChangeItem
                    {
                        Scope = PolicyChangeScope.Dns,
                        Action = PolicyChangeAction.Update,
                        Name = $"{desired.TypeLabel} · {desired.Key}",
                        Details = $"{ImportService.Describe(current)}  →  {ImportService.Describe(desired)}",
                        CurrentId = current.Id,
                        ActualId = current.Id,
                        DesiredDns = desired
                    });
                }
                else
                {
                    matchedCurrent.Add(current);
                    items.Add(new PolicyChangeItem
                    {
                        Scope = PolicyChangeScope.Dns,
                        Action = PolicyChangeAction.Unchanged,
                        Name = $"{desired.TypeLabel} · {desired.Key}",
                        Details = ImportService.Describe(desired),
                        CurrentId = current.Id,
                        ActualId = current.Id,
                        DesiredDns = desired,
                        Status = "无需变更"
                    });
                }
            }
            catch (Exception exception) when (exception is ValidationException or FormatException)
            {
                hasInvalid = true;
                items.Add(Invalid(PolicyChangeScope.Dns, desiredSource.Key, exception.Message));
            }
        }

        if (!synchronizeDeletes || hasInvalid) return;
        foreach (var current in currentRecords.Where(record => !matchedCurrent.Contains(record)))
        {
            items.Add(new PolicyChangeItem
            {
                Scope = PolicyChangeScope.Dns,
                Action = PolicyChangeAction.Delete,
                Name = $"{current.TypeLabel} · {current.Key}",
                Details = ImportService.Describe(current),
                CurrentId = current.Id,
                ActualId = current.Id
            });
        }
    }

    private static void BuildPolicyItems(
        List<PolicyChangeItem> items,
        OfficialPolicyKind kind,
        IReadOnlyList<JsonElement> desiredElements,
        IReadOnlyList<OfficialPolicyRule> currentRules,
        bool synchronizeDeletes,
        bool matchSourceIds)
    {
        var scope = kind == OfficialPolicyKind.Acl ? PolicyChangeScope.Acl : PolicyChangeScope.Firewall;
        var currentUserRules = currentRules.Where(rule => rule.CanModify).ToList();
        var unmatchedCurrentIds = currentUserRules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var desiredNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hasInvalid = false;

        foreach (var element in desiredElements.OrderBy(element => GetInt(element, "index")))
        {
            var origin = element.TryGetProperty("metadata", out var metadata) && metadata.ValueKind == JsonValueKind.Object
                ? GetString(metadata, "origin")
                : null;
            if (!string.IsNullOrWhiteSpace(origin) && !string.Equals(origin, "USER_DEFINED", StringComparison.OrdinalIgnoreCase))
                continue;

            var name = GetPolicyName(element) ?? "未命名策略";
            var sourceId = GetPolicyId(element);
            if (!desiredNames.Add(name))
            {
                hasInvalid = true;
                items.Add(Invalid(scope, name, "目标文件中存在重名的用户策略，无法安全匹配。"));
                continue;
            }

            try
            {
                var editable = ToEditablePolicyJson(kind, element);
                var current = currentUserRules.FirstOrDefault(rule =>
                                  matchSourceIds && !string.IsNullOrWhiteSpace(sourceId) &&
                                  unmatchedCurrentIds.Contains(rule.Id) &&
                                  string.Equals(rule.Id, sourceId, StringComparison.OrdinalIgnoreCase))
                              ?? currentUserRules.FirstOrDefault(rule =>
                                  unmatchedCurrentIds.Contains(rule.Id) &&
                                  string.Equals(rule.Name, name, StringComparison.OrdinalIgnoreCase));
                if (current is null)
                {
                    items.Add(new PolicyChangeItem
                    {
                        Scope = scope,
                        Action = PolicyChangeAction.Add,
                        Name = name,
                        Details = DescribePolicy(kind, element),
                        DesiredSourceId = sourceId,
                        DesiredIndex = GetInt(element, "index"),
                        DesiredPolicyJson = editable
                    });
                }
                else
                {
                    unmatchedCurrentIds.Remove(current.Id);
                    var changed = !PolicyJsonEquals(editable, OfficialPolicyJson.NormalizeAndValidate(kind, current.ToEditableJson()));
                    items.Add(new PolicyChangeItem
                    {
                        Scope = scope,
                        Action = changed ? PolicyChangeAction.Update : PolicyChangeAction.Unchanged,
                        Name = name,
                        Details = changed ? $"{current.Action} / {current.Type}  →  {DescribePolicy(kind, element)}" : DescribePolicy(kind, element),
                        CurrentId = current.Id,
                        ActualId = current.Id,
                        DesiredSourceId = sourceId,
                        DesiredIndex = GetInt(element, "index"),
                        DesiredPolicyJson = editable,
                        Status = changed ? "待执行" : "无需变更"
                    });
                }
            }
            catch (Exception exception) when (exception is ValidationException or JsonException or InvalidOperationException)
            {
                hasInvalid = true;
                items.Add(Invalid(scope, name, exception.Message));
            }
        }

        if (!synchronizeDeletes || hasInvalid) return;
        foreach (var current in currentUserRules.Where(rule => unmatchedCurrentIds.Contains(rule.Id)))
        {
            items.Add(new PolicyChangeItem
            {
                Scope = scope,
                Action = PolicyChangeAction.Delete,
                Name = current.Name,
                Details = $"{current.Action} / {current.Type} · {current.Description}",
                CurrentId = current.Id,
                ActualId = current.Id,
                DesiredIndex = current.Index
            });
        }
    }

    private static bool DnsContentEquals(DnsRecord left, DnsRecord right) =>
        string.Equals(left.RecordType, right.RecordType, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Key, right.Key, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Value, right.Value, left.RecordType == "TXT" ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase) &&
        left.Enabled == right.Enabled &&
        left.Ttl.GetValueOrDefault() == right.Ttl.GetValueOrDefault() &&
        left.Priority.GetValueOrDefault() == right.Priority.GetValueOrDefault() &&
        left.Weight.GetValueOrDefault() == right.Weight.GetValueOrDefault() &&
        left.Port.GetValueOrDefault() == right.Port.GetValueOrDefault() &&
        string.Equals(left.Service, right.Service, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Protocol, right.Protocol, StringComparison.OrdinalIgnoreCase);

    private static bool PolicyJsonEquals(string left, string right)
    {
        var leftNode = JsonNode.Parse(left);
        var rightNode = JsonNode.Parse(right);
        return JsonNode.DeepEquals(leftNode, rightNode);
    }

    private static PolicyChangeItem Invalid(PolicyChangeScope scope, string? name, string details) => new()
    {
        Scope = scope,
        Action = PolicyChangeAction.Invalid,
        Name = string.IsNullOrWhiteSpace(name) ? "无效项目" : name,
        Details = details,
        Status = "需要修正"
    };

    private static string DescribePolicy(OfficialPolicyKind kind, JsonElement element)
    {
        var action = kind == OfficialPolicyKind.Acl
            ? GetString(element, "action")
            : element.TryGetProperty("action", out var actionObject) && actionObject.ValueKind == JsonValueKind.Object ? GetString(actionObject, "type") : null;
        var type = kind == OfficialPolicyKind.Acl
            ? GetString(element, "type")
            : element.TryGetProperty("ipProtocolScope", out var protocol) && protocol.ValueKind == JsonValueKind.Object ? GetString(protocol, "ipVersion") : null;
        var description = GetString(element, "description");
        return $"{action ?? "-"} / {type ?? "-"}{(string.IsNullOrWhiteSpace(description) ? string.Empty : $" · {description}")}";
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static int GetInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) ? number : 0;

    private static JsonElement ParseElement(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static List<JsonElement> CloneElements(IEnumerable<JsonElement> values) => values.Select(value => value.Clone()).ToList();

    private static int ScopeOrder(PolicyChangeScope scope) => scope switch
    {
        PolicyChangeScope.Dns => 0,
        PolicyChangeScope.Acl => 1,
        PolicyChangeScope.Firewall => 2,
        _ => 9
    };

    private static int ActionOrder(PolicyChangeAction action) => action switch
    {
        PolicyChangeAction.Invalid => 0,
        PolicyChangeAction.Add => 1,
        PolicyChangeAction.Update => 2,
        PolicyChangeAction.Delete => 3,
        PolicyChangeAction.Unchanged => 4,
        _ => 9
    };
}
