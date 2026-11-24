namespace GatewayCore.LicenseAuthority;
// Data-only contracts; no signing implementation, keys or I/O.
public sealed record Subscription(string LicenseId,string CustomerId,string DeploymentId,
    string Edition,int MaxNodes,int MaxSites,long ExpiresAt,string[] Features);
public static class EvaluationPolicy
{
    public const long MaxSeconds=30L*24*60*60;
    private static readonly HashSet<string> Allowed=new(StringComparer.Ordinal){"l7","tls","monitoring"};
    public static bool Valid(Subscription terms,DateTimeOffset utc)
    {
        if(terms.Edition!="evaluation")return true;
        var now=utc.ToUnixTimeSeconds();
        return terms.MaxNodes==1 && terms.MaxSites==1 && terms.ExpiresAt>now &&
            terms.ExpiresAt<=now+MaxSeconds && terms.Features is {Length:>=1 and <=3} &&
            terms.Features.Distinct(StringComparer.Ordinal).Count()==terms.Features.Length &&
            terms.Features.Contains("l7",StringComparer.Ordinal) && terms.Features.All(Allowed.Contains);
    }
}
