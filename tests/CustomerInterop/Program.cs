using System.Text.Json;
using GatewayCore.Licensing;

if(Environment.GetEnvironmentVariable("CI")!="true" ||
   Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" ||
   args.Length is < 3 or > 4)
    return 2;
try
{
    var keys=JsonSerializer.Deserialize<Dictionary<string,byte[]>>(File.ReadAllBytes(args[2]))
        ?? throw new InvalidDataException("Missing synthetic public trust.");
    var store=new OfflineLicenseStore(args[1],new OfflineLicenseVerifier(keys));
    var now=DateTimeOffset.UtcNow;
    switch(args[0])
    {
        case "provision" when args.Length==4:
        case "request" when args.Length==4:
            if(args[0]=="provision")store.Initialize();
            using(var file=new FileStream(args[3],FileMode.CreateNew))
                file.Write(store.ExportActivationRequest());
            break;
        case "import" when args.Length==4:
            Report(store.Import(File.ReadAllBytes(args[3]),now));
            break;
        case "revoke" when args.Length==4:
            Report(store.ImportRevocation(File.ReadAllBytes(args[3]),now));
            break;
        case "proof" when args.Length==4:
            Console.WriteLine(JsonSerializer.Serialize(new {proof=System.Text.Encoding.ASCII.GetString(store.CreateInstallationProof(args[3],now))}));
            break;
        case "inspect" when args.Length==3:
            Report(store.Inspect(now)??throw new InvalidOperationException("Missing license."));
            break;
        default:return 2;
    }
    return 0;
}
catch(Exception e){Console.Error.WriteLine("Customer SDK rejected: "+e.GetType().Name);return 1;}
static void Report(VerifiedLicense license)
{
    Console.WriteLine(JsonSerializer.Serialize(new { revision=license.Revision,allocationId=license.AllocationId,
        validity=license.Validity.ToString(),siteId=license.SiteId,features=license.Features.Order(StringComparer.Ordinal).ToArray() }));
}
