using System.Security.Cryptography;
using GatewayCore.ReleaseAuthority;
using GatewayCore.Licensing;

var root=Path.Combine(Path.GetTempPath(),"gc-release-authority-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    using var release=ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var license=ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var commit=new string('a',40);
    var data=Path.Combine(root,"GatewayCoreYarp.dll");
    File.WriteAllText(data,"disposable binary fixture");
    var secret=Path.Combine(root,"forbidden.pk8");
    File.WriteAllText(secret,"not a private key; negative fixture");
    Reject(()=>ReleaseManifestBuilder.SignPackage(root,commit,"release-ci",release),"reject key material in package");
    Check(!File.Exists(Path.Combine(root,ReleaseIntegrityVerifier.ManifestName)),"failed signing leaves no manifest");
    File.Delete(secret);
    Check(ReleaseManifestBuilder.SignPackage(root,commit,"release-ci",release)==commit,"company signer builds verified inventory");
    var verifier=new ReleaseIntegrityVerifier(new Dictionary<string,byte[]> { ["release-ci"]=release.ExportSubjectPublicKeyInfo() });
    Check(verifier.Verify(root,commit)==commit,"customer SDK accepts company-signed inventory");
    Reject(()=>ReleaseManifestBuilder.SignPackage(root,commit,"release-ci",release),"never overwrite existing manifest");
    var wrong=new ReleaseIntegrityVerifier(new Dictionary<string,byte[]> { ["release-ci"]=license.ExportSubjectPublicKeyInfo() });
    Reject(()=>wrong.Verify(root,commit),"entitlement key cannot verify independent release");
    File.WriteAllText(data,"changed binary fixture");
    Reject(()=>verifier.Verify(root,commit),"tampered package denied");
    Console.WriteLine("COMPANY_RELEASE_MANIFEST_ACCEPTANCE_PASS");
}
finally { Directory.Delete(root,true); }
static void Check(bool condition,string label)
{
    if(!condition)throw new Exception("FAIL: "+label);
    Console.WriteLine("PASS: "+label);
}
static void Reject(Action action,string label)
{
    try{action();}
    catch(Exception e) when(e is IOException or InvalidDataException or InvalidOperationException or CryptographicException or ArgumentException)
    {Check(true,label);return;}
    throw new Exception("FAIL: "+label);
}
