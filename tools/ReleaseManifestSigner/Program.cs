using System.Security.Cryptography;
using GatewayCore.ReleaseAuthority;

if (args.Length!=4 || Console.IsInputRedirected)
{
    Console.Error.WriteLine("Usage: ReleaseManifestSigner PACKAGE SOURCE_COMMIT RELEASE_KEY_ID ENCRYPTED_KEY_PEM");
    return 2;
}
try
{
    var package=Path.GetFullPath(args[0]);
    var keyPath=Path.GetFullPath(args[3]);
    var relative=Path.GetRelativePath(package,keyPath);
    if (!Path.IsPathRooted(relative) && relative!=".." && !relative.StartsWith(".."+Path.DirectorySeparatorChar,StringComparison.Ordinal))
        throw new InvalidOperationException("Release signing key must be outside the package.");
    var keyInfo=new FileInfo(keyPath);
    if (keyInfo.Length is < 1 or > 65536 || (keyInfo.Attributes & FileAttributes.ReparsePoint)!=0)
        throw new InvalidDataException("Invalid external encrypted key file.");
    Console.Error.Write("Independent release signing key passphrase: ");
    var password=new List<char>();
    try
    {
        while (true)
        {
            var ch=Console.ReadKey(true);
            if (ch.Key==ConsoleKey.Enter) break;
            if (ch.Key==ConsoleKey.Backspace) { if(password.Count>0)password.RemoveAt(password.Count-1); }
            else if(!char.IsControl(ch.KeyChar) && password.Count<1024)password.Add(ch.KeyChar);
        }
        Console.Error.WriteLine();
        var buffer=password.ToArray();
        using var signer=ECDsa.Create();
        try { signer.ImportFromEncryptedPem(File.ReadAllText(keyPath),buffer); }
        finally { Array.Clear(buffer); }
        var commit=ReleaseManifestBuilder.SignPackage(package,args[1],args[2],signer);
        Console.WriteLine("Release manifest signed and independently verified against source "+commit);
    }
    finally { for(var i=0;i<password.Count;i++)password[i]='\0';password.Clear(); }
    return 0;
}
catch(Exception e)
{
    Console.Error.WriteLine("Release signing rejected: "+e.GetType().Name);
    return 1;
}
