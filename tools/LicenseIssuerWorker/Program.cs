using System.Security.Cryptography;
using GatewayCore.LicenseIssuerWorker;
using Npgsql;

if(args.Length is not (3 or 5) || !Guid.TryParse(args[0],out var id) || Console.IsInputRedirected)
{
    Console.Error.WriteLine("Usage: LicenseIssuerWorker APPROVED_JOB_ID KEY_ID ENCRYPTED_PKCS8_PEM [NEW_KEY_ID NEW_ENCRYPTED_PKCS8_PEM]");
    return 2;
}
try
{
    var connection=Environment.GetEnvironmentVariable("GATEWAYCORE_ISSUER_DB")??
        throw new InvalidOperationException("Issuer-only database connection required.");
    using var signer=Load(args[2],"Current signing key passphrase: ");
    using var nextSigner=args.Length==5?Load(args[4],"New signing key passphrase: "):null;
    await using var db=NpgsqlDataSource.Create(connection);
    await new ApprovedJobExecutor(db,signer,args[1]).Execute(id,DateTimeOffset.UtcNow,nextSigner,args.Length==5?args[3]:null);
    Console.WriteLine("Approved job committed. Retrieve result in portal.");
    return 0;
}
catch(Exception e){Console.Error.WriteLine("Issuer job failed: "+e.GetType().Name);return 1;}
static ECDsa Load(string path,string prompt)
{
    var info=new FileInfo(path);
    if(info.Length is < 1 or > 65536 || (info.Attributes & FileAttributes.ReparsePoint)!=0)
        throw new InvalidDataException("Invalid encrypted signing key file.");
    Console.Error.Write(prompt);
    var password=new List<char>();
    try
    {
        while(true)
        {
            var ch=Console.ReadKey(true);
            if(ch.Key==ConsoleKey.Enter)break;
            if(ch.Key==ConsoleKey.Backspace){if(password.Count>0)password.RemoveAt(password.Count-1);}
            else if(!char.IsControl(ch.KeyChar)&&password.Count<1024)password.Add(ch.KeyChar);
        }
        Console.Error.WriteLine();
        var signer=ECDsa.Create();
        var secret=password.ToArray();
        try{signer.ImportFromEncryptedPem(File.ReadAllText(path),secret);return signer;}
        catch{signer.Dispose();throw;}
        finally{Array.Clear(secret);}
    }
    finally{for(var i=0;i<password.Count;i++)password[i]='\0';password.Clear();}
}
