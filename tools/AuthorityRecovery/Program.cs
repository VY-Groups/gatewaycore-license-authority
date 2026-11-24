using System.Security.Cryptography;
using System.Text;
using GatewayCore.AuthorityRecovery;
using Npgsql;

if(args.Length!=4 || args[0] is not ("checkpoint" or "verify"))
{
    Console.Error.WriteLine("Usage: AuthorityRecovery checkpoint|verify KEY_ID KEY_PEM CHECKPOINT_FILE");
    return 2;
}
try
{
    await using var db=NpgsqlDataSource.Create(Environment.GetEnvironmentVariable("GATEWAYCORE_RECOVERY_DB")
        ??throw new InvalidOperationException("Independent recovery database required."));
    var keyInfo=new FileInfo(args[2]);
    if(keyInfo.Length is < 1 or > 65536 || (keyInfo.Attributes & FileAttributes.ReparsePoint)!=0)
        throw new InvalidDataException("Invalid recovery key file.");
    using var key=ECDsa.Create();
    if(args[0]=="verify")
    {
        // Import only the public SPKI, not a private key.
        var pem=File.ReadAllText(args[2]);
        if(!pem.TrimStart().StartsWith("-----BEGIN PUBLIC KEY-----",StringComparison.Ordinal))
            throw new InvalidDataException("Expected recovery public key.");
        key.ImportFromPem(pem);
        var info=new FileInfo(args[3]);
        if(info.Length is < 1 or > 512 || (info.Attributes & FileAttributes.ReparsePoint)!=0)
            throw new InvalidDataException("Invalid checkpoint file.");
        await LedgerCheckpoint.Verify(db,File.ReadAllText(args[3]),key,args[1]);
        Console.WriteLine("AUTHORITY_RECOVERY_CHECKPOINT_MATCH");
    }
    else
    {
        if(Console.IsInputRedirected)throw new InvalidOperationException("Use an interactive recovery console.");
        Console.Error.Write("Independent recovery key passphrase: ");
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
            var buffer=password.ToArray();
            try{key.ImportFromEncryptedPem(File.ReadAllText(args[2]),buffer);}
            finally{Array.Clear(buffer);}
        }
        finally{for(var i=0;i<password.Count;i++)password[i]='\0';password.Clear();}
        var checkpoint=await LedgerCheckpoint.Sign(db,key,args[1],DateTimeOffset.UtcNow);
        using var file=new FileStream(args[3],FileMode.CreateNew,FileAccess.Write,FileShare.None);
        file.Write(Encoding.ASCII.GetBytes(checkpoint));file.Flush(true);
        Console.WriteLine("AUTHORITY_RECOVERY_CHECKPOINT_CREATED");
    }
    return 0;
}
catch(Exception e){Console.Error.WriteLine("Recovery verification rejected: "+e.GetType().Name);return 1;}
