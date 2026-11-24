using System.Security.Cryptography;
using System.Text;
using System.Globalization;
using Npgsql;
using System.Data;

namespace GatewayCore.AuthorityRecovery;

// Independent recovery trust is not entitlement-signing trust. Preserve the
// latest checkpoint outside the database and outside the authority host.
public static class LedgerCheckpoint
{
    private static readonly (string Table,string Order)[] Tables =
    [
        ("gc_customers","id"),("gc_subscriptions","id"),("gc_license_jobs","id"),
        ("gc_issuer_authority","subscription_id"),("gc_issuer_allocations","subscription_id,installation_hash"),
        ("gc_issuer_results","job_id"),("gc_issuer_key_history","subscription_id,key_id"),("gc_billing_invoices","id"),("gc_portal_audit","id")
    ];
    public static async Task<string> Digest(NpgsqlDataSource db)
    {
        await using var conn=await db.OpenConnectionAsync();
        await using var tx=await conn.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        await using(var setup=new NpgsqlCommand("SET TRANSACTION READ ONLY; SET LOCAL TIME ZONE 'UTC'; SET LOCAL datestyle TO 'ISO, YMD'",conn,tx))
            await setup.ExecuteNonQueryAsync();
        await using(var role=new NpgsqlCommand("""
            SELECT current_user::text,session_user::text,pg_has_role(current_user,'gc_issuer_runtime','MEMBER'),
                pg_has_role(current_user,'gc_portal_requester','MEMBER'),pg_has_role(current_user,'gc_portal_reviewer','MEMBER'),
                (SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user)
            """,conn,tx))
        await using(var row=await role.ExecuteReaderAsync())
        {
            if(!await row.ReadAsync() || row.GetString(0)!="gc_recovery_reader" || row.GetString(1)!="gc_recovery_reader" ||
                row.GetBoolean(2)||row.GetBoolean(3)||row.GetBoolean(4)||row.GetBoolean(5))
                throw new InvalidOperationException("Independent read-only recovery identity required.");
        }
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Add(string value)
        {
            var bytes=Encoding.UTF8.GetBytes(value);
            Span<byte> length=stackalloc byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length,bytes.Length);
            hash.AppendData(length);hash.AppendData(bytes);
        }
        Add("GatewayCore.AuthorityLedger.v1");
        foreach(var (table,order) in Tables)
        {
            Add(table);
            // Identifiers are compile-time constants, not operator input.
            await using var cmd=new NpgsqlCommand($"SELECT to_jsonb(t)::text FROM public.{table} t ORDER BY {order}",conn,tx);
            await using var reader=await cmd.ExecuteReaderAsync();
            long count=0;
            while(await reader.ReadAsync()){Add(reader.GetString(0));count=checked(count+1);}
            Add(count.ToString(CultureInfo.InvariantCulture));
        }
        await tx.CommitAsync();
        return Convert.ToHexString(hash.GetHashAndReset());
    }
    public static async Task<string> Sign(NpgsqlDataSource db,ECDsa key,string keyId,DateTimeOffset now)
    {
        ValidateKey(key,keyId);
        var prefix="GCB1."+keyId+"."+now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)+"."+await Digest(db);
        return prefix+"."+B64(key.SignData(Encoding.ASCII.GetBytes(prefix),HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }
    public static async Task Verify(NpgsqlDataSource db,string checkpoint,ECDsa publicKey,string expectedKeyId)
    {
        ValidateKey(publicKey,expectedKeyId);
        if(checkpoint.Length is < 1 or > 512 || checkpoint.Any(c=>c is < (char)33 or > (char)126))
            throw new InvalidDataException("Invalid checkpoint encoding.");
        var p=checkpoint.Split('.');
        if(p.Length!=5||p[0]!="GCB1"||p[1]!=expectedKeyId||
            !long.TryParse(p[2],NumberStyles.None,CultureInfo.InvariantCulture,out var epoch)||
            epoch is < 0 or > 4102444800L || epoch.ToString(CultureInfo.InvariantCulture)!=p[2]||
            p[3].Length!=64||p[3].Any(c=>c is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new InvalidDataException("Invalid checkpoint fields.");
        var sig=Convert.FromBase64String(p[4].Replace('-','+').Replace('_','/').PadRight((p[4].Length+3)/4*4,'='));
        if(sig.Length!=64||B64(sig)!=p[4]||!publicKey.VerifyData(Encoding.ASCII.GetBytes(string.Join(".",p,0,4)),sig,
            HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new CryptographicException("Recovery checkpoint signature rejected.");
        var actual=await Digest(db);
        if(!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual),Convert.FromHexString(p[3])))
            throw new CryptographicException("Ledger differs from trusted external checkpoint; keep signing fenced.");
    }
    private static void ValidateKey(ECDsa key,string id)
    {
        if(id.Length is < 1 or > 80 || id.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not ('-' or '_'))||
            key.ExportParameters(false).Curve.Oid.Value!="1.2.840.10045.3.1.7")
            throw new ArgumentException("Invalid independent recovery key.");
    }
    private static string B64(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
}
