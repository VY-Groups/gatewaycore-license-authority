using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Licensing;
using GatewayCore.LicenseAuthority;
using GatewayCore.LicenseIssuerWorker;
using Npgsql;

if (Environment.GetEnvironmentVariable("CI") != "true" ||
    Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true")
    throw new InvalidOperationException("Disposable CI only.");
var cfg = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("GC_PG_TEST") ??
    throw new InvalidOperationException("Missing disposable database."));
if (cfg.Host != "127.0.0.1" || cfg.Database != "gatewaycore_ci" || cfg.Username != "postgres")
    throw new InvalidOperationException("Not a disposable database.");
await using var admin = NpgsqlDataSource.Create(cfg.ConnectionString);
await Exec(admin, File.ReadAllText("tools/LicensePortal/schema.sql"));
foreach (var role in new[] { "gc_portal_requester", "gc_portal_reviewer", "gc_issuer_runtime" })
    await Exec(admin, $"CREATE ROLE {role} LOGIN PASSWORD 'disposable-ci-runtime' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT");
await Exec(admin, File.ReadAllText("tools/LicensePortal/runtime-grants.sql"));
NpgsqlDataSource Role(string role) => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(cfg.ConnectionString)
    { Username = role, Password = "disposable-ci-runtime" }.ConnectionString);
await using var requester = Role("gc_portal_requester");
await using var reviewer = Role("gc_portal_reviewer");
await using var issuer = Role("gc_issuer_runtime");
var now = DateTimeOffset.UtcNow;
using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var key = signingKey.ExportPkcs8PrivateKey();
var trust = new Dictionary<string,byte[]> { ["test-pg"] = signingKey.ExportSubjectPublicKeyInfo() };
var verifier = new OfflineLicenseVerifier(trust);
var root = Path.Combine(Path.GetTempPath(), "gc-pg-" + Guid.NewGuid().ToString("N"));
var dirs = Enumerable.Range(0,4).Select(i => root + "-" + i).ToArray();
try
{
    var stores = dirs.Select(d => new OfflineLicenseStore(d, verifier)).ToArray();
    foreach (var s in stores) s.Initialize();
    await Exec(requester, "INSERT INTO gc_customers(id,name) VALUES('ci-customer','Synthetic Customer')");
    await Exec(requester, """
        INSERT INTO gc_subscriptions(id,customer_id,deployment_id,edition,max_nodes,max_sites,expires_at,features)
        VALUES('ci-license','ci-customer','ci-deployment','standard',1,1,$1,ARRAY['l7','monitoring'])
        """, now.AddDays(30));
    async Task<Guid> Request(int index, long terms = 1)
    {
        var bytes = stores[index].ExportActivationRequest();
        var parsed = OfflineActivationRequest.Verify(bytes);
        var id = Guid.NewGuid();
        await Exec(requester, """
            INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,site_id,request_id,installation_hash,request_file,requested_by)
            VALUES($1,'ci-license','issue',$2,'dc',$3,$4,$5,'alice')
            """, id, terms, parsed.RequestId, parsed.InstallationKeySha256, Encoding.ASCII.GetString(bytes));
        return id;
    }
    Task<int> Approve(Guid id) => Exec(reviewer, """
        UPDATE gc_license_jobs SET state='approved',approved_by='bob',approved_at=now()
        WHERE id=$1 AND state='pending'
        """, id);
    async Task<string?> Execute(Guid id)
    {
        using var s = ECDsa.Create();
        s.ImportPkcs8PrivateKey(key,out _);
        return await new ApprovedJobExecutor(issuer,s,"test-pg").Execute(id,now);
    }
    var first = await Request(0);
    var second = await Request(1);
    await Denied(() => Execute(first), "pending job cannot sign");
    await SqlDenied(() => Exec(requester,"UPDATE gc_license_jobs SET state='approved',approved_by='bob',approved_at=now() WHERE id=$1",first),"requester cannot approve");
    await SqlDenied(() => Exec(issuer,"UPDATE gc_license_jobs SET state='approved',approved_by='bob',approved_at=now() WHERE id=$1",first),"worker cannot approve");
    await SqlDenied(() => Exec(reviewer,"UPDATE gc_license_jobs SET request_file='edited' WHERE id=$1",first),"reviewer cannot edit request");
    await SqlDenied(() => Exec(requester,"INSERT INTO gc_issuer_results(job_id,envelope) VALUES($1,'forged')",first),"portal cannot write signed results");
    await SqlDenied(() => Exec(reviewer,"UPDATE gc_license_jobs SET state='approved',approved_by='alice',approved_at=now() WHERE id=$1",first),"self approval denied");
    Check(await Approve(first)==1 && await Approve(second)==1,"distinct reviewer approvals");
    await SqlDenied(() => Exec(reviewer,"UPDATE gc_license_jobs SET state='rejected',approved_by='bob',approved_at=now() WHERE id=$1",first),"approved job immutable");
    async Task<(Guid Id,string? Envelope)> Attempt(Guid id)
    {
        try { return (id,await Execute(id)); }
        catch (InvalidOperationException) { return (id,null); }
    }
    var race = await Task.WhenAll(Attempt(first),Attempt(second));
    Check(race.Count(x=>x.Envelope is not null)==1,"concurrent jobs cannot oversell one seat");
    var winner = race.Single(x=>x.Envelope is not null);
    var winnerIndex = winner.Id==first?0:1;
    var loserIndex = 1-winnerIndex;
    var envelope = winner.Envelope!;
    var active = stores[winnerIndex].Import(Encoding.ASCII.GetBytes(envelope),now);
    Check(active.Allows("l7") && active.Revision==1,"database-signed envelope activates customer SDK");
    Check(await Execute(winner.Id)==envelope,"idempotent committed issuance returns exact bytes");
    Check((long)(await Scalar(admin,"SELECT count(*) FROM gc_issuer_allocations"))! == 1,"one committed allocation");
    await Denied(() => Execute(race.Single(x=>x.Id!=winner.Id).Id),"loser remains denied");
    var stale = await Request(winnerIndex);
    Check(await Approve(stale)==1,"old terms job approved");
    var renewal=Guid.NewGuid();
    var terms=new Subscription("ci-license","ci-customer","ci-deployment","standard",1,1,now.AddDays(60).ToUnixTimeSeconds(),new[]{"monitoring"});
    await Exec(requester, """
        INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,proposed_terms,requested_by)
        VALUES($1,'ci-license','renew_terms',1,$2::jsonb,'alice')
        """,renewal,JsonSerializer.Serialize(terms));
    Check(await Approve(renewal)==1 && await Execute(renewal) is null,"approved terms renewal committed");
    await Denied(() => Execute(stale),"stale approved terms cannot issue");
    var next=await Request(winnerIndex,2);
    Check(await Approve(next)==1,"renewal approved");
    var updated=stores[winnerIndex].Import(Encoding.ASCII.GetBytes((await Execute(next))!),now);
    Check(updated.Revision==2 && !updated.Allows("l7") && updated.Allows("monitoring"),"signed feature downgrade advances revision");
    var revoke=Guid.NewGuid();
    await Exec(requester, """
        INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,allocation_id,requested_by)
        VALUES($1,'ci-license','revoke',2,$2,'alice')
        """,revoke,updated.AllocationId);
    Check(await Approve(revoke)==1,"revocation approved");
    var revoked=(await Execute(revoke))!;
    Check(stores[winnerIndex].ImportRevocation(Encoding.ASCII.GetBytes(revoked),now).Validity==LicenseValidity.Revoked,"database-signed revocation accepted");
    Check(await Execute(revoke)==revoked,"revocation retry exact bytes");
    var retry=await Request(winnerIndex,2);
    Check(await Approve(retry)==1,"revoked renewal request approved");
    await Denied(() => Execute(retry),"revoked allocation cannot renew");
    var replacement=await Request(loserIndex,2);
    Check(await Approve(replacement)==1,"replacement request approved");
    await Denied(() => Execute(replacement),"revoked offline seat cannot silently be reused");
    await SqlDenied(() => Exec(issuer,"DELETE FROM gc_portal_audit"),"worker cannot erase audit");
    await SqlDenied(() => Exec(requester,"UPDATE gc_portal_audit SET action='edited'"),"portal cannot rewrite audit");
    Check((long)(await Scalar(admin,"SELECT count(*) FROM gc_issuer_results"))! == 4,"only committed successful jobs have results");
    Console.WriteLine("POSTGRES_AUTHORITY_ACCEPTANCE_PASS");
}
finally
{
    CryptographicOperations.ZeroMemory(key);
    foreach (var d in dirs) if (Directory.Exists(d)) Directory.Delete(d,true);
}
static async Task<int> Exec(NpgsqlDataSource ds,string sql,params object[] args)
{
    await using var cmd=ds.CreateCommand(sql);
    foreach (var arg in args) cmd.Parameters.AddWithValue(arg);
    return await cmd.ExecuteNonQueryAsync();
}
static async Task<object?> Scalar(NpgsqlDataSource ds,string sql)
{
    await using var cmd=ds.CreateCommand(sql);
    return await cmd.ExecuteScalarAsync();
}
static void Check(bool condition,string name)
{
    if(!condition) throw new Exception("FAIL: "+name);
    Console.WriteLine("PASS: "+name);
}
static async Task Denied(Func<Task> action,string name)
{
    try { await action(); }
    catch (InvalidOperationException) { Check(true,name); return; }
    throw new Exception("FAIL: "+name);
}
static async Task SqlDenied(Func<Task> action,string name)
{
    try { await action(); }
    catch (PostgresException e) when (e.SqlState is "42501" or "23514") { Check(true,name); return; }
    throw new Exception("FAIL: "+name);
}
