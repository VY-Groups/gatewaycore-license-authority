using System.Security.Cryptography;
using System.Diagnostics;
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
foreach (var role in new[] { "gc_portal_requester", "gc_portal_reviewer", "gc_issuer_runtime", "gc_recovery_reader" })
    await Exec(admin, $"CREATE ROLE {role} LOGIN PASSWORD 'disposable-ci-{role}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT");
await Exec(admin, File.ReadAllText("tools/LicensePortal/migration-002-authority-rotation.sql"));
await Exec(admin, File.ReadAllText("tools/LicensePortal/runtime-grants.sql"));
await Exec(admin, File.ReadAllText("tools/AuthorityRecovery/recovery-grants.sql"));
await Exec(admin, File.ReadAllText("tools/LicensePortal/migration-003-billing.sql"));
NpgsqlDataSource Role(string role) => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(cfg.ConnectionString)
    { Username = role, Password = "disposable-ci-" + role }.ConnectionString);
await using var requester = Role("gc_portal_requester");
await using var reviewer = Role("gc_portal_reviewer");
await using var issuer = Role("gc_issuer_runtime");
var now = DateTimeOffset.UtcNow;
using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var key = signingKey.ExportPkcs8PrivateKey();
using var nextSigningKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
var trust = new Dictionary<string,byte[]> { ["test-pg"] = signingKey.ExportSubjectPublicKeyInfo(),
    ["test-pg-next"]=nextSigningKey.ExportSubjectPublicKeyInfo() };
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
    async Task<Guid> Invoice(string subscription,Guid? renewal=null)
    {
        var id=Guid.NewGuid();
        if(renewal is Guid job)
            await Exec(requester,"""
                INSERT INTO gc_billing_invoices(id,subscription_id,renewal_job_id,terms_hash,currency,amount_minor,requested_by)
                VALUES($1,$2,$3,public.gc_billing_terms($2,$3),'INR',10000,'alice')
                """,id,subscription,job);
        else
            await Exec(requester,"""
                INSERT INTO gc_billing_invoices(id,subscription_id,terms_hash,currency,amount_minor,requested_by)
                VALUES($1,$2,public.gc_billing_terms($2,NULL::uuid),'INR',10000,'alice')
                """,id,subscription);
        return id;
    }
    Task<int> Pay(Guid id,string reference,long amount=10000)=>Exec(reviewer,"""
        UPDATE gc_billing_invoices SET state='paid',decided_by='bob',decided_at=now(),payment_reference=$2,paid_minor=$3
        WHERE id=$1 AND state='pending'
        """,id,reference,amount);
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
    await Denied(()=>Execute(first),"approved but unpaid commercial issuance denied");
    var invoice=await Invoice("ci-license");
    await SqlDenied(()=>Exec(requester,"UPDATE gc_billing_invoices SET state='paid',decided_by='bob',decided_at=now(),payment_reference='forged',paid_minor=10000 WHERE id=$1",invoice),"requester cannot mark invoice paid");
    await SqlDenied(()=>Exec(issuer,"UPDATE gc_billing_invoices SET state='paid' WHERE id=$1",invoice),"issuer cannot mark invoice paid");
    await SqlDenied(()=>Pay(invoice,"payment-ci-first",9999),"underpayment denied");
    await SqlDenied(()=>Exec(reviewer,"UPDATE gc_billing_invoices SET state='paid',decided_by='alice',decided_at=now(),payment_reference='self',paid_minor=10000 WHERE id=$1",invoice),"self settlement denied");
    await Denied(()=>Execute(first),"pending invoice cannot authorize issuance");
    Check(await Pay(invoice,"payment-ci-first")==1,"independent exact settlement");
    await SqlDenied(()=>Exec(reviewer,"UPDATE gc_billing_invoices SET state='void',decided_by='bob',decided_at=now(),payment_reference=NULL,paid_minor=NULL WHERE id=$1",invoice),"paid invoice immutable");
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
    Check(await Approve(renewal)==1,"renewal approved independently");
    await Denied(()=>Execute(renewal),"prior paid terms do not cover changed renewal");
    var renewalInvoice=await Invoice("ci-license",renewal);
    await SqlDenied(()=>Exec(reviewer,"UPDATE gc_billing_invoices SET amount_minor=1 WHERE id=$1",renewalInvoice),"reviewer cannot alter agreed invoice amount");
    // Duplicate cleared payment references fail atomically.
    try{await Pay(renewalInvoice,"payment-ci-first");throw new Exception("FAIL: reused payment reference");}
    catch(PostgresException e) when(e.SqlState=="23505"){Check(true,"payment reference replay denied");}
    Check(await Pay(renewalInvoice,"payment-ci-renew")==1,"renewal independently settled");
    Check(await Execute(renewal) is null,"approved paid terms renewal committed");
    await Denied(() => Execute(stale),"stale approved terms cannot issue");
    var next=await Request(winnerIndex,2);
    Check(await Approve(next)==1,"renewal approved");
    var updated=stores[winnerIndex].Import(Encoding.ASCII.GetBytes((await Execute(next))!),now);
    Check(updated.Revision==2 && !updated.Allows("l7") && updated.Allows("monitoring"),"signed feature downgrade advances revision");
    var rotation=Guid.NewGuid();
    var approvedHash=Convert.ToHexString(SHA256.HashData(nextSigningKey.ExportSubjectPublicKeyInfo()));
    var rotationPayload=new RotationApproval("test-pg-next",approvedHash,true);
    await Exec(requester,"""
        INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,proposed_terms,requested_by)
        VALUES($1,'ci-license','rotate_authority',2,$2::jsonb,'alice')
        """,rotation,JsonSerializer.Serialize(rotationPayload));
    Task<string?> Rotate(ECDsa nextKey)=>new ApprovedJobExecutor(issuer,signingKey,"test-pg").Execute(rotation,now,nextKey,"test-pg-next");
    await Denied(()=>Rotate(nextSigningKey),"unapproved authority rotation denied");
    Check(await Approve(rotation)==1,"rotation independently approved");
    await Denied(()=>Execute(rotation),"rotation without both keys denied");
    using(var wrong=ECDsa.Create(ECCurve.NamedCurves.nistP256))
    {
        try { await Rotate(wrong);throw new Exception("FAIL: wrong rotation key accepted"); }
        catch(CryptographicException){Check(true,"wrong replacement key denied");}
    }
    await SqlDenied(()=>Exec(issuer,"UPDATE gc_issuer_authority SET key_id='unapproved' WHERE subscription_id='ci-license'"),"direct authority mutation denied");
    Check(await Rotate(nextSigningKey) is null,"approved key rotation committed");
    Check(await Rotate(nextSigningKey) is null,"rotation replay idempotent");
    Check((long)(await Scalar(admin,"SELECT count(*) FROM gc_issuer_key_history"))! == 2,"both authority fingerprints recorded");
    var nextJob=await Request(winnerIndex,3);
    Check(await Approve(nextJob)==1,"post-rotation issuance approved");
    try { await Execute(nextJob);throw new Exception("FAIL: old signing key still accepted"); }
    catch(CryptographicException){Check(true,"old signer cannot issue after rotation");}
    Task<string?> ExecuteNew(Guid job)=>new ApprovedJobExecutor(issuer,nextSigningKey,"test-pg-next").Execute(job,now);
    var rotatedBytes=Encoding.ASCII.GetBytes((await ExecuteNew(nextJob))!);
    var oldOnly=new OfflineLicenseVerifier(new Dictionary<string,byte[]> { ["test-pg"]=signingKey.ExportSubjectPublicKeyInfo() });
    try{oldOnly.Verify(rotatedBytes,updated.InstallationKeySha256,now);throw new Exception("FAIL: unstaged trust accepted");}
    catch(InvalidDataException){Check(true,"old-only customer trust rejects new signer");}
    updated=stores[winnerIndex].Import(rotatedBytes,now);
    Check(updated.Revision==3 && updated.Allows("monitoring"),"staged dual-trust customer accepts new signer without losing allocation");
    var revoke=Guid.NewGuid();
    await Exec(requester, """
        INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,allocation_id,requested_by)
        VALUES($1,'ci-license','revoke',3,$2,'alice')
        """,revoke,updated.AllocationId);
    Check(await Approve(revoke)==1,"revocation approved");
    var revoked=(await ExecuteNew(revoke))!;
    Check(stores[winnerIndex].ImportRevocation(Encoding.ASCII.GetBytes(revoked),now).Validity==LicenseValidity.Revoked,"database-signed revocation accepted");
    Check(await ExecuteNew(revoke)==revoked,"revocation retry exact bytes");
    var retry=await Request(winnerIndex,3);
    Check(await Approve(retry)==1,"revoked renewal request approved");
    await Denied(() => ExecuteNew(retry),"revoked allocation cannot renew");
    var replacement=await Request(loserIndex,3);
    Check(await Approve(replacement)==1,"replacement request approved");
    await Denied(() => ExecuteNew(replacement),"revoked offline seat cannot silently be reused");
    await SqlDenied(() => Exec(issuer,"DELETE FROM gc_portal_audit"),"worker cannot erase audit");
    await SqlDenied(() => Exec(requester,"UPDATE gc_portal_audit SET action='edited'"),"portal cannot rewrite audit");
    Check((long)(await Scalar(admin,"SELECT count(*) FROM gc_issuer_results"))! == 6,"only committed successful jobs have results");
    // Separate actual customer SDK executable, built from pinned other repository.
    var customerDll=Environment.GetEnvironmentVariable("GC_CUSTOMER_INTEROP_DLL")
        ?? throw new InvalidOperationException("Independent customer build required.");
    var interop=root+"-interop";
    Directory.CreateDirectory(interop);
    try
    {
        var publicTrust=Path.Combine(interop,"public-trust.json");
        File.WriteAllBytes(publicTrust,JsonSerializer.SerializeToUtf8Bytes(trust));
        var customerState=Path.Combine(interop,"customer-state");
        async Task<JsonElement?> Customer(string action,string? file=null,int expected=0)
        {
            var info=new ProcessStartInfo("dotnet"){RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
            foreach(var arg in new[]{customerDll,action,customerState,publicTrust})info.ArgumentList.Add(arg);
            if(file is not null)info.ArgumentList.Add(file);
            using var process=Process.Start(info)??throw new InvalidOperationException("Could not start customer verifier.");
            var stdout=process.StandardOutput.ReadToEndAsync();
            var stderr=process.StandardError.ReadToEndAsync();
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(45));
            try{await process.WaitForExitAsync(deadline.Token);}
            catch(OperationCanceledException){process.Kill(true);throw;}
            var output=await stdout;var error=await stderr;
            if(process.ExitCode!=expected)throw new Exception("Independent customer process exit "+process.ExitCode+": "+error);
            if(string.IsNullOrWhiteSpace(output))return null;
            using var json=JsonDocument.Parse(output);
            return json.RootElement.Clone();
        }
        await Exec(requester,"""
            INSERT INTO gc_subscriptions(id,customer_id,deployment_id,edition,max_nodes,max_sites,expires_at,features)
            VALUES('interop-license','ci-customer','interop-deployment','standard',1,1,$1,ARRAY['l7','monitoring'])
            """,now.AddDays(30));
        var independentInvoice=await Invoice("interop-license");
        Check(await Pay(independentInvoice,"payment-ci-interop")==1,"independent SDK contract paid");
        async Task<string> IssueIndependent(string filename)
        {
            var requestPath=Path.Combine(interop,filename+".gcr");
            await Customer(filename=="first"?"provision":"request",requestPath);
            var bytes=File.ReadAllBytes(requestPath);
            var parsed=OfflineActivationRequest.Verify(bytes);
            var job=Guid.NewGuid();
            await Exec(requester,"""
                INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,site_id,request_id,installation_hash,request_file,requested_by)
                VALUES($1,'interop-license','issue',1,'dc',$2,$3,$4,'alice')
                """,job,parsed.RequestId,parsed.InstallationKeySha256,Encoding.ASCII.GetString(bytes));
            Check(await Approve(job)==1,"independent customer request approved");
            var signed=await ExecuteNew(job)??throw new Exception("Missing independently issued envelope.");
            var path=Path.Combine(interop,filename+".lic");
            File.WriteAllText(path,signed,Encoding.ASCII);
            return path;
        }
        var firstPath=await IssueIndependent("first");
        var independentActive=(await Customer("import",firstPath))!.Value;
        Check(independentActive.GetProperty("revision").GetInt64()==1 &&
            independentActive.GetProperty("validity").GetString()=="Active","actual other-repository SDK imports database-signed license");
        var secondPath=await IssueIndependent("second");
        var independentRenewed=(await Customer("import",secondPath))!.Value;
        Check(independentRenewed.GetProperty("revision").GetInt64()==2 &&
            independentRenewed.GetProperty("allocationId").GetString()==independentActive.GetProperty("allocationId").GetString(),
            "cross-repository renewal preserves allocation");
        await Customer("import",firstPath,1);
        Check((await Customer("inspect"))!.Value.GetProperty("revision").GetInt64()==2,"independent process restart rejects rollback");
        var revokeJob=Guid.NewGuid();
        await Exec(requester,"""
            INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,allocation_id,requested_by)
            VALUES($1,'interop-license','revoke',1,$2,'alice')
            """,revokeJob,independentRenewed.GetProperty("allocationId").GetString()!);
        Check(await Approve(revokeJob)==1,"independent customer revocation approved");
        var revocationPath=Path.Combine(interop,"revoked.gcv");
        File.WriteAllText(revocationPath,(await ExecuteNew(revokeJob))!,Encoding.ASCII);
        Check((await Customer("revoke",revocationPath))!.Value.GetProperty("validity").GetString()=="Revoked",
            "independent customer imports real database-signed revocation");
        Check((await Customer("inspect"))!.Value.GetProperty("validity").GetString()=="Revoked","revocation persists in separate customer process");
        await Customer("import",secondPath,1);
        Console.WriteLine("CROSS_REPOSITORY_OFFLINE_INTEROP_PASS");
    }
    finally{Directory.Delete(interop,true);}
    await RecoveryAcceptance.Run(cfg,admin,nextSigningKey,revoke,revoked,replacement,retry);
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
