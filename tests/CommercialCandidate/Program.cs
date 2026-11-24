using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Licensing;
using GatewayCore.ReleaseAuthority;
using GatewayCore.LicenseIssuerWorker;
using Npgsql;

if(Environment.GetEnvironmentVariable("CI")!="true" || Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" ||
    Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted" ||
    args.Length!=1 || args[0] is not ("packages" or "postgres"))
    throw new InvalidOperationException("Disposable hosted CI only.");
var customer=Path.GetFullPath("customer-contract");
const string commit="5083204affcacd6a3cca321fdcf3331853d80018";
var actual=(await Run("git",["rev-parse","HEAD"],customer)).Out.Trim();
Check(actual==commit,"customer checkout matches exact frozen candidate revision");
var root=Path.Combine(Path.GetTempPath(),"gc-integrated-candidate-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
if(OperatingSystem.IsLinux())File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
try
{
    using var entitlement=ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var release=ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var trust=Path.Combine(root,"entitlement-public.json");
    var releaseTrust=Path.Combine(root,"release-public.json");
    File.WriteAllBytes(trust,JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string,byte[]>
        {["integrated-license-ci"]=entitlement.ExportSubjectPublicKeyInfo()}));
    File.WriteAllBytes(releaseTrust,JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string,byte[]>
        {["integrated-release-ci"]=release.ExportSubjectPublicKeyInfo()}));
    var projects=new (string Path,string Dll)[]{
        ("control-center/GatewayCoreYarp.csproj","GatewayCoreYarp.dll"),
        ("control-center/GatewayAgent/GatewayCoreGatewayAgent.csproj","GatewayCoreGatewayAgent.dll"),
        ("engines/L4/L4Proxy.csproj","L4Proxy.dll"),
        ("engines/GslbDns/GslbDns.csproj","GslbDns.dll"),
        ("engines/GslbObserver/GslbObserver.csproj","GslbObserver.dll")};
    var outputs=new Dictionary<string,string>(StringComparer.Ordinal);
    foreach(var item in projects)
    {
        var package=Path.Combine(root,Path.GetFileNameWithoutExtension(item.Dll));
        await Run("dotnet",["publish",Path.Combine(customer,item.Path),"-c","Release","-o",package,
            "-p:GatewayCoreCommercial=true","-p:GatewayCoreReleasePackage=true",
            "-p:GatewayCoreTrustFile="+trust,"-p:GatewayCoreReleaseTrustFile="+releaseTrust,
            "-p:GatewayCoreReleaseSourceCommit="+commit],customer,timeout:240);
        var binary=Path.Combine(package,item.Dll);
        outputs[item.Dll]=binary;
        var unsigned=await Run("dotnet",[binary,"--verify-release"],root,expected:78);
        Check(unsigned.Err.Contains("Commercial package integrity rejected",StringComparison.Ordinal),"actual unsigned "+item.Dll+" rejected");
        Check(ReleaseManifestBuilder.SignPackage(package,commit,"integrated-release-ci",release)==commit,
            "actual company release signer signs "+item.Dll);
        var verified=await Run("dotnet",[binary,"--verify-release"],root);
        Check(verified.Out.Contains("COMMERCIAL_RELEASE_INTEGRITY_PASS "+commit,StringComparison.Ordinal),
            "actual published "+item.Dll+" verifies independently signed inventory");
        var extra=Path.Combine(package,"unsigned-extra.txt");
        File.WriteAllText(extra,"disposable negative test");
        await Run("dotnet",[binary,"--verify-release"],root,expected:78);
        File.Delete(extra);
        await Run("dotnet",[binary,"--verify-release"],root);
        Check(true,item.Dll+" rejects unsigned extra file and recovers exact package");
    }
    if(args[0]=="postgres")
    {
        if(!OperatingSystem.IsLinux())throw new InvalidOperationException("PostgreSQL acceptance requires Linux CI.");
        var cfg=new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("GC_PG_TEST")??"");
        if(cfg.Host!="127.0.0.1" || cfg.Database!="gatewaycore_ci" || cfg.Username!="postgres")
            throw new InvalidOperationException("Disposable database only.");
        NpgsqlDataSource Role(string role)=>NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(cfg.ConnectionString)
            {Username=role,Password="disposable-ci-"+role}.ConnectionString);
        await using var requester=Role("gc_portal_requester");
        await using var reviewer=Role("gc_portal_reviewer");
        await using var issuer=Role("gc_issuer_runtime");
        var l4=outputs["L4Proxy.dll"];
        var state=Path.Combine(root,"real-installation");
        var env=new Dictionary<string,string>{{"GATEWAYCORE_ENGINE_LICENSE_DIR",state}};
        var request=Path.Combine(root,"request.gcr");
        await Run("dotnet",[l4,"--license-init"],root,env:env);
        await Run("dotnet",[l4,"--license-request",request],root,env:env);
        var requestBytes=File.ReadAllBytes(request);
        var parsed=OfflineActivationRequest.Verify(requestBytes);
        var now=DateTimeOffset.UtcNow;
        await Exec(requester,"INSERT INTO gc_customers(id,name) VALUES('candidate-ci','Synthetic Candidate Customer')");
        await Exec(requester,"""
            INSERT INTO gc_subscriptions(id,customer_id,deployment_id,edition,max_nodes,max_sites,expires_at,features)
            VALUES('candidate-ci','candidate-ci','candidate-deployment','standard',1,1,$1,ARRAY['l7','l4'])
            """,now.AddDays(30));
        var invoice=Guid.NewGuid();
        await Exec(requester,"""
            INSERT INTO gc_billing_invoices(id,subscription_id,terms_hash,currency,amount_minor,requested_by)
            VALUES($1,'candidate-ci',public.gc_billing_terms('candidate-ci',NULL::uuid),'INR',10000,'alice')
            """,invoice);
        var job=Guid.NewGuid();
        await Exec(requester,"""
            INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,site_id,request_id,installation_hash,request_file,requested_by)
            VALUES($1,'candidate-ci','issue',1,'dc',$2,$3,$4,'alice')
            """,job,parsed.RequestId,parsed.InstallationKeySha256,Encoding.ASCII.GetString(requestBytes));
        await Approve(reviewer,job);
        var worker=new ApprovedJobExecutor(issuer,entitlement,"integrated-license-ci");
        try{await worker.Execute(job,now);throw new Exception("FAIL: unpaid candidate issued");}
        catch(InvalidOperationException){Check(true,"actual worker denies unpaid product activation request");}
        Check(await Exec(reviewer,"""
            UPDATE gc_billing_invoices SET state='paid',decided_by='bob',decided_at=now(),
            payment_reference='candidate-ci-cleared',paid_minor=10000 WHERE id=$1 AND state='pending'
            """,invoice)==1,"independent settlement accepted");
        var envelope=await worker.Execute(job,now)??throw new InvalidOperationException("Missing signed envelope.");
        var licensePath=Path.Combine(root,"active.lic");
        File.WriteAllText(licensePath,envelope,Encoding.ASCII);
        var verifiedLicense=new OfflineLicenseVerifier(new Dictionary<string,byte[]>
            {["integrated-license-ci"]=entitlement.ExportSubjectPublicKeyInfo()})
            .Verify(Encoding.ASCII.GetBytes(envelope),parsed.InstallationKeySha256,now);
        Check(verifiedLicense.SiteId=="dc"&&verifiedLicense.Allows("l4"),"actual company worker issues site-bound paid entitlement");
        await Run("dotnet",[l4,"--license-import",licensePath],root,env:env);
        // Independent runtime process uses only embedded public trust. Origin,
        // local config and signed license are outside the immutable package.
        using var origin=new TcpListener(IPAddress.Loopback,0);
        origin.Start();
        var originPort=((IPEndPoint)origin.LocalEndpoint).Port;
        int proxyPort;
        using(var reservation=new TcpListener(IPAddress.Loopback,0))
        {reservation.Start();proxyPort=((IPEndPoint)reservation.LocalEndpoint).Port;}
        var config=Path.Combine(root,"l4.json");
        File.WriteAllBytes(config,JsonSerializer.SerializeToUtf8Bytes(new{allowNonLoopbackListeners=false,
            tcp=new[]{new{name="integrated",listenHost="127.0.0.1",listenPort=proxyPort,
                backends=new[]{new{host="127.0.0.1",port=originPort}}}},
            udp=Array.Empty<object>()}));
        using var echoStop=new CancellationTokenSource();
        var echo=Task.Run(async()=>
        {
            try
            {
                while(!echoStop.IsCancellationRequested)
                {
                    using var client=await origin.AcceptTcpClientAsync(echoStop.Token);
                    using var stream=client.GetStream();
                    var bytes=new byte[4096];
                    int read;
                    while((read=await stream.ReadAsync(bytes,echoStop.Token))>0)
                        await stream.WriteAsync(bytes.AsMemory(0,read),echoStop.Token);
                }
            }
            catch(OperationCanceledException) when(echoStop.IsCancellationRequested){}
            catch(IOException) when(echoStop.IsCancellationRequested){}
        });
        using var process=Process.Start(Info("dotnet",[l4,config],root,env))??throw new InvalidOperationException("Missing L4 process.");
        var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        try
        {
            TcpClient? connected=null;
            for(var i=0;i<40&&connected is null;i++)
            {
                if(process.HasExited)throw new InvalidOperationException("Signed licensed engine exited: "+await stderr);
                var client=new TcpClient();
                try
                {
                    using var attempt=new CancellationTokenSource(TimeSpan.FromSeconds(1));
                    await client.ConnectAsync(IPAddress.Loopback,proxyPort,attempt.Token);
                    connected=client;
                }
                catch(Exception e) when(e is SocketException or OperationCanceledException)
                {client.Dispose();await Task.Delay(150);}
            }
            using var established=connected??throw new InvalidOperationException("Licensed engine never listened.");
            using var stream=established.GetStream();
            using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(4)))
            {
                var sent=Encoding.ASCII.GetBytes("paid-company-signed-runtime");
                await stream.WriteAsync(sent,deadline.Token);
                var got=new byte[sent.Length];
                await stream.ReadExactlyAsync(got,deadline.Token);
                Check(got.SequenceEqual(sent),"actual independently signed customer L4 forwards paid licensed traffic");
            }
            var revokeJob=Guid.NewGuid();
            await Exec(requester,"""
                INSERT INTO gc_license_jobs(id,subscription_id,kind,expected_terms_revision,allocation_id,requested_by)
                VALUES($1,'candidate-ci','revoke',1,$2,'alice')
                """,revokeJob,verifiedLicense.AllocationId);
            await Approve(reviewer,revokeJob);
            var revoked=await worker.Execute(revokeJob,DateTimeOffset.UtcNow)??throw new InvalidOperationException("Missing signed revocation.");
            var revocation=Path.Combine(root,"revoked.gcv");File.WriteAllText(revocation,revoked,Encoding.ASCII);
            bool imported=false;
            for(var i=0;i<10&&!imported;i++)
            {
                var result=await Run("dotnet",[l4,"--license-revoke",revocation],root,env:env,expected:null);
                imported=result.Exit==0;
                if(!imported)await Task.Delay(200);
            }
            Check(imported,"actual customer imports database-backed company revocation");
            using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(7)))
                await process.WaitForExitAsync(deadline.Token);
            Check(process.ExitCode==78,"revoked running customer engine terminates established forwarding");
            using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2)))
            {
                try{Check(await stream.ReadAsync(new byte[1],deadline.Token)==0,"established licensed stream closed on revocation");}
                catch(IOException){Check(true,"established licensed stream reset on revocation");}
            }
            var restart=await Run("dotnet",[l4,config],root,env:env,expected:null);
            Check(restart.Exit!=0&&restart.Err.Contains("Active engine feature entitlement required",StringComparison.Ordinal),
                "revocation persists across actual independently signed binary restart");
            Console.WriteLine("INTEGRATED_COMPANY_SIGNED_PAID_RUNTIME_REVOCATION_PASS");
        }
        finally
        {
            if(!process.HasExited){process.Kill(true);await process.WaitForExitAsync();}
            echoStop.Cancel();
            await echo;
            await stdout;await stderr;
        }
    }
    Console.WriteLine("INTEGRATED_COMMERCIAL_CANDIDATE_ACCEPTANCE_PASS");
}
finally{Directory.Delete(root,true);}

static void Check(bool ok,string name)
{if(!ok)throw new InvalidOperationException("FAIL: "+name);Console.WriteLine("PASS: "+name);}
static ProcessStartInfo Info(string executable,IEnumerable<string> args,string directory,Dictionary<string,string>? env=null)
{
    var info=new ProcessStartInfo(executable){WorkingDirectory=directory,UseShellExecute=false,
        RedirectStandardOutput=true,RedirectStandardError=true};
    foreach(var arg in args)info.ArgumentList.Add(arg);
    if(env is not null)foreach(var row in env)info.Environment[row.Key]=row.Value;
    return info;
}
static async Task<(int Exit,string Out,string Err)> Run(string executable,string[] args,string directory,
    int? expected=0,Dictionary<string,string>? env=null,int timeout=60)
{
    using var process=Process.Start(Info(executable,args,directory,env))??throw new InvalidOperationException("Missing child process.");
    var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
    using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(timeout));
    try{await process.WaitForExitAsync(deadline.Token);}
    catch(OperationCanceledException){process.Kill(true);await process.WaitForExitAsync();throw;}
    var result=(process.ExitCode,await stdout,await stderr);
    if(expected is not null&&result.Item1!=expected)
        throw new InvalidOperationException("Unexpected disposable child exit "+result.Item1+": "+result.Item2+" "+result.Item3);
    return result;
}
static async Task<int> Exec(NpgsqlDataSource db,string sql,params object[] args)
{
    await using var cmd=db.CreateCommand(sql);
    foreach(var value in args)cmd.Parameters.AddWithValue(value);
    return await cmd.ExecuteNonQueryAsync();
}
static async Task Approve(NpgsqlDataSource reviewer,Guid job)
{
    Check(await Exec(reviewer,"UPDATE gc_license_jobs SET state='approved',approved_by='bob',approved_at=now() WHERE id=$1 AND state='pending'",job)==1,
        "independent operator approved actual product request");
}
