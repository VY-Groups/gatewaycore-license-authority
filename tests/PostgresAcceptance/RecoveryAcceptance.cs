using System.Diagnostics;
using System.Security.Cryptography;
using GatewayCore.AuthorityRecovery;
using GatewayCore.LicenseIssuerWorker;
using Npgsql;

internal static class RecoveryAcceptance
{
    internal static async Task Run(NpgsqlConnectionStringBuilder cfg,NpgsqlDataSource admin,
        ECDsa currentKey,Guid revokedJob,string revokedEnvelope,Guid rejectedReplacement,Guid rejectedRenewal)
    {
        if(!OperatingSystem.IsLinux()||cfg.Host!="127.0.0.1"||cfg.Database!="gatewaycore_ci"||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")
            throw new InvalidOperationException("Disposable Linux recovery acceptance only.");
        var root=Path.Combine(Path.GetTempPath(),"gc-authority-restore-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        const string target="gatewaycore_restore_ci";
        async Task Change(NpgsqlDataSource ds,string sql)
        {
            await using var cmd=ds.CreateCommand(sql);await cmd.ExecuteNonQueryAsync();
        }
        NpgsqlDataSource Role(string database,string role)=>NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(cfg.ConnectionString)
            {Database=database,Username=role,Password="disposable-ci-"+role}.ConnectionString);
        async Task RunTool(string name,params string[] args)
        {
            var info=new ProcessStartInfo(name){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(var arg in args)info.ArgumentList.Add(arg);
            info.Environment["PGPASSWORD"]=cfg.Password;
            using var process=Process.Start(info)??throw new InvalidOperationException("Missing PostgreSQL recovery tool.");
            var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(90));
            try{await process.WaitForExitAsync(timeout.Token);}
            catch(OperationCanceledException){process.Kill(true);throw;}
            await stdout;
            var error=await stderr;
            if(process.ExitCode!=0)throw new InvalidOperationException(name+" failed: "+error);
        }
        static void Check(bool ok,string label)
        {if(!ok)throw new Exception("FAIL: "+label);Console.WriteLine("PASS: "+label);}
        static async Task Denied(Func<Task> action,string label)
        {
            try{await action();}
            catch(InvalidOperationException){Check(true,label);return;}
            throw new Exception("FAIL: "+label);
        }
        var created=false;
        try
        {
            using var recoveryKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var recoveryPublic=ECDsa.Create();
            recoveryPublic.ImportSubjectPublicKeyInfo(recoveryKey.ExportSubjectPublicKeyInfo(),out _);
            await using var source=Role(cfg.Database,"gc_recovery_reader");
            var checkpoint=await LedgerCheckpoint.Sign(source,recoveryKey,"recovery-ci",DateTimeOffset.UtcNow);
            await LedgerCheckpoint.Verify(source,checkpoint,recoveryPublic,"recovery-ci");
            try{await Change(source,"DELETE FROM public.gc_portal_audit");throw new Exception("FAIL: recovery role can delete");}
            catch(PostgresException e) when(e.SqlState=="42501"){Check(true,"recovery database role read-only");}
            var dump=Path.Combine(root,"ledger.dump");
            await RunTool("pg_dump","--host=127.0.0.1","--port="+cfg.Port,"--username=postgres",
                "--dbname="+cfg.Database,"--format=custom","--file="+dump);
            await Change(admin,"CREATE DATABASE "+target);
            created=true;
            await RunTool("pg_restore","--host=127.0.0.1","--port="+cfg.Port,"--username=postgres",
                "--dbname="+target,"--exit-on-error","--single-transaction",dump);
            await using(var restored=Role(target,"gc_recovery_reader"))
            await using(var restoredIssuer=Role(target,"gc_issuer_runtime"))
            {
                await LedgerCheckpoint.Verify(restored,checkpoint,recoveryPublic,"recovery-ci");
                Check(true,"actual PostgreSQL dump/restore matches independently signed ledger checkpoint");
                var pass=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                var encrypted=currentKey.ExportEncryptedPkcs8PrivateKey(pass,
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc,HashAlgorithmName.SHA256,100000));
                try
                {
                    using var recovered=ECDsa.Create();
                    try{recovered.ImportEncryptedPkcs8PrivateKey("wrong-disposable-password",encrypted,out _);
                        throw new Exception("FAIL: wrong backup password accepted");}
                    catch(CryptographicException){Check(true,"encrypted signing key backup rejects wrong password");}
                    recovered.ImportEncryptedPkcs8PrivateKey(pass,encrypted,out var read);
                    Check(read==encrypted.Length&&recovered.ExportSubjectPublicKeyInfo().SequenceEqual(currentKey.ExportSubjectPublicKeyInfo()),
                        "encrypted signing key backup restores exact current authority");
                    var worker=new ApprovedJobExecutor(restoredIssuer,recovered,"test-pg-next");
                    Check(await worker.Execute(revokedJob,DateTimeOffset.UtcNow)==revokedEnvelope,"restored issuer retains exact committed revocation");
                    await Denied(()=>worker.Execute(rejectedReplacement,DateTimeOffset.UtcNow),"restored revoked seat cannot be reassigned");
                    await Denied(()=>worker.Execute(rejectedRenewal,DateTimeOffset.UtcNow),"restored revoked allocation cannot renew");
                }
                finally{CryptographicOperations.ZeroMemory(encrypted);}
                await Change(admin,"INSERT INTO public.gc_portal_audit(actor,action,subject) VALUES('recovery-ci','checkpoint-advance','synthetic')");
                var latest=await LedgerCheckpoint.Sign(source,recoveryKey,"recovery-ci",DateTimeOffset.UtcNow);
                try{await LedgerCheckpoint.Verify(restored,latest,recoveryPublic,"recovery-ci");throw new Exception("FAIL: stale snapshot accepted");}
                catch(CryptographicException){Check(true,"stale restored snapshot rejected against latest external checkpoint");}
                using var wrong=ECDsa.Create(ECCurve.NamedCurves.nistP256);
                try{await LedgerCheckpoint.Verify(restored,checkpoint,wrong,"recovery-ci");throw new Exception("FAIL: wrong recovery key accepted");}
                catch(CryptographicException){Check(true,"independent checkpoint trust rejects wrong signer");}
            }
            Console.WriteLine("AUTHORITY_BACKUP_RESTORE_ACCEPTANCE_PASS");
        }
        finally
        {
            if(created)await Change(admin,"DROP DATABASE "+target+" WITH (FORCE)");
            Directory.Delete(root,true);
        }
    }
}
