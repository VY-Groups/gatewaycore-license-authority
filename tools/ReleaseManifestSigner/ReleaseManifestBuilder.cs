using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Licensing;

namespace GatewayCore.ReleaseAuthority;

public static class ReleaseManifestBuilder
{
    // Run only against an immutable, access-controlled, reviewed staging package.
    // This is release signing, not entitlement issuance.
    public static string SignPackage(string package, string sourceCommit, string keyId, ECDsa signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        var root = Path.GetFullPath(package);
        var manifestPath = Path.Combine(root, ReleaseIntegrityVerifier.ManifestName);
        if (sourceCommit.Length != 40 || sourceCommit.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            keyId.Length is < 1 or > 80 || keyId.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')) ||
            signer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new ArgumentException("Require exact source commit and P-256 release key.");
        if (File.Exists(manifestPath) || Directory.Exists(manifestPath))
            throw new InvalidOperationException("Never overwrite an existing release manifest.");
        CheckPath(root, true);
        var rows = new List<FileRecord>();
        var pending = new Stack<string>();
        pending.Push(root);
        var visited = 0;
        while (pending.Count != 0)
        {
            var directory = pending.Pop();
            CheckPath(directory, true);
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++visited > 40000) throw new InvalidDataException("Package inventory exceeds limit.");
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Package links forbidden.");
                var relative = Path.GetRelativePath(root,path).Replace(Path.DirectorySeparatorChar,'/');
                if (relative.Length is < 1 or > 240 || relative.Split('/').Any(part =>
                    part.Length is < 1 or > 120 || part is "." or ".." || part.EndsWith('.') ||
                    part.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_' or '+'))))
                    throw new InvalidDataException("Invalid package path.");
                if ((attributes & FileAttributes.Directory) != 0) { pending.Push(path); continue; }
                var extension = Path.GetExtension(path);
                if (new[] { ".pem",".key",".pk8",".pfx",".p12",".lic",".gcr",".gcv",".db",".dump" }
                    .Contains(extension,StringComparer.OrdinalIgnoreCase) ||
                    Path.GetFileName(path).StartsWith(".env",StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Secret or mutable authority material forbidden in release package.");
                using var input = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                var size = input.Length;
                if (size > 2L*1024*1024*1024 || rows.Count >= 20000)
                    throw new InvalidDataException("Package file or inventory exceeds limit.");
                rows.Add(new(relative,size,Convert.ToHexString(SHA256.HashData(input))));
            }
        }
        if (rows.Count == 0 || rows.Select(x => x.path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != rows.Count)
            throw new InvalidDataException("Empty or case-colliding package.");
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, product = "GatewayCore",
            sourceCommit, files = rows.OrderBy(x=>x.path,StringComparer.Ordinal).ToArray() });
        var prefix = "GCM1."+keyId+"."+B64(payload);
        var text = prefix+"."+B64(signer.SignData(Encoding.ASCII.GetBytes(prefix),HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        if (text.Length > 8*1024*1024) throw new InvalidDataException("Manifest exceeds verifier limit.");
        var created = false;
        try
        {
            using (var output = new FileStream(manifestPath,FileMode.CreateNew,FileAccess.Write,FileShare.None))
            {
                created = true;
                output.Write(Encoding.ASCII.GetBytes(text));
                output.Flush(true);
            }
            // Verify the exact bytes and entire package with the customer SDK.
            return new ReleaseIntegrityVerifier(new Dictionary<string,byte[]> { [keyId] = signer.ExportSubjectPublicKeyInfo() })
                .Verify(root,sourceCommit);
        }
        catch
        {
            if (created) File.Delete(manifestPath);
            throw;
        }
    }
    private static string B64(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
    private static void CheckPath(string path,bool directory)
    {
        var attributes=File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint)!=0 || ((attributes & FileAttributes.Directory)!=0)!=directory)
            throw new InvalidDataException("Unsafe package path.");
    }
    private sealed record FileRecord(string path,long size,string sha256);
}
