using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

internal sealed class OperatorPasswordSessions
{
    internal const string CookieName = "__Host-gc-operator";
    internal static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);
    private readonly Dictionary<string, Entry> entries;
    private readonly PasswordHasher<PortalOperator> hasher = new();

    private sealed class Entry(string hash)
    {
        public readonly string Hash = hash;
        public readonly object Gate = new();
        public int Failures;
        public DateTimeOffset Window;
        public byte[]? TokenHash;
        public DateTimeOffset Expires;
    }

    internal OperatorPasswordSessions(string path, IEnumerable<PortalOperator> actors)
    {
        var info = new FileInfo(path);
        if (info.Length is < 1 or > 65536) throw new InvalidDataException("Invalid password hash file.");
        var hashes = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllBytes(path))
            ?? throw new InvalidDataException("Missing password hashes.");
        var ids = actors.Select(x => x.Id).ToHashSet(StringComparer.Ordinal);
        if (!ids.SetEquals(hashes.Keys) || hashes.Values.Distinct(StringComparer.Ordinal).Count() != hashes.Count)
            throw new InvalidDataException("Each operator needs a separate password hash.");
        entries = new(StringComparer.Ordinal);
        foreach (var (id, hash) in hashes)
        {
            // ASP.NET Identity V3 format; bounded cost and strong minimum.
            if (hash is null || hash.Length is < 60 or > 512)
                throw new InvalidDataException("Invalid operator password hash.");
            var bytes = Convert.FromBase64String(hash);
            if (bytes.Length < 61 || bytes[0] != 1 ||
                BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(1,4)) != 2 ||
                BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(5,4)) is < 100000 or > 2000000 ||
                BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(9,4)) != 16 || bytes.Length != 61)
                throw new InvalidDataException("Require ASP.NET Identity V3 SHA512 password hashes.");
            entries.Add(id, new Entry(hash));
        }
    }

    internal string? Login(PortalOperator actor, string? password, DateTimeOffset now)
    {
        var e = entries[actor.Id];
        lock (e.Gate)
        {
            if (now < e.Window || now - e.Window >= TimeSpan.FromMinutes(5))
            { e.Window = now; e.Failures = 0; }
            if (e.Failures >= 5) return null;
            if (password is null || password.Length is < 16 or > 256 ||
                hasher.VerifyHashedPassword(actor, e.Hash, password) == PasswordVerificationResult.Failed)
            { e.Failures++; return null; }
            e.Failures = 0;
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            e.TokenHash = SHA256.HashData(Encoding.ASCII.GetBytes(token));
            e.Expires = now + Lifetime;
            return token;
        }
    }

    internal bool Valid(PortalOperator actor, string? token, DateTimeOffset now)
    {
        var e = entries[actor.Id];
        lock (e.Gate)
            return token is { Length: 64 } && e.TokenHash is not null &&
                now < e.Expires && now >= e.Expires - Lifetime &&
                CryptographicOperations.FixedTimeEquals(e.TokenHash, SHA256.HashData(Encoding.ASCII.GetBytes(token)));
    }

    internal void Logout(PortalOperator actor, string? token, DateTimeOffset now)
    {
        var e = entries[actor.Id];
        lock (e.Gate)
            if (Valid(actor, token, now)) { e.TokenHash = null; e.Expires = default; }
    }

    internal static CookieOptions Cookie() => new()
    {
        Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, Path = "/",
        IsEssential = true, MaxAge = Lifetime
    };

    internal static void ProvisionPasswordHash()
    {
        if (Console.IsInputRedirected) throw new InvalidOperationException("Use an interactive console.");
        Console.Error.Write("Enter a unique operator password (16–256 characters): ");
        var chars = new List<char>();
        try
        {
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace) { if (chars.Count > 0) chars.RemoveAt(chars.Count - 1); }
                else if (!char.IsControl(key.KeyChar) && chars.Count < 256) chars.Add(key.KeyChar);
            }
            Console.Error.WriteLine();
            if (chars.Count < 16) throw new InvalidOperationException("Password too short.");
            var buffer = chars.ToArray();
            try { Console.WriteLine(new PasswordHasher<PortalOperator>().HashPassword(new("provisioning","requester"),new string(buffer))); }
            finally { Array.Clear(buffer); }
        }
        finally { for (int i = 0; i < chars.Count; i++) chars[i] = '\0'; chars.Clear(); }
    }
}
