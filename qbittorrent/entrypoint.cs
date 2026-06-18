#:property PublishAot=true
#:property InvariantGlobalization=true
#:property StripSymbols=true
#:property OptimizationPreference=Size
#:property IlcOptimizationPreference=Size
#:property StackTraceSupport=false
#:property UseSystemResourceKeys=true
#:property IlcTrimMetadata=true
#:property AssemblyName=entrypoint

using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

const string AppBin = "/usr/bin/qbittorrent";
const string ConfigPath = "/qbittorrent/etc/qBittorrent.conf";
const string DefaultConfigPath = "/usr/share/qbittorrent/qBittorrent.conf";
const string LockFile = "/qbittorrent/etc/lockfile";
const string DefaultPasswordHash = "@ByteArray(188J/h/wfAYQ9H+mTl/7lA==:j/+e2SwJUi9g+IPiEG2+Pix9W0IOv2c20QjrmBUhr4TBUXO3fcMv6leeU6qK8834xiq8fngh8ShwYDfYO0w6lg==)";
const string Alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

try
{
    RemoveStaleLockFile();
    EnsureConfig();
    RotateDefaultPassword();
    Exec();
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.Exit(1);
}

static void EnsureConfig()
{
    Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);

    var inlineConfig = Environment.GetEnvironmentVariable("QBITTORRENT_CONFIG");
    if (!string.IsNullOrEmpty(inlineConfig))
    {
        File.WriteAllText(ConfigPath, inlineConfig);
        return;
    }

    if (!File.Exists(ConfigPath))
        File.Copy(DefaultConfigPath, ConfigPath);
}

static void RotateDefaultPassword()
{
    var content = File.ReadAllText(ConfigPath);
    if (!content.Contains(DefaultPasswordHash, StringComparison.Ordinal))
        return;

    var password = RandomString(12);
    var salt = RandomString(16);

    var hash = Rfc2898DeriveBytes.Pbkdf2(
        password,
        Encoding.UTF8.GetBytes(salt),
        100000,
        HashAlgorithmName.SHA512,
        64);

    var replacement = $"@ByteArray({Convert.ToBase64String(Encoding.UTF8.GetBytes(salt))}:{Convert.ToBase64String(hash)})";
    var updated = content.Replace(DefaultPasswordHash, replacement, StringComparison.Ordinal);

    File.WriteAllText(ConfigPath, updated);
    Console.WriteLine($"qBittorrent admin password: {password}");
}

static string RandomString(int length)
{
    var bytes = RandomNumberGenerator.GetBytes(length);
    var chars = new char[length];

    for (var i = 0; i < bytes.Length; i++)
        chars[i] = Alphabet[bytes[i] % Alphabet.Length];

    return new string(chars);
}

static void RemoveStaleLockFile()
{
    if (!File.Exists(LockFile))
        return;

    var firstLine = File.ReadLines(LockFile).FirstOrDefault()?.Trim();
    if (int.TryParse(firstLine, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) &&
        IsQbittorrentProcess(pid))
    {
        throw new InvalidOperationException($"qBittorrent is already running with PID {pid}");
    }

    File.Delete(LockFile);
    Console.Error.WriteLine($"removed stale qBittorrent lock file: {LockFile}");
}

static bool IsQbittorrentProcess(int pid)
{
    if (pid <= 0)
        return false;

    try
    {
        var commandLine = File.ReadAllText($"/proc/{pid}/cmdline");
        return commandLine.Contains("qbittorrent", StringComparison.OrdinalIgnoreCase);
    }
    catch
    {
        return false;
    }
}

static void Exec()
{
    var args = Environment.GetCommandLineArgs();
    var argv = new string?[args.Length + 1];
    argv[0] = "qbittorrent";
    Array.Copy(args, 1, argv, 1, args.Length - 1);
    argv[^1] = null;

    var result = NativeMethods.execv(AppBin, argv);
    throw new Exception($"execv({AppBin}) failed: errno {Marshal.GetLastPInvokeError()}, result {result}");
}

static class NativeMethods
{
    [DllImport("libc", SetLastError = true)]
    internal static extern int execv(string filename, string?[] argv);
}
