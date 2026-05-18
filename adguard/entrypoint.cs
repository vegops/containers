#:package BCrypt.Net-Next@4.2.0
#:property PublishAot=true
#:property InvariantGlobalization=true
#:property StripSymbols=true
#:property OptimizationPreference=Size
#:property IlcOptimizationPreference=Size
#:property StackTraceSupport=false
#:property UseSystemResourceKeys=true
#:property IlcTrimMetadata=true
#:property AssemblyName=entrypoint

using System.Runtime.InteropServices;
using System.Security.Cryptography;

const string AppBin = "/usr/bin/AdGuardHome";
const string ConfigPath = "/adguard/etc/config.yaml";
const string DefaultConfigPath = "/usr/share/adguard/config.yaml";
const string ConfigEnv = "ADGUARD_CONFIG";
const string PasswordEnv = "ADGUARD_PASSWORD";
const string DefaultPasswordHash = "$2b$12$xzIFiVMrq2jv5NH5pNNQSuEK84FDNI4PoiJbKIhZqUe1Ld/v1BI9W";
const string Alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

try
{
    EnsureConfig();
    var configuredPassword = Environment.GetEnvironmentVariable(PasswordEnv);
    if (!string.IsNullOrEmpty(configuredPassword))
        SetAdminPassword(configuredPassword);
    else
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

    var inlineConfig = Environment.GetEnvironmentVariable(ConfigEnv);
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

    var password = RandomString(16);
    var updated = content.Replace(DefaultPasswordHash, Bcrypt(password), StringComparison.Ordinal);
    File.WriteAllText(ConfigPath, updated);
    Console.WriteLine($"AdGuard Home admin password: {password}");
}

static void SetAdminPassword(string password)
{
    var lines = File.ReadAllLines(ConfigPath);
    for (var i = 0; i < lines.Length; i++)
    {
        if (lines[i].Trim() != "- name: admin")
            continue;

        for (var j = i + 1; j < lines.Length; j++)
        {
            var trimmed = lines[j].TrimStart();
            if (trimmed.StartsWith("- name:", StringComparison.Ordinal))
                break;

            if (!trimmed.StartsWith("password:", StringComparison.Ordinal))
                continue;

            var indent = lines[j][..^trimmed.Length];
            lines[j] = $"{indent}password: {Bcrypt(password)}";
            File.WriteAllLines(ConfigPath, lines);
            Console.WriteLine($"AdGuard Home admin password configured from {PasswordEnv}");
            return;
        }
    }

    throw new Exception($"could not find admin password in {ConfigPath}");
}

static string Bcrypt(string password)
{
    var hash = BCrypt.Net.BCrypt.HashPassword(password, 12);
    return hash.StartsWith("$2a$", StringComparison.Ordinal) ? "$2b$" + hash[4..] : hash;
}

static string RandomString(int length)
{
    var bytes = RandomNumberGenerator.GetBytes(length);
    var chars = new char[length];

    for (var i = 0; i < bytes.Length; i++)
        chars[i] = Alphabet[bytes[i] % Alphabet.Length];

    return new string(chars);
}

static void Exec()
{
    var args = Environment.GetCommandLineArgs();
    var appArgs = args.Length > 1
        ? args[1..]
        : new[]
        {
            "--config", ConfigPath,
            "--pidfile", "/adguard/run/adguard.pid",
            "--work-dir", "/adguard/var",
            "--no-check-update",
        };

    var argv = new string?[appArgs.Length + 2];
    argv[0] = "AdGuardHome";
    Array.Copy(appArgs, 0, argv, 1, appArgs.Length);
    argv[^1] = null;

    var result = NativeMethods.execv(AppBin, argv);
    throw new Exception($"execv({AppBin}) failed: errno {Marshal.GetLastPInvokeError()}, result {result}");
}

static class NativeMethods
{
    [DllImport("libc", SetLastError = true)]
    internal static extern int execv(string filename, string?[] argv);
}
