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

const string AppBin = "/usr/bin/lnd";
const string ConfigPath = "/lnd/etc/lnd.conf";
const string DefaultConfigPath = "/usr/share/lnd/lnd.sample.conf";

try
{
    Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
    if (!File.Exists(ConfigPath))
        File.Copy(DefaultConfigPath, ConfigPath);
    Exec();
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.Exit(1);
}

static void Exec()
{
    var defaults = new[]
    {
        "--logging.file.disable",
        "--logging.console.no-timestamps",
        "--logging.console.call-site=short",
        "--lnddir=/lnd/var",
        "--configfile=/lnd/etc/lnd.conf",
    };

    var args = Environment.GetCommandLineArgs();
    var argv = new string?[defaults.Length + args.Length + 1];
    argv[0] = "lnd";
    Array.Copy(defaults, 0, argv, 1, defaults.Length);
    Array.Copy(args, 1, argv, defaults.Length + 1, args.Length - 1);

    var result = NativeMethods.execv(AppBin, argv);
    throw new Exception($"execv({AppBin}) failed: errno {Marshal.GetLastPInvokeError()}, result {result}");
}

static class NativeMethods
{
    [DllImport("libc", SetLastError = true)]
    internal static extern int execv(string filename, string?[] argv);
}
