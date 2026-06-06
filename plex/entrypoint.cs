#:property PublishAot=true
#:property InvariantGlobalization=true
#:property StripSymbols=true
#:property OptimizationPreference=Size
#:property IlcOptimizationPreference=Size
#:property StackTraceSupport=false
#:property UseSystemResourceKeys=true
#:property IlcTrimMetadata=true
#:property AssemblyName=entrypoint

using System.Diagnostics;
using System.Runtime.InteropServices;

const string AppBin = "/usr/lib/plexmediaserver/Plex Media Server";
const string LogDir = "/plex/etc/Library/Application Support/Plex Media Server/Logs";
const string MainLog = "/plex/etc/Library/Application Support/Plex Media Server/Logs/Plex Media Server.log";
const string StdoutLogLevelEnv = "PLEX_STDOUT_LOG_LEVEL";
const int SigTerm = 15;

using var shutdown = new CancellationTokenSource();
Process? plex = null;
var forwardingSignal = false;

using var sigTerm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
{
    context.Cancel = true;
    RequestShutdown();
});
using var sigInt = PosixSignalRegistration.Create(PosixSignal.SIGINT, context =>
{
    context.Cancel = true;
    RequestShutdown();
});

try
{
    Directory.CreateDirectory(LogDir);

    var stdoutLogLevel = ReadStdoutLogLevel();
    var logTask = stdoutLogLevel == LogLevel.Off
        ? Task.CompletedTask
        : TailMainLog(stdoutLogLevel, shutdown.Token);
    plex = StartPlex();

    await plex.WaitForExitAsync();
    shutdown.Cancel();

    try
    {
        await logTask.WaitAsync(TimeSpan.FromSeconds(2));
    }
    catch
    {
        // The process is exiting; log tail shutdown is best-effort.
    }

    Environment.Exit(plex.ExitCode);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.Exit(1);
}

void RequestShutdown()
{
    shutdown.Cancel();
    if (plex is not { HasExited: false } || forwardingSignal)
        return;

    forwardingSignal = true;
    _ = NativeMethods.kill(plex.Id, SigTerm);
}

static Process StartPlex()
{
    var startInfo = new ProcessStartInfo(AppBin)
    {
        UseShellExecute = false,
    };

    foreach (var arg in Environment.GetCommandLineArgs().Skip(1))
        startInfo.ArgumentList.Add(arg);

    return Process.Start(startInfo) ?? throw new InvalidOperationException($"failed to start {AppBin}");
}

static LogLevel ReadStdoutLogLevel()
{
    var value = Environment.GetEnvironmentVariable(StdoutLogLevelEnv);
    if (string.IsNullOrWhiteSpace(value))
        return LogLevel.Info;

    return value.Trim().ToUpperInvariant() switch
    {
        "ALL" or "DEBUG" => LogLevel.Debug,
        "INFO" => LogLevel.Info,
        "WARN" or "WARNING" => LogLevel.Warn,
        "ERROR" or "ERR" => LogLevel.Error,
        "OFF" or "NONE" or "FALSE" or "0" => LogLevel.Off,
        _ => LogLevel.Info,
    };
}

static async Task TailMainLog(LogLevel minLevel, CancellationToken token)
{
    var position = File.Exists(MainLog) ? new FileInfo(MainLog).Length : 0;
    var currentLineLevel = LogLevel.Info;

    while (!token.IsCancellationRequested)
    {
        try
        {
            if (!File.Exists(MainLog))
            {
                await Task.Delay(500, token);
                continue;
            }

            var length = new FileInfo(MainLog).Length;
            if (length < position)
                position = 0;

            if (length > position)
            {
                using var stream = new FileStream(MainLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                stream.Seek(position, SeekOrigin.Begin);
                using var reader = new StreamReader(stream);

                string? line;
                while ((line = await reader.ReadLineAsync()) is not null)
                {
                    currentLineLevel = ReadLineLevel(line) ?? currentLineLevel;
                    if (currentLineLevel >= minLevel)
                        Console.WriteLine(line);
                }

                position = stream.Position;
                await Console.Out.FlushAsync();
            }

            await Task.Delay(500, token);
        }
        catch (OperationCanceledException)
        {
            break;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"log tail failed: {ex.Message}");
            await Task.Delay(1000, token);
        }
    }
}

static LogLevel? ReadLineLevel(string line)
{
    if (line.Contains("DEBUG -", StringComparison.Ordinal))
        return LogLevel.Debug;
    if (line.Contains("INFO -", StringComparison.Ordinal))
        return LogLevel.Info;
    if (line.Contains("WARN -", StringComparison.Ordinal) || line.Contains("WARNING -", StringComparison.Ordinal))
        return LogLevel.Warn;
    if (line.Contains("ERROR -", StringComparison.Ordinal))
        return LogLevel.Error;

    return null;
}

enum LogLevel
{
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Off = 4,
}

static class NativeMethods
{
    [DllImport("libc", SetLastError = true)]
    internal static extern int kill(int pid, int sig);
}
