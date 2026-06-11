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
using System.Globalization;
using System.Runtime.InteropServices;

const string NodeBin = "/usr/bin/node";
const string BundlePath = "/opt/configarr/bundle.cjs";
const string AppRoot = "/configarr";
const string ConfigPath = "/configarr/etc/config.yml";
const string DefaultConfigPath = "/usr/share/configarr/config.yml";
const string PidFile = "/configarr/run/configarr.pid";
const string ScheduleEnv = "CONFIGARR_SCHEDULE";

Process? child = null;

try
{
    var cliArgs = Environment.GetCommandLineArgs();
    if (cliArgs.Length > 1 && cliArgs[1] == "--ping")
        Environment.Exit(Ping() ? 0 : 1);

    using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
    {
        ctx.Cancel = true;
        Stop(child);
        Environment.Exit(0);
    });
    using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx =>
    {
        ctx.Cancel = true;
        Stop(child);
        Environment.Exit(0);
    });

    EnsureConfig();

    var schedule = Environment.GetEnvironmentVariable(ScheduleEnv);
    if (string.IsNullOrWhiteSpace(schedule))
        Environment.Exit(Run(ref child));
    schedule = NormalizeSchedule(schedule);

    ScheduleLog($"enabled: {schedule}");
    var cron = new CronSchedule(schedule);

    Run(ref child);

    while (true)
    {
        var next = cron.Next(DateTimeOffset.UtcNow);
        var delay = next - DateTimeOffset.UtcNow;
        if (delay < TimeSpan.Zero)
            delay = TimeSpan.Zero;

        ScheduleLog($"next run at {next:O}");
        Thread.Sleep(delay);
        Run(ref child);
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.Exit(1);
}

static int Run(ref Process? child)
{
    Directory.CreateDirectory(Path.GetDirectoryName(PidFile)!);

    using var proc = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = NodeBin,
            WorkingDirectory = AppRoot,
            UseShellExecute = false,
        },
    };

    proc.StartInfo.ArgumentList.Add(BundlePath);
    foreach (var arg in Environment.GetCommandLineArgs().Skip(1))
        proc.StartInfo.ArgumentList.Add(arg);

    proc.Start();
    child = proc;
    File.WriteAllText(PidFile, proc.Id.ToString(CultureInfo.InvariantCulture));

    try
    {
        proc.WaitForExit();
    }
    finally
    {
        child = null;
        File.Delete(PidFile);
    }

    return proc.ExitCode;
}

static void EnsureConfig()
{
    Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
    if (!File.Exists(ConfigPath))
        File.Copy(DefaultConfigPath, ConfigPath);
}

static void Stop(Process? proc)
{
    if (proc is null || proc.HasExited)
        return;

    try
    {
        proc.Kill(entireProcessTree: true);
    }
    catch
    {
        // Best effort during container shutdown.
    }
    finally
    {
        File.Delete(PidFile);
    }
}

static bool Ping()
{
    if (!File.Exists(PidFile))
        return false;

    var raw = File.ReadAllText(PidFile).Trim();
    return int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) && IsPidRunning(pid);
}

static bool IsPidRunning(int pid) => kill(pid, 0) == 0 || Marshal.GetLastPInvokeError() == 1;

static string NormalizeSchedule(string schedule)
{
    schedule = schedule.Trim();
    if (schedule.Length >= 2 && ((schedule[0] == '"' && schedule[^1] == '"') || (schedule[0] == '\'' && schedule[^1] == '\'')))
        schedule = schedule[1..^1].Trim();
    return schedule;
}

static void ScheduleLog(string message) => Console.Error.WriteLine($"INFO {message}");

[DllImport("libc", SetLastError = true)]
static extern int kill(int pid, int sig);

sealed class CronSchedule
{
    private readonly bool[] _minutes;
    private readonly bool[] _hours;
    private readonly bool[] _days;
    private readonly bool[] _months;
    private readonly bool[] _weekdays;

    public CronSchedule(string expression)
    {
        var fields = expression.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length != 5)
            throw new Exception($"invalid cron expression: {expression}");

        _minutes = Parse(fields[0], 0, 59);
        _hours = Parse(fields[1], 0, 23);
        _days = Parse(fields[2], 1, 31);
        _months = Parse(fields[3], 1, 12);
        _weekdays = Parse(fields[4].Replace("7", "0", StringComparison.Ordinal), 0, 6);
    }

    public DateTimeOffset Next(DateTimeOffset from)
    {
        var next = new DateTimeOffset(from.Year, from.Month, from.Day, from.Hour, from.Minute, 0, TimeSpan.Zero)
            .AddMinutes(1);

        for (var i = 0; i < 366 * 5 * 24 * 60; i++)
        {
            if (_months[next.Month] && _days[next.Day] && _weekdays[(int)next.DayOfWeek] &&
                _hours[next.Hour] && _minutes[next.Minute])
                return next;

            next = next.AddMinutes(1);
        }

        throw new Exception("cron expression has no occurrence in the next 5 years");
    }

    private static bool[] Parse(string field, int min, int max)
    {
        var values = new bool[max + 1];
        foreach (var part in field.Split(','))
        {
            var slash = part.IndexOf('/');
            var range = slash < 0 ? part : part[..slash];
            var step = slash < 0 ? 1 : ParseInt(part[(slash + 1)..], $"invalid cron step: {part}");
            if (step < 1)
                throw new Exception($"invalid cron step: {part}");

            var (start, end) = Bounds(range, min, max);
            for (var value = start; value <= end; value += step)
                values[value] = true;
        }
        return values;
    }

    private static (int start, int end) Bounds(string range, int min, int max)
    {
        if (range == "*")
            return (min, max);

        var dash = range.IndexOf('-');
        if (dash < 0)
        {
            var value = ParseInt(range, $"invalid cron value: {range}");
            if (value < min || value > max)
                throw new Exception($"cron value out of range: {range}");
            return (value, value);
        }

        var start = ParseInt(range[..dash], $"invalid cron range: {range}");
        var end = ParseInt(range[(dash + 1)..], $"invalid cron range: {range}");
        if (start < min || end > max || start > end)
            throw new Exception($"cron range out of range: {range}");

        return (start, end);
    }

    private static int ParseInt(string value, string message)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
            throw new Exception(message);
        return parsed;
    }
}
