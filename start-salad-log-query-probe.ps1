[CmdletBinding()]
param(
    [ValidateSet(
        'experiment',
        'single',
        'saturated-branch-trace',
        'production-recursion-trace',
        'page-min-before-probe',
        'page-min-before-capture'
    )]
    [string]$Operation = 'experiment'
)

# Replace this local placeholder only when the operator is ready for a separately
# authorized manual live probe. Never put a real key in source-control history.
$SaladApiKey = 'PASTE_SALAD_API_KEY_HERE'

$script:SaladProbeRoot = $PSScriptRoot
$script:SaladProbePipeConnectTimeoutMilliseconds = 15000
$script:SaladProbeRunTimeoutSeconds = @{
    experiment = 150
    single = 30
    'saturated-branch-trace' = 260
    'production-recursion-trace' = 500
    'page-min-before-probe' = 80
    'page-min-before-capture' = 900
}
$script:SaladProbeTestMarker = $null
$script:SaladProbeTestBehavior = $null
$script:SaladProbeLastPipeName = $null
$script:SaladProbeLastChildPid = $null

$script:SaladProbePipeNativeSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public static class SaladLogProbeSecurePipe
{
    private const uint PipeAccessOutbound = 0x00000002;
    private const uint FileFlagFirstPipeInstance = 0x00080000;
    private const uint PipeTypeByte = 0x00000000;
    private const uint PipeReadModeByte = 0x00000000;
    private const uint PipeWait = 0x00000000;
    private const uint PipeRejectRemoteClients = 0x00000008;
    private const int ErrorPipeConnected = 535;

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maxInstances,
        uint outBufferSize,
        uint inBufferSize,
        uint defaultTimeout,
        ref SecurityAttributes securityAttributes
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ConnectNamedPipe(SafeFileHandle pipe, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(SafeFileHandle pipe, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafeFileHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool LocalFree(IntPtr memory);

    public static SafeFileHandle CreateCurrentUserOnlyServer(string pipeName, string userSid)
    {
        IntPtr descriptor = IntPtr.Zero;
        uint descriptorSize = 0;
        string sddl = "D:P(A;;GA;;;" + userSid + ")";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, 1, out descriptor, out descriptorSize))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            SecurityAttributes attributes = new SecurityAttributes();
            attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));
            attributes.SecurityDescriptor = descriptor;
            attributes.InheritHandle = 0;

            string fullName = @"\\.\pipe\" + pipeName;
            SafeFileHandle handle = CreateNamedPipe(
                fullName,
                PipeAccessOutbound | FileFlagFirstPipeInstance,
                PipeTypeByte | PipeReadModeByte | PipeWait | PipeRejectRemoteClients,
                1,
                0,
                4096,
                0,
                ref attributes
            );
            if (handle == null || handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                if (handle != null) handle.Dispose();
                throw new Win32Exception(error);
            }
            return handle;
        }
        finally
        {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }

    public static bool WaitForConnection(SafeFileHandle handle, int timeoutMilliseconds)
    {
        if (handle == null || handle.IsInvalid || timeoutMilliseconds < 1)
            throw new ArgumentException("pipe configuration invalid");

        Task<bool> task = Task.Run(() =>
        {
            try
            {
                bool connected = ConnectNamedPipe(handle, IntPtr.Zero);
                if (connected) return true;
                return Marshal.GetLastWin32Error() == ErrorPipeConnected;
            }
            catch
            {
                return false;
            }
        });
        if (!task.Wait(timeoutMilliseconds))
        {
            CancelIoEx(handle, IntPtr.Zero);
            try { task.Wait(5000); } catch { }
            return false;
        }
        try { return task.GetAwaiter().GetResult(); }
        catch { return false; }
    }

    public static uint GetClientProcessId(SafeFileHandle handle)
    {
        uint processId;
        if (!GetNamedPipeClientProcessId(handle, out processId))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return processId;
    }
}
'@

function Write-SaladProbeFailure {
    param([Parameter(Mandatory = $true)][string]$Code)

    Write-Output ('{"failure_code":"' + $Code + '","status":"BLOCKED"}')
}

function Test-SaladProbeSecret {
    param([AllowNull()][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrEmpty($Value) -or $Value -ceq 'PASTE_SALAD_API_KEY_HERE') {
        return $false
    }
    if ($Value.Length -gt 4096) {
        return $false
    }
    foreach ($character in $Value.ToCharArray()) {
        $codePoint = [int]$character
        if ($codePoint -lt 33 -or $codePoint -gt 126) {
            return $false
        }
    }
    return $true
}

function ConvertTo-SaladProbeArgument {
    param([AllowEmptyString()][string]$Value)

    if ($Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashes++
            continue
        }
        if ($character -eq [char]'"') {
            if ($backslashes -gt 0) {
                [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            } else {
                [void]$builder.Append('\')
            }
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-SaladProbeWindow {
    param([Parameter(Mandatory = $true)][string]$SelectedOperation)

    # Keep this as the only wall-clock read. Both endpoints derive from this
    # exact UTC instant before millisecond serialization.
    $clockCapture = [DateTimeOffset]::UtcNow
    $windowSeconds = 3600
    if ($SelectedOperation -in @('page-min-before-probe', 'page-min-before-capture')) {
        $windowSeconds = 135
    }
    $endUtc = $clockCapture.ToUniversalTime()
    $startUtc = $endUtc.AddSeconds(-$windowSeconds)
    $format = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'"
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    return [pscustomobject]@{
        StartTime = $startUtc.ToString($format, $culture)
        EndTime = $endUtc.ToString($format, $culture)
        WindowSeconds = $windowSeconds
    }
}

function Get-SaladProbeRequestBudget {
    param([Parameter(Mandatory = $true)][string]$SelectedOperation)

    switch ($SelectedOperation) {
        'experiment' { return 6 }
        'single' { return 1 }
        'saturated-branch-trace' { return 11 }
        'production-recursion-trace' { return 23 }
        'page-min-before-probe' { return 3 }
        'page-min-before-capture' { return 30 }
        default { return 0 }
    }
}

function Test-SaladProbeOutputContainsSecret {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Secret
    )

    if ([string]::IsNullOrEmpty($Secret)) {
        return $false
    }
    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [string]) {
        return $Value.IndexOf($Secret, [System.StringComparison]::Ordinal) -ge 0
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($entry in $Value.GetEnumerator()) {
            if (Test-SaladProbeOutputContainsSecret -Value $entry.Value -Secret $Secret) {
                return $true
            }
        }
        return $false
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($entry in $Value) {
            if (Test-SaladProbeOutputContainsSecret -Value $entry -Secret $Secret) {
                return $true
            }
        }
        return $false
    }
    if ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            if (Test-SaladProbeOutputContainsSecret -Value $property.Value -Secret $Secret) {
                return $true
            }
        }
    }
    return $false
}

function Invoke-SaladLogQueryProbe {
    param(
        [ValidateSet(
            'experiment',
            'single',
            'saturated-branch-trace',
            'production-recursion-trace',
            'page-min-before-probe',
            'page-min-before-capture'
        )]
        [string]$SelectedOperation = 'experiment'
    )

    $script:SaladProbeLastPipeName = $null
    $script:SaladProbeLastChildPid = $null
    $pipeHandle = $null
    $pipeStream = $null
    $process = $null
    $secretBytes = $null
    $secret = $script:SaladApiKey
    $resultCode = $null

    try {
        if (-not (Test-SaladProbeSecret -Value $secret)) {
            Write-SaladProbeFailure -Code 'SECRET_INPUT_EMPTY_OR_INVALID'
            return
        }

        $budget = Get-SaladProbeRequestBudget -SelectedOperation $SelectedOperation
        if ($budget -lt 1) {
            Write-SaladProbeFailure -Code 'CONFIGURATION_INVALID'
            return
        }

        $pythonCommand = Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $pythonCommand -or [string]::IsNullOrWhiteSpace($pythonCommand.Source)) {
            Write-SaladProbeFailure -Code 'PYTHON_UNAVAILABLE'
            return
        }

        $telemetryRoot = Join-Path $script:SaladProbeRoot 'gpu-mining\telemetry'
        if (-not (Test-Path -LiteralPath (Join-Path $telemetryRoot 'log_query_probe\cli.py') -PathType Leaf)) {
            Write-SaladProbeFailure -Code 'PROBE_PACKAGE_UNAVAILABLE'
            return
        }

        try {
            $secretBytes = [System.Text.Encoding]::ASCII.GetBytes($secret)
            $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $pipeName = 'scrum80-probe-' + [Guid]::NewGuid().ToString('N')
            if (-not ('SaladLogProbeSecurePipe' -as [type])) {
                [void](Add-Type -TypeDefinition $script:SaladProbePipeNativeSource -ErrorAction Stop)
            }
            $pipeHandle = [SaladLogProbeSecurePipe]::CreateCurrentUserOnlyServer($pipeName, $userSid)
            $script:SaladProbeLastPipeName = $pipeName
        } catch {
            Write-SaladProbeFailure -Code 'SECRET_PIPE_UNAVAILABLE'
            return
        }

        $window = Get-SaladProbeWindow -SelectedOperation $SelectedOperation
        $query = '(resource.type = "container" or resource.type = "instance_controller")'
        $pythonBootstrap = @'
import sys
import json
import time
_test_marker = None
_test_behavior = None
_argument_offset = 2
if len(sys.argv) > 2 and sys.argv[2] == "--s80-test-harness":
    if len(sys.argv) < 5:
        raise SystemExit(90)
    _test_marker = sys.argv[3]
    _test_behavior = sys.argv[4]
    _argument_offset = 5
def _record_test(_event, **_fields):
    if not _test_marker:
        return
    _record = {"event": _event}
    _record.update(_fields)
    with open(_test_marker, "a", encoding="ascii") as _handle:
        _handle.write(json.dumps(_record, sort_keys=True, separators=(",", ":")) + "\n")
if _test_marker:
    if _test_behavior == "crash_before_pipe":
        _record_test("bootstrap_crash")
        raise SystemExit(92)
    import http.client as _http_client
    import socket as _socket
    class _TestTty:
        def isatty(self):
            return True
    sys.stdin = _TestTty()
    def _network_blocked(*_args, **_kwargs):
        _record_test("network_blocked")
        raise RuntimeError("offline network guard")
    _socket.socket = _network_blocked
    _socket.create_connection = _network_blocked
    _socket.getaddrinfo = _network_blocked
    class _BeforeHttps:
        def __init__(self, _host, _port=443, **_kwargs):
            _record_test("before_https", host_fixed=(_host == "api.salad.com"), port_fixed=(_port == 443))
            if _test_behavior == "slow":
                time.sleep(10)
            raise RuntimeError("synthetic pre-HTTPS stop")
    _http_client.HTTPSConnection = _BeforeHttps
def _blocked():
    sys.stdout.write('{"failure_code":"PROBE_BOOTSTRAP_FAILED","status":"BLOCKED"}\n')
    raise SystemExit(3)
try:
    import getpass
    import sys as _sys
    from log_alerts.live_transport import secret_boundary_types
    _provider_type, _, _material_type = secret_boundary_types()
    if _test_marker:
        _original_acquire = _provider_type.acquire
        def _checked_acquire(_self):
            _material = _original_acquire(_self)
            _record_test(
                "provider_acquired",
                provider_exact=(type(_self) is _provider_type),
                material_exact=(type(_material) is _material_type),
                source_ok=(_material.source_label == "interactive_tty_session"),
                read_count_one=(_self.read_count == 1),
                tty_ok=bool(_sys.stdin.isatty()),
            )
            return _material
        _provider_type.acquire = _checked_acquire
    _boundary = _sys.modules.get("_salad_g4c_live_secret_boundary")
    if _boundary is None or not hasattr(_boundary, "getpass"):
        _blocked()
    _original_getpass = _boundary.getpass.getpass
    _reads = [0]
    _pipe_name = _sys.argv[1]
    _cli_arguments = _sys.argv[_argument_offset:]
    def _read_once(_prompt):
        if _reads[0] != 0:
            raise RuntimeError("secret handoff exhausted")
        _reads[0] = 1
        _pipe_path = r"\\.\pipe" + "\\" + _pipe_name
        _raw = bytearray()
        with open(_pipe_path, "rb", buffering=0) as _pipe:
            while len(_raw) <= 4096:
                _chunk = _pipe.read(min(512, 4097 - len(_raw)))
                if not _chunk:
                    break
                _raw.extend(_chunk)
        if not _raw or len(_raw) > 4096:
            raise RuntimeError("secret handoff invalid")
        return _raw.decode("ascii")
    _boundary.getpass.getpass = _read_once
    try:
        from log_query_probe.cli import main
        raise SystemExit(main(_cli_arguments))
    finally:
        _boundary.getpass.getpass = _original_getpass
except SystemExit:
    raise
except BaseException:
    _blocked()
'@
        $bootstrapArguments = @('-c', $pythonBootstrap, $pipeName)
        if (-not [string]::IsNullOrWhiteSpace([string]$script:SaladProbeTestMarker)) {
            $bootstrapArguments += @(
                '--s80-test-harness',
                [string]$script:SaladProbeTestMarker,
                [string]$script:SaladProbeTestBehavior
            )
        }
        $cliArguments = @($bootstrapArguments) + @(
            '--mode', 'live-manual',
            '--operation', $SelectedOperation,
            '--organization', 'mybrainassistant',
            '--start-time', $window.StartTime,
            '--end-time', $window.EndTime,
            '--query', $query,
            '--page-size', '100',
            '--sort-order', 'asc',
            '--enable-live-read',
            '--confirm-live', 'CENTRAL_FLEET_MONITOR'
        )
        if ($SelectedOperation -eq 'experiment') {
            $cliArguments += '--repeat-parent'
        }

        $argumentString = (@($cliArguments | ForEach-Object {
            ConvertTo-SaladProbeArgument -Value ([string]$_)
        }) -join ' ')
        if ($argumentString.IndexOf($secret, [System.StringComparison]::Ordinal) -ge 0) {
            Write-SaladProbeFailure -Code 'SECRET_BOUNDARY_VIOLATION'
            return
        }

        Write-Output ''
        Write-Output 'Salad Log Query Contract Probe'
        if (@('page-min-before-probe', 'page-min-before-capture') -notcontains $SelectedOperation) {
            Write-Output 'Organization : mybrainassistant'
        }
        Write-Output ('Window       : ' + $window.StartTime + ' -> ' + $window.EndTime)
        Write-Output ('Requests max : ' + $budget)

        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $pythonCommand.Source
        $startInfo.Arguments = $argumentString
        $startInfo.WorkingDirectory = $telemetryRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $startInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        $startInfo.EnvironmentVariables['PYTHONNOUSERSITE'] = '1'
        foreach ($name in @($startInfo.EnvironmentVariables.Keys)) {
            if ([string]$name -match '^(?i)(PYTHONPATH|PYTHONHOME|PYTHONSTARTUP)$') {
                $startInfo.EnvironmentVariables.Remove([string]$name)
            }
            if ([string]$name -match '(?i)(SALAD|TELEGRAM).*(KEY|TOKEN)|(KEY|TOKEN).*(SALAD|TELEGRAM)') {
                $startInfo.EnvironmentVariables.Remove([string]$name)
            }
        }

        $timeoutSeconds = [int]$script:SaladProbeRunTimeoutSeconds[$SelectedOperation]
        $deadlineUtc = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        [void]$process.Start()
        $script:SaladProbeLastChildPid = $process.Id
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        $remainingMilliseconds = [int][Math]::Max(
            0,
            ($deadlineUtc - [DateTime]::UtcNow).TotalMilliseconds
        )
        $connectTimeoutMilliseconds = [int][Math]::Min(
            $script:SaladProbePipeConnectTimeoutMilliseconds,
            $remainingMilliseconds
        )
        $connected = $false
        if ($connectTimeoutMilliseconds -gt 0) {
            $connected = [SaladLogProbeSecurePipe]::WaitForConnection(
                $pipeHandle,
                $connectTimeoutMilliseconds
            )
        }
        if (-not $connected) {
            $resultCode = 'SECRET_PIPE_CONNECT_FAILED'
            if (-not $process.HasExited) {
                try { $process.Kill() } catch {}
            }
        } else {
            $clientProcessId = [SaladLogProbeSecurePipe]::GetClientProcessId($pipeHandle)
            if ([long]$clientProcessId -ne [long]$process.Id) {
                $resultCode = 'SECRET_PIPE_CLIENT_INVALID'
                if (-not $process.HasExited) {
                    try { $process.Kill() } catch {}
                }
            } else {
                $pipeStream = [System.IO.FileStream]::new(
                    $pipeHandle,
                    [System.IO.FileAccess]::Write,
                    4096,
                    $false
                )
                $pipeStream.Write($secretBytes, 0, $secretBytes.Length)
                $pipeStream.Flush()
                $pipeStream.Dispose()
                $pipeStream = $null
                $pipeHandle = $null
            }
        }

        if ($null -eq $resultCode) {
            $remainingMilliseconds = [int][Math]::Max(
                0,
                ($deadlineUtc - [DateTime]::UtcNow).TotalMilliseconds
            )
            if ($remainingMilliseconds -lt 1 -or -not $process.WaitForExit($remainingMilliseconds)) {
                $resultCode = 'PROBE_TIMEOUT'
                try { $process.Kill() } catch {}
            }
        }
        if (-not $process.HasExited) {
            try { $process.Kill() } catch {}
        }
        try { [void]$process.WaitForExit(5000) } catch {}
        try { [void]$stdoutTask.Wait(5000) } catch {}
        try { [void]$stderrTask.Wait(5000) } catch {}

        if ($null -ne $resultCode) {
            Write-SaladProbeFailure -Code $resultCode
            return
        }

        $childStdout = ''
        $childStderr = ''
        try { $childStdout = [string]$stdoutTask.GetAwaiter().GetResult() } catch {}
        try { $childStderr = [string]$stderrTask.GetAwaiter().GetResult() } catch {}
        if ($childStdout.IndexOf($secret, [System.StringComparison]::Ordinal) -ge 0 -or
            $childStderr.IndexOf($secret, [System.StringComparison]::Ordinal) -ge 0) {
            Write-SaladProbeFailure -Code 'PROBE_OUTPUT_REDACTION_FAILED'
            return
        }

        $jsonLine = $childStdout.Trim()
        if ([string]::IsNullOrWhiteSpace($jsonLine) -or $jsonLine -match '[\r\n]') {
            Write-SaladProbeFailure -Code 'PROBE_OUTPUT_INVALID'
            return
        }
        try {
            $parsedOutput = ConvertFrom-Json -InputObject $jsonLine -ErrorAction Stop
        } catch {
            Write-SaladProbeFailure -Code 'PROBE_OUTPUT_INVALID'
            return
        }
        if (Test-SaladProbeOutputContainsSecret -Value $parsedOutput -Secret $secret) {
            Write-SaladProbeFailure -Code 'PROBE_OUTPUT_REDACTION_FAILED'
            return
        }
        Write-Output $jsonLine
    } catch {
        Write-SaladProbeFailure -Code 'PROBE_PROCESS_FAILED'
    } finally {
        if ($null -ne $pipeStream) {
            try { $pipeStream.Dispose() } catch {}
        }
        if ($null -ne $pipeHandle) {
            try { $pipeHandle.Dispose() } catch {}
        }
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                    [void]$process.WaitForExit(5000)
                }
            } catch {}
            try { $process.Dispose() } catch {}
        }
        if ($null -ne $secretBytes) {
            [Array]::Clear($secretBytes, 0, $secretBytes.Length)
        }
        $script:SaladApiKey = $null
        $secret = $null
        $childStdout = $null
        $childStderr = $null
        $parsedOutput = $null
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SaladLogQueryProbe -SelectedOperation $Operation
}
