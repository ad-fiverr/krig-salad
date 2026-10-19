[CmdletBinding()]
param(
    [switch]$ChildMode
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:Assertions = 0
$script:LauncherPath = Join-Path $PSScriptRoot 'start-salad-log-query-probe.ps1'
$script:TestPath = $PSCommandPath
$script:TestTempRoot = $null

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $script:Assertions++
    if (-not $Condition) {
        $script:Failures++
        throw ('ASSERTION_FAILED:' + $Name)
    }
}

function Test-PipeReleased {
    param([Parameter(Mandatory = $true)][string]$PipeName)
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $handle = $null
    try {
        $handle = [SaladLogProbeSecurePipe]::CreateCurrentUserOnlyServer($PipeName, $sid)
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $handle) { $handle.Dispose() }
    }
}

function Read-TestMarker {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $values = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        try { $values += ,(ConvertFrom-Json -InputObject $line -ErrorAction Stop) } catch {
            throw 'ASSERTION_FAILED:marker_json_valid'
        }
    }
    return $values
}

function Remove-TestTempRoot {
    if ([string]::IsNullOrWhiteSpace([string]$script:TestTempRoot)) { return }
    $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $candidate = [System.IO.Path]::GetFullPath([string]$script:TestTempRoot)
    $prefix = $tempBase.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) -and
        [System.IO.Path]::GetFileName($candidate).StartsWith('scrum80-probe-', [System.StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $candidate -Recurse -Force -ErrorAction SilentlyContinue
    }
    $script:TestTempRoot = $null
    $script:SaladProbeTestMarker = $null
    $script:SaladProbeTestBehavior = $null
    $script:SaladApiKey = $null
}

function Invoke-LauncherForTest {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Secret,
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
    if ([string]::IsNullOrWhiteSpace([string]$script:SaladProbeTestMarker) -or
        @('normal', 'slow', 'crash_before_pipe') -notcontains [string]$script:SaladProbeTestBehavior) {
        throw 'OFFLINE_GUARD_REQUIRED'
    }
    $script:SaladApiKey = $Secret
    $captured = Invoke-SaladLogQueryProbe -SelectedOperation $SelectedOperation 2>&1 | Out-String
    return [string]$captured
}

function Invoke-ChildSuite {
    if (-not (Test-Path -LiteralPath $script:LauncherPath -PathType Leaf)) {
        throw 'ASSERTION_FAILED:launcher_exists'
    }
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $script:LauncherPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    Assert-Condition -Condition ($parseErrors.Count -eq 0) -Name 'launcher_powershell_ast'
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $script:TestPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    Assert-Condition -Condition ($parseErrors.Count -eq 0) -Name 'test_powershell_ast'

    $source = Get-Content -LiteralPath $script:LauncherPath -Raw
    $testSource = Get-Content -LiteralPath $script:TestPath -Raw
    $directProbeCalls = [regex]::Matches($testSource, '(?m)^\s*\$captured\s*=\s*Invoke-SaladLogQueryProbe\b').Count
    Assert-Condition -Condition ($directProbeCalls -eq 1) -Name 'all_test_probe_launches_use_guarded_helper'
    Assert-Condition -Condition ($source.Contains("`$SaladApiKey = 'PASTE_SALAD_API_KEY_HERE'")) -Name 'exact_placeholder'
    Assert-Condition -Condition ($source -notmatch '2026-10-14T20:00:00Z|2026-10-14T21:00:00Z') -Name 'no_historical_fixed_window'
    Assert-Condition -Condition ($source.Contains("mybrainassistant")) -Name 'fixed_organization'
    Assert-Condition -Condition ($source.Contains("(resource.type = `"container`" or resource.type = `"instance_controller`")")) -Name 'fixed_query'
    Assert-Condition -Condition ($source.Contains("'--page-size', '100'")) -Name 'fixed_page_size'
    Assert-Condition -Condition ($source.Contains("'--sort-order', 'asc'")) -Name 'fixed_sort_order'
    Assert-Condition -Condition ($source.Contains("'--confirm-live', 'CENTRAL_FLEET_MONITOR'")) -Name 'fixed_confirmation'
    Assert-Condition -Condition ($source.Contains("'--enable-live-read'")) -Name 'live_gate_flag'
    Assert-Condition -Condition ($source.Contains("'--repeat-parent'")) -Name 'experiment_repeat_parent'
    Assert-Condition -Condition ($source.Contains("Join-Path `$script:SaladProbeRoot 'gpu-mining\telemetry'")) -Name 'package_path_from_script_root'
    Assert-Condition -Condition ($source.Contains('FileFlagFirstPipeInstance')) -Name 'first_pipe_instance'
    Assert-Condition -Condition ($source.Contains('PipeRejectRemoteClients')) -Name 'reject_remote_clients'
    Assert-Condition -Condition ($source.Contains('D:P(A;;GA;;;')) -Name 'protected_current_user_acl'
    Assert-Condition -Condition ($source.Contains('GetNamedPipeClientProcessId')) -Name 'verify_pipe_client_pid'
    Assert-Condition -Condition ($source.Contains('_reads[0] != 0')) -Name 'one_shot_python_reader'
    Assert-Condition -Condition ($source.Contains('secret_boundary_types()')) -Name 'exact_boundary_loader'
    Assert-Condition -Condition ($source.Contains('interactive_tty_session')) -Name 'approved_source_label'
    Assert-Condition -Condition ($source.Contains('getpass.getpass = _read_once')) -Name 'scoped_getpass_bridge'
    Assert-Condition -Condition ($source.Contains('_boundary.getpass.getpass = _original_getpass')) -Name 'restore_getpass'
    Assert-Condition -Condition ($source.Contains('[Array]::Clear($secretBytes')) -Name 'clear_parent_secret_buffer'
    Assert-Condition -Condition ($source.Contains("$script:SaladApiKey = `$null")) -Name 'clear_parent_key_reference'
    Assert-Condition -Condition ($source.Contains('--s80-test-harness')) -Name 'network_guard_test_hook_in_command_source'
    Assert-Condition -Condition ($source.Contains('socket.socket = _network_blocked')) -Name 'test_hook_socket_kill_switch'
    Assert-Condition -Condition ($source.Contains('_http_client.HTTPSConnection = _BeforeHttps')) -Name 'test_hook_https_sentinel'
    Assert-Condition -Condition ($source -notmatch '(?i)SALAD_API_KEY\s*=|--api-key|--password') -Name 'no_generic_credential_interface'
    $bootstrapGuardPosition = $source.IndexOf('_socket.socket = _network_blocked', [System.StringComparison]::Ordinal)
    $bootstrapSentinelPosition = $source.IndexOf('_http_client.HTTPSConnection = _BeforeHttps', [System.StringComparison]::Ordinal)
    $bootstrapCliImportPosition = $source.IndexOf('from log_query_probe.cli import main', [System.StringComparison]::Ordinal)
    Assert-Condition -Condition ($bootstrapGuardPosition -ge 0 -and $bootstrapSentinelPosition -gt $bootstrapGuardPosition -and $bootstrapCliImportPosition -gt $bootstrapSentinelPosition) -Name 'offline_guards_precede_probe_import'
    $testGuardPosition = $testSource.IndexOf("throw 'OFFLINE_GUARD_REQUIRED'", [System.StringComparison]::Ordinal)
    $testProbeCallPosition = $testSource.IndexOf('$captured = Invoke-SaladLogQueryProbe', [System.StringComparison]::Ordinal)
    Assert-Condition -Condition ($testGuardPosition -ge 0 -and $testProbeCallPosition -gt $testGuardPosition) -Name 'test_helper_refuses_unprotected_child'

    $windowFunction = [regex]::Match(
        $source,
        '(?s)function Get-SaladProbeWindow\s*\{(?<body>.*?)\r?\n\}\r?\n\r?\nfunction Get-SaladProbeRequestBudget'
    )
    Assert-Condition -Condition $windowFunction.Success -Name 'window_function_found'
    $clockReads = [regex]::Matches($windowFunction.Groups['body'].Value, '\[DateTimeOffset\]::UtcNow').Count
    Assert-Condition -Condition ($clockReads -eq 1) -Name 'single_clock_capture'

    . $script:LauncherPath
    $window = Get-SaladProbeWindow -SelectedOperation 'experiment'
    $format = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'"
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $start = [DateTimeOffset]::ParseExact($window.StartTime, $format, $culture, $styles)
    $end = [DateTimeOffset]::ParseExact($window.EndTime, $format, $culture, $styles)
    Assert-Condition -Condition (($end - $start).TotalSeconds -eq 3600) -Name 'rolling_window_exactly_one_hour'
    Assert-Condition -Condition ($window.StartTime -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') -Name 'start_utc_milliseconds'
    Assert-Condition -Condition ($window.EndTime -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') -Name 'end_utc_milliseconds'
    $pageMin = Get-SaladProbeWindow -SelectedOperation 'page-min-before-capture'
    $pageMinStart = [DateTimeOffset]::ParseExact($pageMin.StartTime, $format, $culture, $styles)
    $pageMinEnd = [DateTimeOffset]::ParseExact($pageMin.EndTime, $format, $culture, $styles)
    Assert-Condition -Condition (($pageMinEnd - $pageMinStart).TotalSeconds -eq 135) -Name 'page_min_window_135_seconds'
    Assert-Condition -Condition ((Get-SaladProbeRequestBudget -SelectedOperation 'experiment') -eq 6) -Name 'experiment_request_budget'
    Assert-Condition -Condition ((Get-SaladProbeRequestBudget -SelectedOperation 'single') -eq 1) -Name 'single_request_budget'
    Assert-Condition -Condition ((Get-SaladProbeRequestBudget -SelectedOperation 'saturated-branch-trace') -eq 11) -Name 'saturated_trace_request_budget'
    Assert-Condition -Condition ((Get-SaladProbeRequestBudget -SelectedOperation 'production-recursion-trace') -eq 23) -Name 'production_trace_request_budget'
    Assert-Condition -Condition ((Get-SaladProbeRequestBudget -SelectedOperation 'page-min-before-probe') -eq 3) -Name 'page_min_probe_budget'
    Assert-Condition -Condition ((Get-SaladProbeRequestBudget -SelectedOperation 'page-min-before-capture') -eq 30) -Name 'page_min_capture_budget'

    $syntheticKey = [string]::Concat('SYNTHETIC', '_OFFLINE', '_KEY_', [Guid]::NewGuid().ToString('N'))
    $script:SaladApiKey = $null
    $script:SaladProbeTestMarker = $null
    $script:SaladProbeTestBehavior = $null
    $guardRequired = $false
    try {
        [void](Invoke-LauncherForTest -Secret $syntheticKey)
    } catch {
        $guardRequired = ([string]$_.Exception.Message -eq 'OFFLINE_GUARD_REQUIRED')
    }
    Assert-Condition -Condition $guardRequired -Name 'unprotected_test_child_rejected_before_launcher'
    Assert-Condition -Condition ($null -eq $script:SaladProbeLastChildPid) -Name 'unprotected_test_child_not_spawned'
    Assert-Condition -Condition ($null -eq $script:SaladProbeLastPipeName) -Name 'unprotected_test_pipe_not_created'

    $testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scrum80-probe-' + [Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $testRoot)
    $script:TestTempRoot = $testRoot
    $markerPath = Join-Path $testRoot 'safe-marker.jsonl'
    $script:SaladProbeTestMarker = $markerPath
    $script:SaladProbeTestBehavior = 'normal'
    $script:SaladProbePipeConnectTimeoutMilliseconds = 1000
    $script:SaladProbeRunTimeoutSeconds['experiment'] = 5
    $script:SaladProbeRunTimeoutSeconds['page-min-before-probe'] = 5
    $script:SaladProbeRunTimeoutSeconds['page-min-before-capture'] = 5

    $invalidInputs = @(
        'PASTE_SALAD_API_KEY_HERE',
        '',
        '   ',
        "BAD`nKEY",
        "BAD`rKEY",
        'BAD KEY',
        ('BAD' + [char]0 + 'KEY'),
        ('BAD' + [char]233 + 'KEY'),
        ('A' * 4097)
    )
    foreach ($invalid in $invalidInputs) {
        $output = Invoke-LauncherForTest -Secret $invalid
        Assert-Condition -Condition ($output.Contains('SECRET_INPUT_EMPTY_OR_INVALID')) -Name 'invalid_secret_rejected_before_spawn'
        Assert-Condition -Condition ($null -eq $script:SaladProbeLastChildPid) -Name 'invalid_secret_no_child'
        Assert-Condition -Condition ($null -eq $script:SaladProbeLastPipeName) -Name 'invalid_secret_no_pipe'
        Assert-Condition -Condition (-not (Test-SaladProbeOutputContainsSecret -Value $output -Secret $invalid)) -Name 'invalid_secret_not_output'
    }

    $positiveOutput = Invoke-LauncherForTest -Secret $syntheticKey
    Assert-Condition -Condition (-not (Test-SaladProbeOutputContainsSecret -Value $positiveOutput -Secret $syntheticKey)) -Name 'synthetic_secret_absent_from_output'
    $positiveRecords = @(Read-TestMarker -Path $markerPath)
    $providerRecord = @($positiveRecords | Where-Object { $_.event -eq 'provider_acquired' }) | Select-Object -First 1
    $httpsRecord = @($positiveRecords | Where-Object { $_.event -eq 'before_https' }) | Select-Object -First 1
    $networkRecord = @($positiveRecords | Where-Object { $_.event -eq 'network_blocked' })
    if ($null -eq $providerRecord) {
        $safeCode = 'NO_JSON_CODE'
        foreach ($line in ($positiveOutput -split '\r?\n')) {
            try {
                $parsedLine = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ([string]$parsedLine.failure_code -match '^[A-Z_]+$') {
                    $safeCode = [string]$parsedLine.failure_code
                    break
                }
            } catch {}
        }
        Assert-Condition -Condition $false -Name ('provider_missing_' + $safeCode)
    }
    Assert-Condition -Condition ($null -ne $providerRecord) -Name 'synthetic_provider_acquired'
    Assert-Condition -Condition ([bool]$providerRecord.provider_exact) -Name 'exact_interactive_provider_type'
    Assert-Condition -Condition ([bool]$providerRecord.material_exact) -Name 'exact_secret_material_type'
    Assert-Condition -Condition ([bool]$providerRecord.source_ok) -Name 'approved_interactive_source_label'
    Assert-Condition -Condition ([bool]$providerRecord.read_count_one) -Name 'one_getpass_acquisition'
    Assert-Condition -Condition ([bool]$providerRecord.tty_ok) -Name 'provider_tty_gate_preserved'
    Assert-Condition -Condition ($null -ne $httpsRecord) -Name 'reached_fake_pre_https_sentinel'
    Assert-Condition -Condition ([bool]$httpsRecord.host_fixed -and [bool]$httpsRecord.port_fixed) -Name 'fixed_https_destination'
    Assert-Condition -Condition ($networkRecord.Count -eq 0) -Name 'no_socket_dns_activity'
    Assert-Condition -Condition ($positiveOutput.Contains('Window       :')) -Name 'actual_window_printed'
    Assert-Condition -Condition ($positiveOutput.Contains('Requests max : 6')) -Name 'experiment_budget_printed'
    Assert-Condition -Condition ($null -eq (Get-Process -Id $script:SaladProbeLastChildPid -ErrorAction SilentlyContinue)) -Name 'child_exited_after_sentinel'
    Assert-Condition -Condition (Test-PipeReleased -PipeName $script:SaladProbeLastPipeName) -Name 'named_pipe_cleaned_after_success'
    $markerText = Get-Content -LiteralPath $markerPath -Raw
    Assert-Condition -Condition (-not $markerText.Contains($syntheticKey)) -Name 'synthetic_secret_absent_from_marker'

    foreach ($pageMinOperation in @('page-min-before-probe', 'page-min-before-capture')) {
        Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
        $pageMinOutput = Invoke-LauncherForTest -Secret $syntheticKey -SelectedOperation $pageMinOperation
        $expectedPageMinBudget = if ($pageMinOperation -eq 'page-min-before-probe') { 3 } else { 30 }
        Assert-Condition -Condition (-not $pageMinOutput.Contains('Organization :')) -Name ($pageMinOperation.Replace('-', '_') + '_organization_label_redacted')
        Assert-Condition -Condition (-not $pageMinOutput.Contains('mybrainassistant')) -Name ($pageMinOperation.Replace('-', '_') + '_organization_value_redacted')
        Assert-Condition -Condition ($pageMinOutput.Contains('Window       :')) -Name ($pageMinOperation.Replace('-', '_') + '_window_still_printed')
        Assert-Condition -Condition ($pageMinOutput.Contains(('Requests max : ' + $expectedPageMinBudget))) -Name ($pageMinOperation.Replace('-', '_') + '_budget_still_printed')
        Assert-Condition -Condition (-not (Test-SaladProbeOutputContainsSecret -Value $pageMinOutput -Secret $syntheticKey)) -Name ($pageMinOperation.Replace('-', '_') + '_synthetic_secret_redacted')
        $pageMinRecords = @(Read-TestMarker -Path $markerPath)
        $pageMinProvider = @($pageMinRecords | Where-Object { $_.event -eq 'provider_acquired' }) | Select-Object -First 1
        $pageMinHttps = @($pageMinRecords | Where-Object { $_.event -eq 'before_https' }) | Select-Object -First 1
        $pageMinNetwork = @($pageMinRecords | Where-Object { $_.event -eq 'network_blocked' })
        Assert-Condition -Condition ($null -ne $pageMinProvider -and [bool]$pageMinProvider.provider_exact -and [bool]$pageMinProvider.material_exact -and [bool]$pageMinProvider.source_ok -and [bool]$pageMinProvider.read_count_one) -Name ($pageMinOperation.Replace('-', '_') + '_exact_provider_boundary')
        Assert-Condition -Condition ($null -ne $pageMinHttps -and [bool]$pageMinHttps.host_fixed -and [bool]$pageMinHttps.port_fixed) -Name ($pageMinOperation.Replace('-', '_') + '_offline_https_sentinel')
        Assert-Condition -Condition ($pageMinNetwork.Count -eq 0) -Name ($pageMinOperation.Replace('-', '_') + '_zero_network_activity')
        Assert-Condition -Condition (-not ((Get-Content -LiteralPath $markerPath -Raw).Contains($syntheticKey))) -Name ($pageMinOperation.Replace('-', '_') + '_marker_secret_redacted')
        Assert-Condition -Condition ($null -eq (Get-Process -Id $script:SaladProbeLastChildPid -ErrorAction SilentlyContinue)) -Name ($pageMinOperation.Replace('-', '_') + '_child_exited')
        Assert-Condition -Condition (Test-PipeReleased -PipeName $script:SaladProbeLastPipeName) -Name ($pageMinOperation.Replace('-', '_') + '_pipe_released')
    }

    Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    $script:SaladProbeTestBehavior = 'slow'
    $script:SaladProbeRunTimeoutSeconds['experiment'] = 1
    $timeoutOutput = Invoke-LauncherForTest -Secret $syntheticKey
    Assert-Condition -Condition ($timeoutOutput.Contains('PROBE_TIMEOUT')) -Name 'child_timeout_sanitized'
    Assert-Condition -Condition ($null -eq (Get-Process -Id $script:SaladProbeLastChildPid -ErrorAction SilentlyContinue)) -Name 'timed_out_child_terminated'
    Assert-Condition -Condition (Test-PipeReleased -PipeName $script:SaladProbeLastPipeName) -Name 'named_pipe_cleaned_after_timeout'
    Assert-Condition -Condition (-not (Test-SaladProbeOutputContainsSecret -Value $timeoutOutput -Secret $syntheticKey)) -Name 'timeout_secret_redacted'

    Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    $script:SaladProbeTestBehavior = 'crash_before_pipe'
    $crashOutput = Invoke-LauncherForTest -Secret $syntheticKey
    Assert-Condition -Condition ($crashOutput.Contains('SECRET_PIPE_CONNECT_FAILED')) -Name 'pre_pipe_child_crash_sanitized'
    Assert-Condition -Condition ($null -eq (Get-Process -Id $script:SaladProbeLastChildPid -ErrorAction SilentlyContinue)) -Name 'crashed_child_exited'
    Assert-Condition -Condition (Test-PipeReleased -PipeName $script:SaladProbeLastPipeName) -Name 'named_pipe_cleaned_after_crash'
    Assert-Condition -Condition (-not (Test-SaladProbeOutputContainsSecret -Value $crashOutput -Secret $syntheticKey)) -Name 'crash_secret_redacted'

    Write-Output ('CHILD_SUITE_PASS assertions=' + $script:Assertions)
}

if ($ChildMode) {
    $childExitCode = 0
    try {
        Invoke-ChildSuite
    } catch {
        $safeFailure = 'UNEXPECTED_TEST_ERROR'
        if ([string]$_.Exception.Message -match '^ASSERTION_FAILED:[A-Za-z0-9_]+$') {
            $safeFailure = ([string]$_.Exception.Message).Substring('ASSERTION_FAILED:'.Length)
        }
        $safeType = [string]$_.Exception.GetType().Name
        if ($safeType -notmatch '^[A-Za-z0-9_]+$') { $safeType = 'ERROR' }
        $safeLine = 0
        if ($null -ne $_.InvocationInfo) { $safeLine = [int]$_.InvocationInfo.ScriptLineNumber }
        Write-Output ('CHILD_SUITE_FAIL reason=' + $safeFailure + ' type=' + $safeType + ' line=' + $safeLine)
        $childExitCode = 1
    } finally {
        Remove-TestTempRoot
    }
    exit $childExitCode
}

$engines = @()
foreach ($name in @('powershell.exe', 'pwsh.exe')) {
    $engine = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $engine -and -not ($engines | Where-Object { $_.Source -eq $engine.Source })) {
        $engines += $engine
    }
}
if ($engines.Count -eq 0) {
    Write-Output 'NO_POWERSHELL_ENGINE_AVAILABLE'
    exit 1
}
foreach ($engine in $engines) {
    & $engine.Source -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:TestPath -ChildMode
    if ($LASTEXITCODE -ne 0) {
        Write-Output ('ENGINE_FAILED name=' + $engine.Name)
        exit 1
    }
    Write-Output ('ENGINE_PASS name=' + $engine.Name)
}
Write-Output ('POWERSHELL_TESTS_PASS engines=' + $engines.Count)
