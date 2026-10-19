[CmdletBinding()]
param(
    [string[]]$Relay = @('us-sjc-wg-001', 'us-sjc-wg-002', 'us-sjc-wg-401', 'us-sjc-wg-501'),
    [int[]]$Port = @(80, 443, 5001),
    [string]$CatalogPath = (Join-Path $env:LOCALAPPDATA 'MullvadAdapter-Windows/relays.json'),
    [string]$OutputPath = (Join-Path (Join-Path $env:LOCALAPPDATA 'MullvadAdapter-Diagnostics') ('direct-tcp-public-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.json') )
)

$ErrorActionPreference = 'Stop'
$startedUtc = [DateTime]::UtcNow.ToString('o')
$status = 'rejected'
$errorCode = $null
$results = @()

function Stop-Probe {
    param([string]$Code)
    throw ('PROBE:' + $Code)
}

function Test-PublicIPv4 {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$') {
        return $false
    }

    $parts = @($Text.Split('.'))
    $octets = @()
    foreach ($part in $parts) {
        $number = 0
        if (-not [int]::TryParse($part, [ref]$number) -or $number -lt 0 -or $number -gt 255) {
            return $false
        }
        $octets += $number
    }

    $a = $octets[0]
    $b = $octets[1]
    $c = $octets[2]

    if ($a -eq 0 -or $a -eq 10 -or $a -eq 127 -or $a -ge 224) { return $false }
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $false }
    if ($a -eq 169 -and $b -eq 254) { return $false }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $false }
    if ($a -eq 192 -and $b -eq 168) { return $false }
    if ($a -eq 192 -and $b -eq 0 -and ($c -eq 0 -or $c -eq 2)) { return $false }
    if ($a -eq 192 -and $b -eq 88 -and $c -eq 99) { return $false }
    if ($a -eq 198 -and ($b -eq 18 -or $b -eq 19)) { return $false }
    if ($a -eq 198 -and $b -eq 51 -and $c -eq 100) { return $false }
    if ($a -eq 203 -and $b -eq 0 -and $c -eq 113) { return $false }
    if ($a -eq 255) { return $false }

    return $true
}

function Get-SocketErrorCode {
    param([System.Exception]$Exception)

    if ($null -eq $Exception) { return $null }
    if ($Exception -is [System.Net.Sockets.SocketException]) {
        return $Exception.SocketErrorCode.ToString()
    }
    if ($Exception -is [System.AggregateException]) {
        foreach ($inner in $Exception.InnerExceptions) {
            $code = Get-SocketErrorCode -Exception $inner
            if ($code) { return $code }
        }
    }
    if ($Exception.InnerException) {
        return Get-SocketErrorCode -Exception $Exception.InnerException
    }
    return $null
}

function Get-RouteBinding {
    param([string]$RemoteAddress)

    try {
        $routeObjects = @(Find-NetRoute -RemoteIPAddress $RemoteAddress -ErrorAction Stop)
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Code = 'RouteUnavailable'; Source = $null; IfIndex = $null }
    }

    # Find-NetRoute emits a NetIPAddress and a NetRoute object. Use only the row
    # with IPAddress, then bind that source address to its route interface.
    $sourceRows = @($routeObjects | Where-Object {
        $_.PSObject.Properties['IPAddress'] -and $_.PSObject.Properties['InterfaceIndex']
    })
    if ($sourceRows.Count -ne 1) {
        return [pscustomobject]@{ Ok = $false; Code = 'RouteUnavailable'; Source = $null; IfIndex = $null }
    }

    $sourceText = [string]$sourceRows[0].IPAddress
    $sourceAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($sourceText, [ref]$sourceAddress) -or
        $sourceAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return [pscustomobject]@{ Ok = $false; Code = 'SourceAddressInvalid'; Source = $null; IfIndex = $null }
    }

    $ifIndex = 0
    if (-not [int]::TryParse([string]$sourceRows[0].InterfaceIndex, [ref]$ifIndex) -or $ifIndex -le 0) {
        return [pscustomobject]@{ Ok = $false; Code = 'RouteUnavailable'; Source = $null; IfIndex = $null }
    }

    try {
        $physicalUp = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {
            $_.Status -eq 'Up' -and [int]$_.ifIndex -eq $ifIndex
        })
    }
    catch {
        return [pscustomobject]@{ Ok = $false; Code = 'PhysicalAdapterUnavailable'; Source = $null; IfIndex = $null }
    }
    if ($physicalUp.Count -ne 1) {
        return [pscustomobject]@{ Ok = $false; Code = 'PhysicalAdapterUnavailable'; Source = $null; IfIndex = $null }
    }

    return [pscustomobject]@{
        Ok = $true
        Code = $null
        Source = $sourceAddress.ToString()
        IfIndex = $ifIndex
    }
}

try {
    if ($Relay.Count -lt 1 -or $Port.Count -lt 1) { Stop-Probe 'EmptyInput' }
    if (($Relay.Count * $Port.Count) -gt 48) { Stop-Probe 'CaseLimitExceeded' }

    $seenRelays = @()
    foreach ($name in $Relay) {
        if ([string]::IsNullOrWhiteSpace($name) -or $name -ne $name.Trim() -or
            $name -notmatch '^[a-z0-9]+(?:-[a-z0-9]+){2,4}$') {
            Stop-Probe 'InvalidRelayList'
        }
        if ($seenRelays -contains $name) { Stop-Probe 'DuplicateRelay' }
        $seenRelays += $name
    }

    $seenPorts = @()
    foreach ($number in $Port) {
        if ($number -lt 1 -or $number -gt 65535) { Stop-Probe 'InvalidPortList' }
        if ($seenPorts -contains $number) { Stop-Probe 'DuplicatePort' }
        $seenPorts += $number
    }

    try {
        if ((Get-Item -LiteralPath $CatalogPath).Length -gt 8388608) { Stop-Probe 'RelayCatalogCap' }; $catalog = [IO.File]::ReadAllText($CatalogPath,[Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Stop-Probe 'RelayCatalogUnavailable'
    }
    if ($null -eq $catalog.wireguard -or $null -eq $catalog.wireguard.relays) {
        Stop-Probe 'RelayCatalogInvalid'
    }
    $catalogRelays = @($catalog.wireguard.relays)
    $selected = @()

    foreach ($name in $Relay) {
        $matches = @($catalogRelays | Where-Object { [string]$_.hostname -ceq $name })
        if ($matches.Count -ne 1 -or $matches[0].active -isnot [bool] -or -not $matches[0].active) {
            Stop-Probe 'RelayNotUniquelyActive'
        }
        $endpoint = [string]$matches[0].ipv4_addr_in
        if (-not (Test-PublicIPv4 -Text $endpoint)) {
            Stop-Probe 'RelayAddressNotPublicIPv4'
        }
        $owners = @($catalogRelays | Where-Object {
            $_.active -is [bool] -and $_.active -and [string]$_.ipv4_addr_in -ceq $endpoint
        })
        if ($owners.Count -ne 1) { Stop-Probe 'DuplicatePrimaryAddress' }
        $selected += [pscustomobject]@{ Relay = $name; Endpoint = $endpoint }
    }

    $status = 'running'
    foreach ($relayItem in $selected) {
        foreach ($portNumber in $Port) {
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            $socket = $null
            $asyncResult = $null
            $waitHandle = $null
            $initialRoute = Get-RouteBinding -RemoteAddress $relayItem.Endpoint
            $row = [ordered]@{
                relay = $relayItem.Relay
                endpoint = $relayItem.Endpoint
                port = [int]$portNumber
                ifindex = $null
                elapsed_ms = 0
                result = 'not_run'
                socket_error = $null
                route_stable = $null
            }

            try {
                if (-not $initialRoute.Ok) {
                    $row.result = 'route_rejected'
                    $row.socket_error = $initialRoute.Code
                }
                else {
                    $row.ifindex = [int]$initialRoute.IfIndex
                    $socket = [System.Net.Sockets.Socket]::new(
                        [System.Net.Sockets.AddressFamily]::InterNetwork,
                        [System.Net.Sockets.SocketType]::Stream,
                        [System.Net.Sockets.ProtocolType]::Tcp
                    )
                    $socket.Bind([System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($initialRoute.Source), 0))
                    $socket.SetSocketOption(
                        [System.Net.Sockets.SocketOptionLevel]::IP,
                        [System.Net.Sockets.SocketOptionName]31,
                        [System.Net.IPAddress]::HostToNetworkOrder([int]$initialRoute.IfIndex)
                    )
                    $asyncResult = $socket.BeginConnect([System.Net.IPAddress]::Parse($relayItem.Endpoint), [int]$portNumber, $null, $null)
                    $waitHandle = $asyncResult.AsyncWaitHandle
                    if ($waitHandle.WaitOne(3000)) {
                        $socket.EndConnect($asyncResult)
                        $row.result = 'connected'
                    }
                    else {
                        $row.result = 'timeout'
                        $row.socket_error = ([System.Net.Sockets.SocketError]::TimedOut).ToString()
                    }
                }
            }
            catch {
                $code = Get-SocketErrorCode -Exception $_.Exception
                $row.result = 'socket_error'
                if ($code) { $row.socket_error = $code } else { $row.socket_error = 'ConnectFailed' }
            }
            finally {
                if ($socket) { try { $socket.Close() } catch {} }
                if ($waitHandle) { try { $waitHandle.Close() } catch {} }

                if ($initialRoute.Ok) {
                    $finalRoute = Get-RouteBinding -RemoteAddress $relayItem.Endpoint
                    if ($finalRoute.Ok -and
                        [int]$finalRoute.IfIndex -eq [int]$initialRoute.IfIndex -and
                        [string]$finalRoute.Source -ceq [string]$initialRoute.Source) {
                        $row.route_stable = $true
                    }
                    else {
                        $row.route_stable = $false
                        $row.result = 'route_changed'
                        if ($finalRoute.Code) { $row.socket_error = $finalRoute.Code }
                        else { $row.socket_error = 'RouteChanged' }
                    }
                }

                $timer.Stop()
                $row.elapsed_ms = [long]$timer.ElapsedMilliseconds
                $results += [pscustomobject]$row
            }
        }
    }
    $status = 'complete'
}
catch {
    $message = [string]$_.Exception.Message
    if ($message -match '^PROBE:([A-Za-z0-9_]+)$') { $errorCode = $Matches[1] }
    else { $errorCode = 'InternalError' }
    $status = 'rejected'
}

$document = [ordered]@{
    schema_version = 1
    scope = 'direct_tcp_connect_only'
    interpretation = 'TCP endpoint reachability does not establish WireGuard tunnel availability.'
    status = $status
    error_code = $errorCode
    started_utc = $startedUtc
    completed_utc = [DateTime]::UtcNow.ToString('o')
    results = @($results)
}
$json = $document | ConvertTo-Json -Depth 6

try {
    $fullOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = [System.IO.Path]::GetDirectoryName($fullOutputPath)
    if (-not [System.IO.Directory]::Exists($outputDirectory)) {
        [void][System.IO.Directory]::CreateDirectory($outputDirectory)
    }
    [System.IO.File]::WriteAllText($fullOutputPath, $json, ([System.Text.UTF8Encoding]::new($false)))
}
catch {
    $document.status = 'output_error'
    $document.error_code = 'OutputUnavailable'
    $json = $document | ConvertTo-Json -Depth 6
}

[Console]::Out.WriteLine($json)
