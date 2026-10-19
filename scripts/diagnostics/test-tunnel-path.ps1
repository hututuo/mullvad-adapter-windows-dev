param(
 [Parameter(Mandatory=$true)][ValidateSet('direct','ss','clash')][string]$Mode,
 [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$Port,
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$IdentityBlob='',
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$IdentityEntropy='',
 [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$VerifiedPublicReceipt='',
 [string]$DiagnosticRoot=(Join-Path $env:LOCALAPPDATA 'MullvadAdapter-Diagnostics'),
 [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$Scope='Windows',
 [string]$RpcHelperPath=(Join-Path $DiagnosticRoot 'rpc-helpers.ps1'),
 [string]$ClashHelperPath=(Join-Path $DiagnosticRoot 'clash-pipe.ps1'),
 [ValidatePattern('^[a-z0-9-]{1,64}$')][string]$Relay='us-sjc-wg-002',
 [switch]$ExitCheck
)
# Component experiment only. Alternate endpoint success is not product acceptance.
# No TUN, route, account, app or Clash mutations. Identity paths must already exist.
# Trusted local helpers must expose Invoke-AdapterCommand(command, scope) and
# legacy Invoke-FriendClash(path, method, body); they may be implemented locally.
# The legacy function name is an interface name, not embedded personal data.
# Use a persistent PowerShell session; retain it if child shutdown is unconfirmed.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding
$diag=$DiagnosticRoot
$stage='preflight';$bytes=$null;$payload=$null;$login=$null;$config=$null;$wg=$null
$lease=$null;$p=$null;$started=$false;$out=$null;$err=$null;$clashBefore=$null
$id=[Guid]::NewGuid().ToString('N')
$receipt=[ordered]@{component_only=$true;mode=$Mode;relay=$Relay;port=$Port;receipt_id=$id;time_utc=[DateTimeOffset]::UtcNow.ToString('o');outcome='FAIL';error=$null;probes=@();owned_engine_stop=$true;public_engine_signal_counters=@{};bound_carrier_acceptance='NOT_RUN';product_readiness='NOT_RUN'}
function Require($condition,[string]$code){if(!$condition){$failure=[InvalidOperationException]::new('tunnel_path_guard');$failure.Data['TunnelPathCode']=$code;throw $failure}}
function Read-Json([string]$path){Require ((Get-Item -LiteralPath $path).Length -le 8388608) 'input_cap';return ([IO.File]::ReadAllText($path,[Text.Encoding]::UTF8)|ConvertFrom-Json)}
function Public-V4($value){
 $ip=$null;if(![Net.IPAddress]::TryParse([string]$value,[ref]$ip)){return $false}
 if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
 $b=$ip.GetAddressBytes();return !([Net.IPAddress]::IsLoopback($ip) -or $b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))
}
function In-Ranges($ranges,[int]$value){foreach($range in @($ranges)){if(@($range).Count -eq 2 -and [int]$range[0] -ge 1 -and [int]$range[1] -le 65535 -and [int]$range[0] -le $value -and $value -le [int]$range[1]){return $true}};return $false}
function Assert-Idle([string]$expectedPublic='') {
 $r=Invoke-AdapterCommand @{kind='dashboard'} $Scope
 Require ($r.kind -eq 'dashboard' -and $null -ne $r.dashboard) 'dashboard_unavailable'
 $d=$r.dashboard
 Require ($null -ne $d.PSObject.Properties['active_relay'] -and $null -ne $d.PSObject.Properties['operation'] -and $null -ne $d.PSObject.Properties['front_selected']) 'dashboard_schema'
 Require ($null -eq $d.active_relay -and $null -eq $d.operation -and $d.front_selected -ceq 'reject') 'adapter_not_idle_reject'
 if($expectedPublic){Require ($null -ne $d.PSObject.Properties['public_key'] -and [string]$d.public_key -ceq $expectedPublic) 'dashboard_identity_mismatch'}
 $cli=[Diagnostics.Process]::new();$live=$false
 try{$si=[Diagnostics.ProcessStartInfo]::new();$si.FileName='C:\Program Files\Mullvad VPN\resources\mullvad.exe';$si.Arguments='status';$si.UseShellExecute=$false;$si.CreateNoWindow=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true;$cli.StartInfo=$si;$live=$cli.Start();Require $live 'official_status_start';$a=$cli.StandardOutput.ReadToEndAsync();$b=$cli.StandardError.ReadToEndAsync();Require ($cli.WaitForExit(3000) -and $a.Wait(250) -and $b.Wait(250)) 'official_status_deadline';Require ($cli.ExitCode -eq 0 -and $a.Result.Trim() -ceq 'Disconnected') 'official_tunnel_not_disconnected'}finally{if($live -and !$cli.HasExited){$cli.Kill();Require ($cli.WaitForExit(1000)) 'official_status_stop_unconfirmed'};$cli.Dispose()}
}
function Assert-OwnedListeners {
 Require ($started -and !$p.HasExited) 'owned_engine_exited'
 foreach($portValue in @(17940,17941)){
  $rows=@(Get-NetTCPConnection -State Listen -LocalPort $portValue -ErrorAction SilentlyContinue)
  Require ($rows.Count -eq 1 -and $rows[0].LocalAddress -eq '127.0.0.1' -and $rows[0].OwningProcess -eq $p.Id) 'listener_owner_mismatch'
 }
}
function Assert-ClashIndependent {
 $rows=@(Get-NetTCPConnection -State Listen -LocalPort 7897 -ErrorAction SilentlyContinue)
 Require ($rows.Count -eq 1) 'clash_listener_ambiguous'
 $owner=Get-Process -Id $rows[0].OwningProcess
 Require ($owner.Path -eq 'C:\Program Files\Clash Verge\verge-mihomo.exe' -and $owner.SessionId -eq [Diagnostics.Process]::GetCurrentProcess().SessionId) 'clash_listener_owner'
 $reply=Invoke-FriendClash '/proxies';$map=$reply.proxies
 Require ($null -ne $map) 'clash_proxies_schema'
 $providerNodes=$null
 # ASCII source remains safe under Windows PowerShell 5's default file decoding.
 $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('5pmu6YCa5aSW572R5Ye65Y+j'))
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$path=@();$leaf=$null
 for($i=0;$i -lt 16;$i++){
  Require ($name -and !$seen.Contains($name) -and $name -notmatch '(?i)mullvad' -and $name -notin @('DIRECT','REJECT','GLOBAL')) 'clash_graph_loop_or_adapter'
  [void]$seen.Add($name);$matches=@($map.PSObject.Properties|Where-Object {$_.Name -ceq $name})
  if($matches.Count -eq 1){$node=$matches[0].Value}else{
   Require ($matches.Count -eq 0) 'clash_graph_ambiguous'
   if($null -eq $providerNodes){$providers=Invoke-FriendClash '/providers/proxies';Require ($null -ne $providers.providers) 'clash_providers_schema';$providerNodes=@(foreach($provider in @($providers.providers.PSObject.Properties)){foreach($candidate in @($provider.Value.proxies)){$candidate}});Require ($providerNodes.Count -le 16384) 'clash_catalogue_cap'}
   $matches=@($providerNodes|Where-Object {[string]$_.name -ceq $name});Require ($matches.Count -gt 0) 'clash_graph_unknown';Require ($matches.Count -eq 1) 'clash_graph_ambiguous';$node=$matches[0]
  }
  Require ([string]$node.name -ceq $name) 'clash_node_name_mismatch'
  $type=([string]$node.type).ToLowerInvariant();$path+=($name+'|'+$type+'|'+[string]$node.now+'|'+[string]$node.'provider-name')
  if($type -in @('selector','select','urltest','fallback')){Require ([string]$node.now -and @($node.all) -ccontains [string]$node.now) 'clash_graph_selection';$name=[string]$node.now;continue}
  Require ($type -in @('vmess','vless','trojan','shadowsocks','ss')) 'clash_leaf_not_independent'
  foreach($field in @('dialer-proxy','underlying-proxy')){Require (![string]$node.$field) 'clash_leaf_chained'}
  if($node.server){$addr=$null;$s=[string]$node.server;Require ($s -notmatch '(?i)(^localhost$|\.localhost$)') 'clash_leaf_loopback';if([Net.IPAddress]::TryParse($s,[ref]$addr)){Require (![Net.IPAddress]::IsLoopback($addr) -and !$addr.Equals([Net.IPAddress]::Any) -and !$addr.Equals([Net.IPAddress]::IPv6Any)) 'clash_leaf_loopback'}}
  $leaf=$type;break
 }
 Require ($null -ne $leaf) 'clash_graph_depth'
 return @{signature=($path -join "`n");leaf_type=$leaf}
}
function Probe([string]$name,[string]$url,[int]$expected,[switch]$Body){
 $cp=$null;$live=$false;$sw=[Diagnostics.Stopwatch]::StartNew();$raw=$null;$result=$null
 try{
  $si=[Diagnostics.ProcessStartInfo]::new();$si.FileName='curl.exe';$si.UseShellExecute=$false;$si.CreateNoWindow=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
  $dest=if($Body){'-'}else{'NUL'}
  $si.Arguments='-q --proxy socks5h://127.0.0.1:17940 --noproxy never-match.invalid --connect-timeout 5 --max-time 10 --max-filesize 16384 --silent --output '+$dest+' --write-out "\nTUNNEL_METRICS:%{http_code}|%{time_total}" '+$url
  $cp=[Diagnostics.Process]::new();$cp.StartInfo=$si;$live=$cp.Start();Require $live 'probe_start'
  $co=$cp.StandardOutput.ReadToEndAsync();$ce=$cp.StandardError.ReadToEndAsync()
  if(!$cp.WaitForExit(11000)){$cp.Kill();Require ($cp.WaitForExit(1000)) 'probe_stop_unconfirmed'}
  Require ($co.Wait(500) -and $ce.Wait(500)) 'probe_output_deadline'
  $raw=$co.Result;$m=[regex]::Match($raw,'(?s)^(.*)\r?\nTUNNEL_METRICS:([0-9]{3})\|([0-9]+(?:\.[0-9]+)?)\s*$')
  Require $m.Success 'probe_metrics_invalid'
  $result=@{name=$name;exit=$cp.ExitCode;http=[int]$m.Groups[2].Value;elapsed_ms=$sw.ElapsedMilliseconds;pass=($cp.ExitCode -eq 0 -and [int]$m.Groups[2].Value -eq $expected)}
  if($Body -and $result.pass){Require ($m.Groups[1].Value.Length -le 16384) 'exit_body_cap';$j=$m.Groups[1].Value|ConvertFrom-Json;$result.exit_info=@{mullvad_exit=($j.mullvad_exit_ip -eq $true);country=([string]$j.country).Substring(0,[Math]::Min(64,([string]$j.country).Length));city=([string]$j.city).Substring(0,[Math]::Min(64,([string]$j.city).Length))};$j=$null}
  return $result
 }finally{
  if($cp){if($live -and !$cp.HasExited){$cp.Kill();Require ($cp.WaitForExit(1000)) 'probe_stop_unconfirmed'};$cp.Dispose()};$raw=$null;$sw.Stop()
 }
}
try{
 foreach($helper in @($RpcHelperPath,$ClashHelperPath)){. ([scriptblock]::Create([IO.File]::ReadAllText($helper,[Text.Encoding]::UTF8)))}
 Assert-Idle
 Require (!(Get-NetTCPConnection -State Listen -LocalPort 17940,17941 -ErrorAction SilentlyContinue)) 'diagnostic_listener_in_use'
 $stage='identity';Add-Type -AssemblyName System.Security
 Require ((Get-Item -LiteralPath $IdentityBlob).Length -le 1048576) 'identity_cap'
 $bytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($IdentityBlob),[Text.Encoding]::UTF8.GetBytes($IdentityEntropy),[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $login=([Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json).logged_in
 Require ($login.device.wg_data.private_key -and $login.device.wg_data.addresses.ipv4_address) 'identity_schema'
 $keyBytes=[Convert]::FromBase64String($login.device.wg_data.private_key);Require ($keyBytes.Length -eq 32) 'identity_key_length';[Array]::Clear($keyBytes,0,$keyBytes.Length);$keyBytes=$null
 $public=Read-Json $VerifiedPublicReceipt;$pubBytes=[Convert]::FromBase64String($public.public_key);Require ($pubBytes.Length -eq 32) 'public_key_length'
 if($null -ne $public.PSObject.Properties['device_id']){Require ([string]$public.device_id -and [string]$public.device_id -ceq [string]$login.device.id) 'device_id_mismatch'}
 foreach($field in @('ipv4_address','ipv6_address')){if($null -ne $public.PSObject.Properties[$field]){Require ([string]$public.$field -ceq [string]$login.device.wg_data.addresses.$field) 'identity_address_mismatch'};if($public.addresses -and $null -ne $public.addresses.PSObject.Properties[$field]){Require ([string]$public.addresses.$field -ceq [string]$login.device.wg_data.addresses.$field) 'identity_address_mismatch'}}
 Assert-Idle $public.public_key
 $hash=[Security.Cryptography.SHA256]::Create();try{$fp=([BitConverter]::ToString($hash.ComputeHash($pubBytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 $created=$false;$lease=[Threading.Mutex]::new($false,('Global\MullvadAdapter.Peer.'+$fp),[ref]$created);Require $created 'peer_lease_exists'
 Assert-Idle $public.public_key;$receipt.identity_match=$true
 if($Mode -eq 'clash'){$stage='clash_preflight';$clashBefore=Assert-ClashIndependent;$receipt.clash_leaf_type=$clashBefore.leaf_type}
 $stage='catalogue';$c=Read-Json (Join-Path $env:LOCALAPPDATA ('MullvadAdapter-'+$Scope+'\relays.json'))
 $relays=@($c.wireguard.relays|Where-Object {$_.hostname -ceq $Relay -and $_.active -eq $true});Require ($relays.Count -eq 1) 'relay_not_uniquely_active';$r=$relays[0]
 Require (Public-V4 $r.ipv4_addr_in) 'relay_ipv4_invalid';$relayKey=[Convert]::FromBase64String($r.public_key);Require ($relayKey.Length -eq 32) 'relay_key_invalid'
 if($Mode -ne 'ss'){Require (In-Ranges $c.wireguard.port_ranges $Port) 'wg_port_not_advertised'}
 $stage='config';$config=Read-Json (Join-Path $diag 'synthetic-ss-template.json')
 $ss=@($config.proxies|Where-Object {$_.type -eq 'ss'});$wgRows=@($config.proxies|Where-Object {$_.type -eq 'wireguard'});Require ($ss.Count -eq 1 -and $wgRows.Count -eq 1) 'template_shape';$ss=$ss[0];$wg=$wgRows[0]
 foreach($proxy in @($ss,$wg)){$proxy.PSObject.Properties.Remove('interface-name');$proxy.PSObject.Properties.Remove('routing-mark')}
 $config.'mixed-port'=17940;$config.'bind-address'='127.0.0.1';$config.'external-controller'='127.0.0.1:17941';$config.secret=([Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N'));$config.'log-level'='debug';$config.'allow-lan'=$false;$config.tun.enable=$false;$config.dns.enable=$false
 $wg.name='MULLVAD';$wg.udp=$true;$ss.name='SS-INLET';$ss.cipher='aes-256-gcm';$ss.password='mullvad';$ss.udp=$true;$config.mode='rule';$config.'proxy-groups'=@([pscustomobject]@{name='OUT';type='select';proxies=@('MULLVAD')});$config.rules=@('MATCH,OUT')
 $config.profile=[pscustomobject]@{'store-selected'=$false;'store-fake-ip'=$false}
 $wg.'private-key'=$login.device.wg_data.private_key;$wg.'public-key'=$r.public_key;$wg.ip=($login.device.wg_data.addresses.ipv4_address -split '/')[0];$wg.ipv6=($login.device.wg_data.addresses.ipv6_address -split '/')[0]
 if($Mode -eq 'ss'){
  $extra=@($r.shadowsocks_extra_addr_in|Where-Object {Public-V4 $_})
  if($extra.Count){$ss.server=$extra[0]}else{Require ($Port -ge 51900 -and $Port -le 51949 -and (In-Ranges $c.wireguard.shadowsocks_port_ranges $Port)) 'primary_ss_port_not_advertised';$ss.server=$r.ipv4_addr_in}
  $ss.port=$Port;$ss.PSObject.Properties.Remove('dialer-proxy');$wg.server='127.0.0.1';$wg.port=51820;$wg.'dialer-proxy'='SS-INLET';$config.proxies=@($ss,$wg)
 }else{
  $wg.server=$r.ipv4_addr_in;$wg.port=$Port;$wg.mtu=1280;$wg.PSObject.Properties.Remove('dialer-proxy');$config.proxies=@($wg)
  if($Mode -eq 'clash'){$wg|Add-Member -NotePropertyName 'dialer-proxy' -NotePropertyValue 'INDEPENDENT-CLASH';$sock=[pscustomobject]@{name='INDEPENDENT-CLASH';type='socks5';server='127.0.0.1';port=7897;udp=$true};$config.proxies=@($sock,$wg)}
 }
 $stage='launch';$exe=Join-Path $env:LOCALAPPDATA 'Mullvad Adapter\runtime\mihomo.exe'
 Require ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant() -ceq '1fa8055e03596fc35167f70e9ecd1890517d38d960a39177445746a1b0defc2b') 'engine_pin_mismatch'
 $work=Join-Path $diag ('path-matrix-'+$id);[void](New-Item -ItemType Directory -Path $work)
 $si=[Diagnostics.ProcessStartInfo]::new();$si.FileName=$exe;$si.Arguments='-f - -d "'+$work+'"';$si.UseShellExecute=$false;$si.CreateNoWindow=$true;$si.RedirectStandardInput=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
 $p=[Diagnostics.Process]::new();$p.StartInfo=$si;$started=$p.Start();Require $started 'engine_start';$receipt.owned_engine_stop=$false
 $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();$payload=[Text.Encoding]::UTF8.GetBytes(($config|ConvertTo-Json -Depth 16 -Compress))
 Require ($p.StandardInput.BaseStream.WriteAsync($payload,0,$payload.Length).Wait(2000)) 'stdin_write_deadline';Require ($p.StandardInput.BaseStream.FlushAsync().Wait(1000)) 'stdin_flush_deadline';$p.StandardInput.Close()
 [Array]::Clear($payload,0,$payload.Length);$payload=$null;[Array]::Clear($bytes,0,$bytes.Length);$bytes=$null;$login=$null;$config=$null;$wg=$null;$ss=$null
 Start-Sleep -Milliseconds 700;Assert-OwnedListeners;$stage='canaries'
 foreach($test in @(@('literal_ip','https://1.1.1.1/cdn-cgi/trace',200),@('hostname','https://www.gstatic.com/generate_204',204))){$receipt.probes+=@(Probe $test[0] $test[1] $test[2]);Assert-OwnedListeners}
 if($Mode -eq 'clash'){$after=Assert-ClashIndependent;Require ($after.signature -ceq $clashBefore.signature) 'clash_selection_changed'}
 if(@($receipt.probes|Where-Object {!$_.pass}).Count -eq 0){$receipt.outcome='COMPONENT_PASS';if($ExitCheck){$receipt.exit_check=Probe 'mullvad_exit' 'https://am.i.mullvad.net/json' 200 -Body}}
}catch{
 $failure=$_.Exception;$closedCode=$null
 for($i=0;$i -lt 8 -and $null -ne $failure;$i++){if([string]$failure.Data['TunnelPathCode'] -cmatch '^[a-z][a-z0-9_]{0,63}$'){$closedCode=[string]$failure.Data['TunnelPathCode'];break};$failure=$failure.InnerException}
 if($closedCode){$receipt.error=$closedCode}else{$receipt.error=$stage+'_failed'};$receipt.outcome='FAIL'
}finally{
 $cleanup=[Diagnostics.Stopwatch]::StartNew()
 $stopped=!$started
 if($p -and $started){try{if(!$p.HasExited){$p.Kill()};$stopped=$p.WaitForExit([int][Math]::Max(0,5000-$cleanup.ElapsedMilliseconds))}catch{$stopped=$false}}
 $receipt.owned_engine_stop=$stopped
 if($stopped -and $out -and $err){try{if($out.Wait([int][Math]::Max(0,[Math]::Min(250,5000-$cleanup.ElapsedMilliseconds))) -and $err.Wait([int][Math]::Max(0,[Math]::Min(250,5000-$cleanup.ElapsedMilliseconds)))){$logs=$out.Result+"`n"+$err.Result;foreach($signal in @('sending handshake initiation','receiving handshake response','handshake did not complete','invalid mac','failed to decrypt','authentication failed','i/o timeout','network is unreachable')){$receipt.public_engine_signal_counters[$signal.Replace(' ','_')]=[regex]::Matches($logs,[regex]::Escape($signal),[Text.RegularExpressions.RegexOptions]::IgnoreCase).Count};$logs=$null}}catch{$receipt.error='log_drain_failed'}}
 if($payload){[Array]::Clear($payload,0,$payload.Length)};if($bytes){[Array]::Clear($bytes,0,$bytes.Length)};if($keyBytes){[Array]::Clear($keyBytes,0,$keyBytes.Length)};$payload=$null;$bytes=$null;$login=$null;$config=$null;$wg=$null;$ss=$null;$wgRows=$null;$out=$null;$err=$null
 if($stopped){if($p){$p.Dispose()};if($lease){$lease.Dispose()}}else{$receipt.outcome='FAIL';$receipt.error='owned_stop_unconfirmed';$global:MullvadDiagnosticUnconfirmedPeerLease=$lease}
 try{[IO.File]::WriteAllText((Join-Path $diag ('path-matrix-'+$Mode+'-'+$Port+'-'+$id+'.json')),($receipt|ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))}catch{$receipt.outcome='FAIL';$receipt.error='receipt_write_failed'}
 $receipt|ConvertTo-Json -Depth 8 -Compress
}
