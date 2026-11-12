# Arche Defender: one-window sweep of the usual persistence and tampering spots, diffed against a saved baseline.
# Read-only: it never deletes, kills or changes anything. The only file it writes is baseline.json beside itself.
# Keep ASCII: Windows PowerShell 5.1 reads this as ANSI. Usage: ArcheDefender.cmd, or ArcheDefender.ps1 -SelfTest
[CmdletBinding()] param([switch]$SelfTest)
$ErrorActionPreference = 'SilentlyContinue'
$baseFile = Join-Path $PSScriptRoot 'baseline.json'

function Alert($t) { [pscustomobject]@{ T = "$t"; Alert = $true } }    # always bad
function Item($t)  { [pscustomobject]@{ T = "$t"; Alert = $false } }   # inventory: flagged only when not in the baseline
function Ver($s)   { $s -replace '\d+(\.\d+){2,}', '*' }               # app updates must not look like new items
function Reg($k, $n) { (Get-ItemProperty $k).$n }

$checks = [ordered]@{
  'Defender' = {
    $s = Get-MpComputerStatus
    if (-not $s) { return Alert 'Defender status unavailable' }
    if (-not $s.RealTimeProtectionEnabled) { Alert 'Real-time protection is OFF' }
    if (-not $s.IsTamperProtected) { Alert 'Tamper protection is OFF' }
    $age = ((Get-Date) - $s.AntivirusSignatureLastUpdated).Days
    if ($age -gt 3) { Alert "Signatures are $age days old" }
    Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) } |
      ForEach-Object { Alert "Detection $($_.InitialDetectionTime): $($_.Resources -join '; ')" }
    $p = Get-MpPreference   # exclusions read as 'N/A: Must be an administrator' unless elevated
    @($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ -and $_ -notmatch '^N/A' } |
      ForEach-Object { Item "Exclusion: $_" }
  }
  'Running programs' = {
    Get-Process | Where-Object Path | Select-Object -ExpandProperty Path -Unique | ForEach-Object {
      if ($_ -match '\\(Temp|Downloads)\\|^C:\\Users\\Public\\') { Alert "Running from a drop folder: $_" }
      if ((Get-AuthenticodeSignature $_).Status -ne 'Valid') { Item (Ver "Unsigned: $_") }
    }
  }
  'Network listeners' = {
    # Keyed by process, not port: Tailscale and Steam pick new ports every start. Loopback and RPC dynamic ports skipped.
    Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -lt 49152 -and $_.LocalAddress -notmatch '^(127\.|::1$)' } | ForEach-Object {
      $n = (Get-Process -Id $_.OwningProcess).ProcessName
      if ($n -in 'System', 'svchost') { Item "$n port $($_.LocalPort)" } else { Item "$n" }
    }
  }
  'Startup entries' = {
    Get-CimInstance Win32_StartupCommand | ForEach-Object { Item (Ver "$($_.Name) -> $($_.Command)") }
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' | ForEach-Object {
      $k = $_; (Get-Item $k).Property | ForEach-Object { Item (Ver "$_ -> $(Reg $k $_)") }
    }
  }
  'Scheduled tasks' = {
    # ponytail: only tasks that run a program. COM-handler tasks (Windows' SoftLanding) have no command line to show.
    Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled' } | ForEach-Object {
      $a = ($_.Actions | Where-Object Execute | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
      if ($a) { Item (Ver "$($_.TaskPath)$($_.TaskName) -> $a") }
    }
  }
  'Services' = {
    Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -and $_.PathName -notmatch '(?i)\\windows\\' } |
      ForEach-Object { Item (Ver "$($_.Name) [$($_.StartName)] -> $($_.PathName)") }
  }
  'Hijack points' = {
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ((Reg $wl Shell) -ne 'explorer.exe') { Alert "Winlogon Shell is '$(Reg $wl Shell)'" }
    if ((Reg $wl Userinit) -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Alert "Winlogon Userinit is '$(Reg $wl Userinit)'" }
    $ai = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' AppInit_DLLs
    if ($ai) { Alert "AppInit_DLLs: $ai" }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
      $d = Reg $_.PSPath Debugger; if ($d) { Alert "Debugger hijack on $($_.PSChildName): $d" }
    }
    'CommandLineEventConsumer', 'ActiveScriptEventConsumer' | ForEach-Object {
      Get-CimInstance -Namespace root\subscription -ClassName $_ | ForEach-Object { Alert "WMI consumer $($_.Name): $($_.CommandLineTemplate)$($_.ScriptFileName)" }
    }
  }
  'Network settings' = {
    Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { Item "hosts: $($_.Trim())" }
    Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique | ForEach-Object { Item "DNS server: $_" }
    $is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if (Reg $is ProxyEnable) { Item "Proxy: $(Reg $is ProxyServer)" }
    if (Reg $is AutoConfigURL) { Item "Proxy auto-config: $(Reg $is AutoConfigURL)" }
  }
  'Remote access and accounts' = {
    if ((Reg 'HKLM:\System\CurrentControlSet\Control\Terminal Server' fDenyTSConnections) -eq 0) { Item 'Remote Desktop is enabled' }
    Get-Service sshd, WinRM, RemoteRegistry | Where-Object Status -eq 'Running' | ForEach-Object { Item "Service running: $($_.Name)" }
    "$env:USERPROFILE\.ssh\authorized_keys", "$env:ProgramData\ssh\administrators_authorized_keys" | Where-Object { Test-Path $_ } | ForEach-Object { Item "SSH keys accepted: $_" }
    Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object { Item "Share: $($_.Name) -> $($_.Path)" }
    Get-LocalUser | Where-Object Enabled | ForEach-Object { Item "Enabled account: $($_.Name)" }
  }
  'Browser extensions' = {
    $b = @{ Chrome = 'Google\Chrome'; Edge = 'Microsoft\Edge'; Brave = 'BraveSoftware\Brave-Browser' }
    foreach ($n in $b.Keys) {
      foreach ($e in (Get-ChildItem "$env:LOCALAPPDATA\$($b[$n])\User Data\*\Extensions\*" -Directory)) {
        $m = Get-ChildItem $e.FullName -Recurse -Filter manifest.json -Depth 1 | Select-Object -First 1
        if (-not $m) { continue }
        $j = Get-Content $m.FullName -Raw | ConvertFrom-Json; $name = $j.name
        if ($name -match '^__MSG_(.+)__$') {
          $loc = 'en', 'en_US', 'en_GB' | ForEach-Object { "$($m.DirectoryName)\_locales\$_\messages.json" } | Where-Object { Test-Path $_ } | Select-Object -First 1
          if ($loc) { $v = (Get-Content $loc -Raw | ConvertFrom-Json).($Matches[1]).message; if ($v) { $name = $v } }
        }
        $wide = if ("$($j.permissions) $($j.host_permissions)" -match '<all_urls>|\*://\*/|https?://\*/') { ' (all sites)' }
        Item "${n}: $name [$($e.Name)]$wide"
      }
    }
    'HKCU:\Software\Google\Chrome', 'HKCU:\Software\Microsoft\Edge', 'HKLM:\Software\Google\Chrome', 'HKLM:\Software\Microsoft\Edge', 'HKCU:\Software\Mozilla' | ForEach-Object {
      Get-ChildItem "$_\NativeMessagingHosts" | ForEach-Object { Item (Ver "Native host: $($_.PSChildName) -> $(Reg $_.PSPath '(default)')") }
    }
  }
  'Drivers' = {
    Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | ForEach-Object {
      $p = $_.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:windir -replace '^system32', "$env:windir\system32"
      $c = (Get-Item $p).VersionInfo.CompanyName
      if ($c -notmatch 'Microsoft') {
        if ((Get-AuthenticodeSignature $p).Status -ne 'Valid') { Alert "Unsigned driver: $($_.Name) ($p)" } else { Item "$($_.Name) ($c)" }
      }
    }
  }
}

function Get-Baseline { if (Test-Path $baseFile) { Get-Content $baseFile -Raw | ConvertFrom-Json } }

# One check -> its rows, each marked Alert, New (not in baseline) or known.
function Invoke-Check($name, $base) {
  $known = @(if ($base) { $base.$name })
  @(& $checks[$name]) | Where-Object T | Sort-Object T -Unique | ForEach-Object {
    $_ | Add-Member New ([bool]($base -and -not $_.Alert -and $known -notcontains $_.T)) -PassThru
  }
}

if ($SelfTest) {
  $fail = 0
  if ((Ver 'C:\x\app-1.0.9267\a.exe') -ne 'C:\x\app-*\a.exe') { 'FAIL Ver'; $fail++ }
  $checks['_t'] = { Item 'known'; Item 'fresh'; Alert 'bad' }
  $r = Invoke-Check '_t' ([pscustomobject]@{ _t = @('known') })
  if (@($r | Where-Object New).T -ne 'fresh' -or @($r | Where-Object Alert).T -ne 'bad') { 'FAIL baseline diff'; $fail++ }
  $checks.Remove('_t')
  foreach ($n in $checks.Keys) {
    $r = @(Invoke-Check $n $null)
    '{0,-28} {1,3} rows, {2} alerts' -f $n, $r.Count, @($r | Where-Object Alert).Count
    $r | Where-Object Alert | ForEach-Object { "    [!] $($_.T)" }
  }
  if ($fail) { exit 1 } else { 'self-test passed' }
}

Add-Type -AssemblyName PresentationFramework
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Arche Defender" Width="1040" Height="640"
        Background="#14161a" WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="13">
  <Grid Margin="14">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Grid.ColumnDefinitions><ColumnDefinition Width="300"/><ColumnDefinition/></Grid.ColumnDefinitions>
    <DockPanel Grid.ColumnSpan="2" Margin="0,0,0,12">
      <TextBlock Text="ARCHE DEFENDER" Foreground="#e8eaed" FontSize="20" FontWeight="Bold" VerticalAlignment="Center"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button Name="Save" Content="Accept as baseline" Padding="14,6" Margin="0,0,8,0" Background="#2a2e35" Foreground="#e8eaed" BorderBrush="#3a3f47"/>
        <Button Name="Scan" Content="Scan" Padding="22,6" Background="#2f6f4f" Foreground="White" BorderBrush="#2f6f4f" FontWeight="Bold"/>
      </StackPanel>
    </DockPanel>
    <ListBox Name="List" Grid.Row="1" Background="#1b1e23" BorderBrush="#2a2e35" Margin="0,0,10,0" FontSize="14"/>
    <TextBox Name="Detail" Grid.Row="1" Grid.Column="1" IsReadOnly="True" Background="#1b1e23" Foreground="#cfd3d8" BorderBrush="#2a2e35"
             FontFamily="Consolas" Padding="8" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
    <TextBlock Name="Status" Grid.Row="2" Grid.ColumnSpan="2" Foreground="#9aa0a6" Margin="0,10,0,0"/>
  </Grid>
</Window>
'@
$win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}; 'Scan', 'Save', 'List', 'Detail', 'Status' | ForEach-Object { $ui[$_] = $win.FindName($_) }
if ($SelfTest) { 'window built'; exit 0 }

$script:last = @{}
function Show-Detail($name) {
  $ui.Detail.Text = if ($script:last[$name]) {
    ($script:last[$name] | ForEach-Object { $(if ($_.Alert) { '[!] ' } elseif ($_.New) { '[+] ' } else { '    ' }) + $_.T }) -join "`r`n"
  } else { 'Nothing to report.' }
}
function Start-Scan {
  $ui.Scan.IsEnabled = $false; $ui.List.Items.Clear(); $ui.Detail.Text = ''; $script:last = @{}
  $base = Get-Baseline; $alerts = 0; $new = 0
  foreach ($n in $checks.Keys) {
    $ui.Status.Text = "Scanning: $n ..."
    # ponytail: checks run on the UI thread, pumped between checks so the list fills in. Move to a runspace if a check gets slow.
    $win.Dispatcher.Invoke([Action] {}, [Windows.Threading.DispatcherPriority]::Background)
    $r = @(Invoke-Check $n $base); $script:last[$n] = $r
    $a = @($r | Where-Object Alert).Count; $w = @($r | Where-Object New).Count; $alerts += $a; $new += $w
    $row = New-Object Windows.Controls.ListBoxItem
    $row.Tag = $n; $row.Padding = '8,6'
    $row.Content = if ($a) { "!!   $n  ($a alert)" } elseif ($w) { "+    $n  ($w new)" } else { "ok   $n  ($($r.Count))" }
    $row.Foreground = if ($a) { '#ff6b6b' } elseif ($w) { '#f5c451' } else { '#7bd88f' }
    [void]$ui.List.Items.Add($row)
  }
  $ui.Status.Text = "$(Get-Date -Format 'HH:mm:ss')  $alerts alerts, $new new since baseline." + $(if (-not $base) { '  No baseline yet: review the lists, then Accept as baseline.' })
  $ui.Scan.IsEnabled = $true
  $first = $ui.List.Items | Where-Object { $_.Content -notmatch '^ok' } | Select-Object -First 1
  $ui.List.SelectedItem = if ($first) { $first } else { $ui.List.Items[0] }
}
$ui.List.Add_SelectionChanged({ if ($ui.List.SelectedItem) { Show-Detail $ui.List.SelectedItem.Tag } })
$ui.Scan.Add_Click({ Start-Scan })
$ui.Save.Add_Click({
  if (-not $script:last.Count) { return }
  $b = [ordered]@{}; foreach ($n in $checks.Keys) { $b[$n] = @($script:last[$n] | Where-Object { -not $_.Alert } | ForEach-Object T) }
  $b | ConvertTo-Json -Depth 3 | Set-Content $baseFile -Encoding UTF8
  Start-Scan
})
$win.Add_ContentRendered({ Start-Scan })
[void]$win.ShowDialog()
