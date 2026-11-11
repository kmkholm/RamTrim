# RamTrim security engine: connections, core-process verification, eavesdropping and persistence checks.
# Every finding states the evidence it rests on. Findings are indicators to review, not proof of malware.
# Nothing is sent off this machine: host names come from the local DNS cache only.

$script:SigCache = @{}
$script:WinDir = $env:windir

function Get-Sig([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ Status = 'NoPath'; Signer = '' } }
    $key = $Path.ToLower()
    if ($script:SigCache.ContainsKey($key)) { return $script:SigCache[$key] }
    $r = [pscustomobject]@{ Status = 'Unknown'; Signer = '' }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $r.Status = 'Unreadable' }
        else {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $r.Status = [string]$s.Status      # Valid, NotSigned, HashMismatch, NotTrusted, UnknownError
            if ($s.SignerCertificate) {
                $subj = $s.SignerCertificate.Subject
                $r.Signer = if ($subj -match 'CN="([^"]+)"') { $Matches[1] } elseif ($subj -match 'CN=([^,]+)') { $Matches[1] } else { $subj }
            }
        }
    } catch { $r.Status = 'Unknown' }
    $script:SigCache[$key] = $r
    $r
}

function Test-RiskyDir([string]$Path) {
    if (-not $Path) { return $false }
    $Path -match '\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\Downloads\\|\\\$Recycle\.Bin\\|^[A-Za-z]:\\ProgramData\\[^\\]+\.(exe|scr|com)$'
}

function Get-IpScope([string]$Ip) {
    if (-not $Ip) { return 'none' }
    $a = $Ip -replace '^::ffff:', '' -replace '%.*$', ''
    if ($a -like '0.*' -or $a -eq '::') { return 'any' }      # 0.0.0.0/8 is not routable (used to block names)
    if ($a -eq '::1' -or $a -like '127.*') { return 'loop' }
    if ($a -match '^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)') { return 'lan' }
    if ($a -match '^(fe[89ab]|f[cd])') { return 'lan' }
    if ($a -match '^(22[4-9]|23\d)\.' -or $a -eq '255.255.255.255' -or $a -like 'ff*') { return 'multi' }
    'public'
}

function Get-ProcTable {
    $wins = @{}
    # a browser's network traffic belongs to a windowless child process, so "has a window" is judged per program name
    foreach ($p in Get-Process) { if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $wins[$p.ProcessName.ToLower()] = $true } }
    $h = @{}
    foreach ($p in Get-CimInstance Win32_Process) {
        $id = [int]$p.ProcessId
        $path = $p.ExecutablePath; if ($path -and $path.StartsWith('\\?\')) { $path = $path.Substring(4) }
        $h[$id] = [pscustomobject]@{ Id = $id; Name = $p.Name; Path = $path; Parent = [int]$p.ParentProcessId
                                     Cmd = $p.CommandLine; Created = $p.CreationDate; Window = $wins.ContainsKey(($p.Name -replace '\.exe$', '').ToLower()) }
    }
    $h
}

function Get-RawEndpoints {
    $rows = New-Object System.Collections.ArrayList
    foreach ($c in Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $st = [string]$c.State
        if ($st -ne 'Established' -and $st -ne 'Listen') { continue }
        [void]$rows.Add([pscustomobject]@{ Proto = 'TCP'; State = $st; LAddr = $c.LocalAddress; LPort = [int]$c.LocalPort
                                           RAddr = $(if ($st -eq 'Listen') { '' } else { $c.RemoteAddress }); RPort = [int]$c.RemotePort; Id = [int]$c.OwningProcess })
    }
    foreach ($u in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        [void]$rows.Add([pscustomobject]@{ Proto = 'UDP'; State = 'Bound'; LAddr = $u.LocalAddress; LPort = [int]$u.LocalPort; RAddr = ''; RPort = 0; Id = [int]$u.OwningProcess })
    }
    $rows
}

function Get-Connections($Procs) {
    if (-not $Procs) { $Procs = Get-ProcTable }
    $dns = @{}
    try { foreach ($d in Get-DnsClientCache -ErrorAction Stop) { if ($d.Data -and ($d.Type -eq 1 -or $d.Type -eq 28) -and -not $dns.ContainsKey($d.Data)) { $dns[$d.Data] = $d.Entry } } } catch { }
    foreach ($e in Get-RawEndpoints) {
        $p = $Procs[$e.Id]
        $scope = if ($e.State -eq 'Established') { Get-IpScope $e.RAddr } else { Get-IpScope $e.LAddr }
        [pscustomobject]@{
            Name = $(if ($p) { $p.Name } elseif ($e.Id -eq 0) { 'System Idle' } else { '?' }); Id = $e.Id; Proto = $e.Proto; State = $e.State
            Local = $(if ($e.LAddr -like '*:*') { '[{0}]:{1}' -f $e.LAddr, $e.LPort } else { '{0}:{1}' -f $e.LAddr, $e.LPort })
            Remote = $(if (-not $e.RAddr) { '' } elseif ($e.RAddr -like '*:*') { '[{0}]:{1}' -f $e.RAddr, $e.RPort } else { '{0}:{1}' -f $e.RAddr, $e.RPort })
            RAddr = $e.RAddr; LPort = $e.LPort; LAddr = $e.LAddr
            Host = $(if ($e.RAddr -and $dns.ContainsKey($e.RAddr)) { $dns[$e.RAddr] } else { '' })
            Scope = $scope; Path = $(if ($p) { $p.Path } else { $null }); Window = $(if ($p) { $p.Window } else { $false }); Known = [bool]$p
        }
    }
}

# ---- Windows core processes: where they must live and who must have started them
$script:CoreSys = 'smss', 'csrss', 'wininit', 'services', 'lsass', 'lsaiso', 'svchost', 'winlogon', 'dwm', 'fontdrvhost', 'spoolsv', 'taskhostw',
    'sihost', 'ctfmon', 'conhost', 'dllhost', 'runtimebroker', 'searchindexer', 'audiodg', 'userinit', 'logonui', 'wudfhost', 'dashost',
    'taskmgr', 'rundll32', 'regsvr32', 'cmd', 'powershell', 'wscript', 'cscript', 'mshta', 'msiexec', 'werfault', 'smartscreen', 'securityhealthservice'
$script:CoreParent = @{ 'services' = 'wininit'; 'lsass' = 'wininit'; 'lsaiso' = 'wininit'; 'svchost' = 'services'; 'spoolsv' = 'services'; 'searchindexer' = 'services'; 'dwm' = 'winlogon' }
$script:LookTargets = 'svchost', 'lsass', 'csrss', 'services', 'winlogon', 'explorer', 'wininit', 'spoolsv', 'taskhostw', 'rundll32', 'conhost', 'dllhost'
$script:LolBins = 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'msbuild', 'installutil', 'regasm', 'cmd'
$script:RemoteTools = '^(ultraviewer|anydesk|teamviewer|tv_w32|tv_x64|rustdesk|vncserver|winvnc|tvnserver|uvnc_service|radmin|rserver3|screenconnect|connectwise|ammyy|aa_v3|supremo|logmein|lmiguardian|splashtop|srservice|strwinclt|remoting_host|aeroadmin|dwagent|dwagsvc|ateraagent|client32|meshagent|ngrok|parsecd|zohoassist|zaservice|g2a|getscreen|iperius|hoptodesk|msra)'
$script:BadCmd = '(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|downloadstring|downloadfile|frombase64string|invoke-expression|\biex\b|net\.webclient|invoke-webrequest.*\|\s*iex|bitsadmin.*/transfer|certutil.*-urlcache)'

function Test-EditOne([string]$a, [string]$b) {
    # true when a and b differ by exactly one insertion, deletion or substitution
    if ($a -eq $b) { return $false }
    $la = $a.Length; $lb = $b.Length
    if ([math]::Abs($la - $lb) -gt 1) { return $false }
    $i = 0; $j = 0; $diff = 0
    while ($i -lt $la -and $j -lt $lb) {
        if ($a[$i] -eq $b[$j]) { $i++; $j++; continue }
        $diff++; if ($diff -gt 1) { return $false }
        if ($la -gt $lb) { $i++ } elseif ($lb -gt $la) { $j++ } else { $i++; $j++ }
    }
    ($diff + ($la - $i) + ($lb - $j)) -eq 1
}

function Get-ExeFromCommand([string]$Cmd) {
    if (-not $Cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd).Trim()
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 1) { return $c.Substring(1, $e - 1) } }
    if ($c -match '(?i)^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|scr|lnk))(\s|$)') { return $Matches[1] }
    ($c -split '\s+')[0]
}

function Get-CapabilityUse([string]$Cap, $Procs) {
    $running = @{}
    foreach ($p in $Procs.Values) { if ($p.Path) { $running[$p.Path.ToLower()] = $true } }
    foreach ($hive in 'HKCU:', 'HKLM:') {
        $base = "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$Cap"
        if (-not (Test-Path $base)) { continue }
        $keys = @(Get-ChildItem $base -ErrorAction SilentlyContinue | Where-Object PSChildName -ne 'NonPackaged') + @(Get-ChildItem "$base\NonPackaged" -ErrorAction SilentlyContinue)
        foreach ($k in $keys) {
            $start = $k.GetValue('LastUsedTimeStart'); $stop = $k.GetValue('LastUsedTimeStop')
            if (-not $start) { continue }
            $np = $k.Name -like '*\NonPackaged\*'
            $path = if ($np) { $k.PSChildName -replace '#', '\' } else { $null }
            $inUse = ($stop -eq 0)
            # a crashed app leaves Stop = 0 behind; trust "in use" for classic apps only while the exe is running
            if ($inUse -and $np -and -not $running.ContainsKey($path.ToLower())) { $inUse = $false; $stop = $start }
            [pscustomobject]@{ Cap = $Cap; App = $(if ($np) { Split-Path $path -Leaf } else { $k.PSChildName }); Path = $path
                               Start = [DateTime]::FromFileTime($start); Stop = $(if ($stop) { [DateTime]::FromFileTime($stop) } else { $null }); InUse = $inUse }
        }
    }
}

function Get-StartupEntries {
    foreach ($rk in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
        $k = Get-Item $rk -ErrorAction SilentlyContinue; if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) { if ($n) { [pscustomobject]@{ Source = 'Run'; Where = $rk -replace '^HK(..):\\Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\', 'HK$1 '; Name = $n; Cmd = [string]$k.GetValue($n) } } }
    }
    foreach ($dir in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
        if (-not $dir -or -not (Test-Path $dir)) { continue }
        foreach ($f in Get-ChildItem $dir -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini') {
            $target = $f.FullName
            if ($f.Extension -eq '.lnk') { try { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).TargetPath } catch { } }
            [pscustomobject]@{ Source = 'StartupFolder'; Where = 'Startup folder'; Name = $f.Name; Cmd = "`"$target`"" }
        }
    }
    try {
        foreach ($t in Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and [string]$_.State -ne 'Disabled' }) {
            foreach ($a in $t.Actions) { if ($a.Execute) { [pscustomobject]@{ Source = 'Task'; Where = 'Scheduled task'; Name = ($t.TaskPath + $t.TaskName); Cmd = ('"{0}" {1}' -f $a.Execute.Trim('"'), $a.Arguments) } } }
        }
    } catch { }
}

function Invoke-SecurityScan([scriptblock]$OnProgress) {
    $F = New-Object System.Collections.ArrayList
    function Add-F([int]$Sev, [string]$Cat, [string]$Subject, [string]$Ar, [string]$En, [string]$Path, [int]$Id) {
        [void]$F.Add([pscustomobject]@{ Sev = $Sev; Cat = $Cat; Subject = $Subject; Ar = $Ar; En = $En; Path = $Path; Id = $Id })
    }
    function Step([int]$pct) { if ($OnProgress) { & $OnProgress $pct } }
    $sysDirs = @("$script:WinDir\System32", "$script:WinDir\SysWOW64") | ForEach-Object { $_.ToLower() }

    Step 3
    $procs = Get-ProcTable
    $conns = @(Get-Connections $procs)
    Step 10

    # ---- 1. connections owned by a PID that has no process (possible hidden process)
    $orphans = @($conns | Where-Object { -not $_.Known -and $_.Id -gt 4 } | Select-Object -ExpandProperty Id -Unique)
    if ($orphans.Count) {
        Start-Sleep -Milliseconds 1200          # rule out a process that was simply exiting
        $again = @{}; foreach ($e in Get-RawEndpoints) { $again[$e.Id] = $true }
        $alive = @{}; foreach ($p in Get-Process) { $alive[$p.Id] = $true }
        foreach ($id in $orphans) {
            if ($again.ContainsKey($id) -and -not $alive.ContainsKey($id)) {
                $c = $conns | Where-Object Id -eq $id | Select-Object -First 1
                Add-F 3 'net' "PID $id" "اتصال ($($c.Proto) $($c.Local) $($c.Remote)) يملكه رقم عملية غير ظاهر في قائمة العمليات، وبقي كذلك بعد إعادة الفحص. قد يدل على عملية مخفية." "A connection ($($c.Proto) $($c.Local) $($c.Remote)) is owned by a PID missing from the process list, and still was on re-check. Possible hidden process." '' $id
            }
        }
    }

    # ---- 2. per-process checks
    $byPath = @{}; $pubByProc = @{}
    foreach ($c in $conns) { if ($c.State -eq 'Established' -and $c.Scope -eq 'public') { $pubByProc[$c.Id] = 1 + [int]$pubByProc[$c.Id] } }
    $self = @{}; $cur = $PID          # this tool and whatever launched it are not suspects
    while ($cur -gt 4 -and $procs.ContainsKey($cur) -and -not $self.ContainsKey($cur)) { $self[$cur] = $true; $cur = $procs[$cur].Parent }
    $list = @($procs.Values | Where-Object { $_.Id -gt 4 -and -not $self.ContainsKey($_.Id) })
    $unverified = 0; $n = 0
    foreach ($p in $list) {
        $n++; if ($n % 12 -eq 0) { Step (10 + [int](55 * $n / $list.Count)) }
        $base = ($p.Name -replace '\.exe$', '').ToLower()
        $isCore = $script:CoreSys -contains $base -or $base -eq 'explorer'

        # parent check (skipped when the parent exited or its PID was reused by a younger process)
        if ($script:CoreParent.ContainsKey($base)) {
            $par = $procs[$p.Parent]
            if ($par -and $par.Created -le $p.Created) {
                $pb = ($par.Name -replace '\.exe$', '').ToLower()
                if ($pb -ne $script:CoreParent[$base]) {
                    Add-F 3 'proc' "$($p.Name) ($($p.Id))" "عملية نظام شغّلها «$($par.Name)» بدل «$($script:CoreParent[$base]).exe» المتوقع. هذا نمط انتحال." "System process started by '$($par.Name)' instead of the expected '$($script:CoreParent[$base]).exe'. This is a masquerading pattern." $p.Path $p.Id
                }
            }
        }
        if (-not $p.Path) { if ($isCore) { $unverified++ }; continue }
        $dir = (Split-Path $p.Path -Parent).ToLower()

        # core name outside the Windows directories
        if ($isCore) {
            $okDir = if ($base -eq 'explorer') { $dir -eq $script:WinDir.ToLower() -or $dir -eq $sysDirs[1] } else { $sysDirs -contains $dir -or $dir -like "$($sysDirs[0])\*" }
            if (-not $okDir) {
                Add-F 3 'proc' "$($p.Name) ($($p.Id))" "يحمل اسم عملية نظام لكنه يعمل من مسار غير مجلد ويندوز: $($p.Path)" "Carries a Windows system process name but runs from outside the Windows folder: $($p.Path)" $p.Path $p.Id
            }
        }
        elseif ($base.Length -ge 5) {
            foreach ($t in $script:LookTargets) {
                if (Test-EditOne $base $t) {
                    Add-F 2 'proc' "$($p.Name) ($($p.Id))" "الاسم يختلف بحرف واحد عن عملية النظام «$t.exe». تحقق من مصدره: $($p.Path)" "Name is one character away from the system process '$t.exe'. Check where it came from: $($p.Path)" $p.Path $p.Id
                    break
                }
            }
        }

        # script hosts and living-off-the-land binaries
        if ($script:LolBins -contains $base) {
            if ($p.Cmd -and $p.Cmd -match $script:BadCmd) {
                $snip = if ($p.Cmd.Length -gt 160) { $p.Cmd.Substring(0, 160) + '...' } else { $p.Cmd }
                Add-F 3 'proc' "$($p.Name) ($($p.Id))" "سطر أوامر فيه تنزيل أو تنفيذ مشفَّر: $snip" "Command line contains a download or encoded execution: $snip" $p.Path $p.Id
            }
            if ($pubByProc.ContainsKey($p.Id)) {
                Add-F 2 'net' "$($p.Name) ($($p.Id))" "مفسِّر أوامر له $($pubByProc[$p.Id]) اتصال بعناوين إنترنت عامة. طبيعي لسكربت تعرفه، ومريب إن لم تعرفه." "A script host holds $($pubByProc[$p.Id]) connection(s) to public internet addresses. Normal for a script you know, suspicious otherwise." $p.Path $p.Id
            }
        }

        # remote-control software
        if ($base -match $script:RemoteTools) {
            $key = "rt:$base"
            if (-not $byPath.ContainsKey($key)) {
                $byPath[$key] = $true
                Add-F 2 'privacy' $p.Name "برنامج تحكم عن بعد يعمل الآن ويستطيع رؤية الشاشة والتحكم بالجهاز. طبيعي إن كنت أنت من ثبّته وتستعمله، وإلا فأغلقه." "Remote-control software is running and can view the screen and control this PC. Normal if you installed and use it, otherwise close it." $p.Path $p.Id
            }
        }

        # signature (one finding per executable file)
        $pk = $p.Path.ToLower()
        if ($byPath.ContainsKey($pk)) { continue }
        $byPath[$pk] = $true
        $sig = Get-Sig $p.Path
        # Store apps are signed as a whole package and live in an OS-protected folder; their exes carry no own signature
        if ($sig.Status -eq 'NotSigned' -and $p.Path -like "$env:ProgramFiles\WindowsApps\*") { continue }
        $ctx = @(); $ctxEn = @()
        if (Test-RiskyDir $p.Path) { $ctx += 'يعمل من مجلد مؤقت أو تنزيلات'; $ctxEn += 'runs from a temp or downloads folder' }
        if ($pubByProc.ContainsKey($p.Id)) { $ctx += 'له اتصالات بالإنترنت'; $ctxEn += 'has internet connections' }
        $tail = if ($ctx.Count) { ' (' + ($ctx -join '، ') + ')' } else { '' }
        $tailEn = if ($ctxEn.Count) { ' (' + ($ctxEn -join ', ') + ')' } else { '' }
        switch ($sig.Status) {
            'HashMismatch' { Add-F 3 'proc' $p.Name "الملف عُدِّل بعد توقيعه (التوقيع الرقمي لا يطابق المحتوى): $($p.Path)" "The file was modified after signing (digital signature does not match the content): $($p.Path)" $p.Path $p.Id }
            'NotTrusted' { Add-F 2 'proc' $p.Name "موقَّع بشهادة غير موثوقة على هذا الجهاز$tail`: $($p.Path)" "Signed with a certificate this PC does not trust$tailEn`: $($p.Path)" $p.Path $p.Id }
            'NotSigned' { Add-F $(if ($ctx.Count) { 2 } else { 1 }) 'proc' $p.Name "برنامج غير موقَّع رقميًا$tail`: $($p.Path)" "Program has no digital signature$tailEn`: $($p.Path)" $p.Path $p.Id }
            'Unreadable' { Add-F 1 'proc' $p.Name "ملفه التنفيذي غير موجود أو لا يمكن قراءته وهو يعمل$tail`: $($p.Path)" "Its executable is missing or unreadable while it runs$tailEn`: $($p.Path)" $p.Path $p.Id }
        }
    }
    Step 66

    # ---- 3. ports open to the whole network
    $seen = @{}
    foreach ($c in $conns | Where-Object { $_.Proto -eq 'TCP' -and $_.State -eq 'Listen' -and $_.Scope -eq 'any' -and $_.Path }) {
        $sig = Get-Sig $c.Path
        if ($sig.Status -eq 'Valid' -and $sig.Signer -like 'Microsoft*') { continue }
        $k = "$($c.Name)"; if (-not $seen.ContainsKey($k)) { $seen[$k] = New-Object System.Collections.ArrayList }
        if ($seen[$k] -notcontains $c.LPort) { [void]$seen[$k].Add($c.LPort) }
    }
    foreach ($k in $seen.Keys) {
        $c = $conns | Where-Object { $_.Name -eq $k -and $_.Path } | Select-Object -First 1
        $sig = Get-Sig $c.Path; $ports = ($seen[$k] | Sort-Object) -join ', '
        $sev = if ($sig.Status -eq 'Valid') { 1 } else { 2 }
        Add-F $sev 'net' $k "يستمع على المنفذ $ports لكل واجهات الشبكة، فأي جهاز على شبكتك يستطيع محاولة الاتصال به (إن سمح الجدار الناري)." "Listens on port $ports on all network interfaces, so any device on your network can try to connect (if the firewall allows)." $c.Path $c.Id
    }
    Step 72

    # ---- 4. microphone and camera
    foreach ($cap in 'microphone', 'webcam') {
        $capAr = if ($cap -eq 'microphone') { 'الميكروفون' } else { 'الكاميرا' }
        $uses = @(Get-CapabilityUse $cap $procs | Sort-Object App, Start -Descending)
        $done = @{}
        foreach ($u in $uses) {
            if ($done.ContainsKey($u.App)) { continue }; $done[$u.App] = $true
            $sig = if ($u.Path) { Get-Sig $u.Path } else { $null }
            $unsigned = $sig -and $sig.Status -in 'NotSigned', 'HashMismatch', 'NotTrusted'
            if ($u.InUse) {
                Add-F $(if ($unsigned) { 3 } else { 2 }) 'privacy' $u.App "مسجَّل في ويندوز أنه يستخدم $capAr الآن (منذ $($u.Start.ToString('HH:mm')))$(if ($unsigned) { '، وهو غير موقَّع' })." "Windows records it as using the $cap right now (since $($u.Start.ToString('HH:mm')))$(if ($unsigned) { ', and it is not signed' })." $u.Path 0
            }
            elseif ($u.Start -gt (Get-Date).AddDays(-7)) {
                Add-F $(if ($unsigned) { 2 } else { 0 }) 'privacy' $u.App "استخدم $capAr آخر مرة $($u.Start.ToString('yyyy-MM-dd HH:mm'))$(if ($unsigned) { '، وهو غير موقَّع' })." "Last used the $cap on $($u.Start.ToString('yyyy-MM-dd HH:mm'))$(if ($unsigned) { ', and it is not signed' })." $u.Path 0
            }
        }
    }
    Step 78

    # ---- 5. what starts with Windows
    $entries = @(Get-StartupEntries)
    foreach ($e in $entries) {
        $exe = Get-ExeFromCommand $e.Cmd
        $base = if ($exe) { ([IO.Path]::GetFileNameWithoutExtension($exe)).ToLower() } else { '' }
        $subj = "$($e.Where): $($e.Name)"
        if ($e.Cmd -match $script:BadCmd) {
            Add-F 3 'startup' $subj "يبدأ مع ويندوز بأمر فيه تنزيل أو تنفيذ مشفَّر: $($e.Cmd)" "Starts with Windows using a download or encoded command: $($e.Cmd)" $exe 0; continue
        }
        if ($script:LolBins -contains $base) {
            Add-F 1 'startup' $subj "يبدأ مع ويندوز عبر مفسِّر أوامر: $($e.Cmd)" "Starts with Windows through a script host: $($e.Cmd)" $exe 0; continue
        }
        if (-not $exe -or $exe -notmatch '^[A-Za-z]:\\') { continue }          # bare names resolve through PATH; not checked
        $sig = Get-Sig $exe; $risky = Test-RiskyDir $exe
        switch ($sig.Status) {
            'HashMismatch' { Add-F 3 'startup' $subj "ملف الإقلاع عُدِّل بعد توقيعه: $exe" "The startup file was modified after signing: $exe" $exe 0 }
            'NotTrusted' { Add-F 2 'startup' $subj "يبدأ مع ويندوز وموقَّع بشهادة غير موثوقة: $exe" "Starts with Windows and is signed with an untrusted certificate: $exe" $exe 0 }
            'NotSigned' { Add-F $(if ($risky) { 2 } else { 1 }) 'startup' $subj "يبدأ مع ويندوز وهو غير موقَّع$(if ($risky) { ' ومن مجلد مؤقت' })`: $exe" "Starts with Windows and is not signed$(if ($risky) { ', from a temp folder' })`: $exe" $exe 0 }
            'Unreadable' { Add-F 0 'startup' $subj "مدخل إقلاع يشير إلى ملف غير موجود (بقايا برنامج محذوف): $exe" "Startup entry points to a missing file (leftover of a removed program): $exe" $exe 0 }
        }
    }
    Step 90

    # ---- 6. system settings that redirect or expose traffic
    try {
        $hosts = @(Get-Content "$script:WinDir\System32\drivers\etc\hosts" -ErrorAction Stop | Where-Object { $_ -match '^\s*[0-9a-fA-F:.]+\s+\S' })
        $redir = @($hosts | Where-Object { $_ -notmatch '^\s*(127\.0\.0\.1|::1|0\.0\.0\.0)\s' })
        $pubRedir = @($redir | Where-Object { (Get-IpScope (($_.Trim() -split '\s+')[0])) -eq 'public' })
        if ($redir.Count) { Add-F $(if ($pubRedir.Count) { 2 } else { 1 }) 'system' 'hosts' "ملف hosts يحوّل $($redir.Count) اسمًا إلى عناوين أخرى ($($pubRedir.Count) منها عناوين إنترنت عامة)، مثل: $($redir[0].Trim())" "The hosts file redirects $($redir.Count) name(s) to other addresses ($($pubRedir.Count) of them public internet addresses), e.g. $($redir[0].Trim())" "$script:WinDir\System32\drivers\etc\hosts" 0 }
        elseif ($hosts.Count) { Add-F 0 'system' 'hosts' "ملف hosts فيه $($hosts.Count) مدخلًا، كلها تحجب أو تشير إلى الجهاز نفسه." "The hosts file has $($hosts.Count) entries, all blocking or pointing to this PC." "$script:WinDir\System32\drivers\etc\hosts" 0 }
    } catch { }
    $inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($inet.ProxyEnable -eq 1 -and $inet.ProxyServer) { Add-F 2 'system' 'Proxy' "تصفح الإنترنت يمرّ عبر وسيط (Proxy): $($inet.ProxyServer). من يشغّل الوسيط يرى حركتك." "Web traffic goes through a proxy: $($inet.ProxyServer). Whoever runs it can see your traffic." '' 0 }
    if ($inet.AutoConfigURL) { Add-F 2 'system' 'Proxy' "إعداد وسيط تلقائي مفعَّل: $($inet.AutoConfigURL)" "A proxy auto-config script is set: $($inet.AutoConfigURL)" '' 0 }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled) {
            $other = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Where-Object displayName -notlike '*Defender*')
            if ($other.Count) { Add-F 0 'system' 'Defender' "حماية Defender الفورية متوقفة لوجود مضاد آخر: $($other[0].displayName)" "Defender real-time protection is off because another antivirus is installed: $($other[0].displayName)" '' 0 }
            else { Add-F 3 'system' 'Defender' 'الحماية الفورية في Windows Defender متوقفة ولا يوجد مضاد فيروسات آخر.' 'Windows Defender real-time protection is off and no other antivirus is present.' '' 0 }
        }
    } catch { }
    try {
        $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
        if ($off.Count) { Add-F 2 'system' 'Firewall' "الجدار الناري متوقف في الوضع: $($off -join ', ')" "Windows Firewall is off for profile(s): $($off -join ', ')" '' 0 }
    } catch { }
    Step 100

    $pub = @($conns | Where-Object { $_.State -eq 'Established' -and $_.Scope -eq 'public' })
    [pscustomobject]@{
        Findings = @($F | Sort-Object @{ e = 'Sev'; Descending = $true }, Cat, Subject)
        Stats = [pscustomobject]@{
            Processes = $list.Count; Files = $byPath.Count; CoreUnverified = $unverified; Startup = $entries.Count
            PublicConns = $pub.Count; PublicProcs = @($pub | Select-Object -ExpandProperty Id -Unique).Count
            PublicNoWindow = @($pub | Where-Object { -not $_.Window } | Select-Object -ExpandProperty Id -Unique).Count
            Admin = $IsAdmin; When = Get-Date
        }
    }
}

function Get-SecurityReportText($Scan) {
    $s = $Scan.Stats
    $l = @("RamTrim security scan - $($s.When.ToString('yyyy-MM-dd HH:mm:ss'))   machine $env:COMPUTERNAME   administrator: $($s.Admin)",
        "Checked: $($s.Processes) processes, $($s.Files) executable files, $($s.Startup) startup entries.",
        "Internet: $($s.PublicConns) connections from $($s.PublicProcs) processes ($($s.PublicNoWindow) of them have no window).",
        "System processes whose file could not be verified without administrator rights: $($s.CoreUnverified).", '')
    $names = @{ 3 = 'HIGH'; 2 = 'REVIEW'; 1 = 'LOW'; 0 = 'INFO' }
    foreach ($f in $Scan.Findings) { $l += ('[{0,-6}] {1,-8} {2}' -f $names[$f.Sev], $f.Cat, $f.Subject); $l += ('         ' + $f.En); $l += '' }
    $l += '--- connections to public addresses'
    $l += Get-Connections | Where-Object { $_.State -eq 'Established' -and $_.Scope -eq 'public' } | Sort-Object Name | ForEach-Object { '{0,-26} {1,6}  {2,-46} {3}' -f $_.Name, $_.Id, $_.Remote, $_.Host }
    $l -join "`r`n"
}
