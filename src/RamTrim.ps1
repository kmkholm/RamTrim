# RamTrim 3.0 - memory trimmer plus a security monitor (connections, core processes, eavesdropping, startup).
# Developer: Dr. Mohammed Tawfik (Ajloun National University)
#   (no args)   bilingual GUI (Arabic / English)
#   -Cli        one trim, numbers printed to the console
#   -Scan       security scan, report printed to the console
#   -Snap DIR   self-test: walks every page in both languages and saves PNGs into DIR
param([switch]$Cli, [switch]$Scan, [string]$Snap)
$Version = '3.0'

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class RamTrimNative {
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EmptyWorkingSet(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)] struct TP { public int Count; public long Luid; public int Attr; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll, ref TP tp, int len, IntPtr prev, IntPtr ret);
    [DllImport("ntdll.dll")] static extern int NtSetSystemInformation(int cls, ref int info, int len);

    public static bool EnablePrivilege(string name) {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return false;
        TP tp; tp.Count = 1; tp.Attr = 2; tp.Luid = 0;
        if (!LookupPrivilegeValue(null, name, out tp.Luid)) { CloseHandle(tok); return false; }
        bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
        CloseHandle(tok);
        return ok;
    }
    // SystemMemoryListInformation (80): 3 = flush modified list, 4 = purge standby list
    public static int MemoryListCommand(int cmd) { return NtSetSystemInformation(80, ref cmd, 4); }
}
"@

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) { 'SeDebugPrivilege', 'SeProfileSingleProcessPrivilege', 'SeIncreaseQuotaPrivilege' | ForEach-Object { [void][RamTrimNative]::EnablePrivilege($_) } }

# ---------------------------------------------------------------- engine
function Get-Mem {
    $os = Get-CimInstance Win32_OperatingSystem
    $total = $os.TotalVisibleMemorySize / 1MB
    $avail = $os.FreePhysicalMemory / 1MB
    [pscustomobject]@{ Total = $total; Avail = $avail; Used = $total - $avail }
}

function Get-MemMap {
    $os = Get-CimInstance Win32_OperatingSystem
    $m = Get-CimInstance Win32_PerfRawData_PerfOS_Memory
    $gb = 1GB
    $total = $os.TotalVisibleMemorySize * 1KB / $gb
    $standby = ([double]$m.StandbyCacheNormalPriorityBytes + [double]$m.StandbyCacheReserveBytes + [double]$m.StandbyCacheCoreBytes) / $gb
    $free = [double]$m.FreeAndZeroPageListBytes / $gb
    $modified = [double]$m.ModifiedPageListBytes / $gb
    $mc = Get-Process -Name 'Memory Compression' -ErrorAction SilentlyContinue
    $pf = Get-CimInstance Win32_PageFileUsage | Measure-Object CurrentUsage, AllocatedBaseSize -Sum
    [pscustomobject]@{
        Total = $total; Standby = $standby; Free = $free; Modified = $modified
        Active = [math]::Max(0, $total - $standby - $free - $modified)
        Compressed = $(if ($mc) { $mc.WorkingSet64 / $gb } else { 0 })
        Kernel = ([double]$m.PoolPagedBytes + [double]$m.PoolNonpagedBytes) / $gb
        Commit = [double]$m.CommittedBytes / $gb; CommitLimit = [double]$m.CommitLimit / $gb
        PageUsed = ($pf | Where-Object Property -eq CurrentUsage).Sum / 1024
        PageSize = ($pf | Where-Object Property -eq AllocatedBaseSize).Sum / 1024
    }
}

function Get-Groups {
    $h = @{}
    foreach ($p in Get-Process) {
        if (-not $h.ContainsKey($p.ProcessName)) { $h[$p.ProcessName] = [pscustomobject]@{ Name = $p.ProcessName; Count = 0; WS = 0.0; Priv = 0.0 } }
        $g = $h[$p.ProcessName]; $g.Count++; $g.WS += $p.WorkingSet64 / 1GB; $g.Priv += $p.PrivateMemorySize64 / 1GB
    }
    $h
}

function Invoke-Trim([string]$Name) {
    # PROCESS_QUERY_INFORMATION (0x400) + PROCESS_SET_QUOTA (0x100)
    $ok = 0; $denied = 0
    $list = if ($Name) { Get-Process -Name $Name -ErrorAction SilentlyContinue } else { Get-Process }
    foreach ($p in $list) {
        if ($p.Id -le 4 -or $p.Id -eq $PID) { continue }
        $h = [RamTrimNative]::OpenProcess(0x500, $false, $p.Id)
        if ($h -eq [IntPtr]::Zero) { $denied++; continue }
        if ([RamTrimNative]::EmptyWorkingSet($h)) { $ok++ } else { $denied++ }
        [void][RamTrimNative]::CloseHandle($h)
    }
    [pscustomobject]@{ Trimmed = $ok; Denied = $denied }
}

function Invoke-TrimMeasured {
    $before = Get-Mem; $gBefore = Get-Groups
    $r = Invoke-Trim
    Start-Sleep -Seconds 3      # let trimmed pages reach the standby list
    $after = Get-Mem; $gAfter = Get-Groups
    $top = $gBefore.Values | Sort-Object WS -Descending | Select-Object -First 8 | ForEach-Object {
        $a = $gAfter[$_.Name]
        [pscustomobject]@{ Name = $_.Name; Before = $_.WS; After = $(if ($a) { $a.WS } else { 0 }) }
    }
    [pscustomobject]@{ Before = $before; After = $after; Freed = $before.Used - $after.Used
                       Trimmed = $r.Trimmed; Denied = $r.Denied; Top = $top }
}

function Get-ReportText {
    $m = Get-MemMap
    $l = @("RamTrim $Version report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", "Machine: $env:COMPUTERNAME   Administrator: $IsAdmin", '',
        ('Total RAM        {0,7:N1} GB' -f $m.Total), ('Active (in use)  {0,7:N1} GB' -f $m.Active), ('Modified         {0,7:N1} GB' -f $m.Modified),
        ('Standby cache    {0,7:N1} GB' -f $m.Standby), ('Free             {0,7:N1} GB' -f $m.Free), ('Compressed store {0,7:N1} GB' -f $m.Compressed),
        ('Kernel pools     {0,7:N1} GB' -f $m.Kernel), ('Commit           {0,7:N1} / {1:N1} GB' -f $m.Commit, $m.CommitLimit),
        ('Page file        {0,7:N1} / {1:N1} GB' -f $m.PageUsed, $m.PageSize), '', ('{0,-28} {1,5} {2,9} {3,9}' -f 'Process', 'Count', 'RAM GB', 'Priv GB'))
    $l += (Get-Groups).Values | Sort-Object WS -Descending | Select-Object -First 25 | ForEach-Object { '{0,-28} {1,5} {2,9:N2} {3,9:N2}' -f $_.Name, $_.Count, $_.WS, $_.Priv }
    $l -join "`r`n"
}

if ($Cli) {
    $x = Invoke-TrimMeasured
    "Used before : {0:N1} GB" -f $x.Before.Used
    "Used after  : {0:N1} GB" -f $x.After.Used
    "Freed       : {0:N1} GB" -f $x.Freed
    "Processes   : {0} trimmed, {1} protected/denied" -f $x.Trimmed, $x.Denied
    $x.Top | ForEach-Object { "  {0,-22} {1,6:N2} -> {2,6:N2} GB" -f $_.Name, $_.Before, $_.After }
    return
}

. (Join-Path $PSScriptRoot 'Security.ps1')
if ($Scan) { Get-SecurityReportText (Invoke-SecurityScan); return }

# ---------------------------------------------------------------- texts
$S = @{
ar = @{
    title = 'RamTrim  ·  الذاكرة والأمان'; lang_btn = 'English'
    nav_home = 'الرئيسية'; nav_proc = 'العمليات'; nav_map = 'الخريطة'; nav_tools = 'الأدوات'; nav_about = 'حول'
    used_now = 'المستخدم الآن   -   المتاح {0:N1} جيجا'
    trim_now = 'قلِّص الآن'; trimming = '... جارٍ التقليص'; auto = 'تقليص تلقائي كل'; minutes = 'دقيقة'
    col_name = 'البرنامج'; col_count = 'العمليات'; col_ws = 'الذاكرة (جيجا)'; col_priv = 'الخاصة (جيجا)'
    refresh = 'تحديث'; trim_sel = 'قلِّص المحدَّد'; end_sel = 'أنهِ المحدَّد'
    sel_first = 'اختر برنامجًا من الجدول أولًا'
    confirm_end = 'إنهاء «{0}» ({1} عملية)؟ ستفقد أي عمل غير محفوظ فيه.'
    protected = '«{0}» من عمليات النظام الأساسية ولا يمكن إنهاؤه من هنا.'
    trim_done = '{0}:   {1:N2}  ->  {2:N2} GB'
    col_item = 'البند'; col_val = 'الحجم'; col_mean = 'معناه'
    m_active = 'مستخدم فعليًا'; m_active_d = 'صفحات تعمل عليها البرامج والنظام الآن'
    m_modified = 'معدَّل ينتظر الكتابة'; m_modified_d = 'صفحات سُحبت من البرامج وتنتظر النسخ إلى ملف الصفحة'
    m_standby = 'كاش احتياطي'; m_standby_d = 'نسخ ملفات وصفحات قديمة، تُفرَّغ فورًا عند الطلب'
    m_free = 'فارغ'; m_free_d = 'غير مستخدم إطلاقًا'
    m_comp = 'مخزن الضغط'; m_comp_d = 'صفحات مضغوطة داخل الرام بدل كتابتها على القرص'
    m_kernel = 'ذاكرة النواة'; m_kernel_d = 'تعريفات الأجهزة وهياكل النظام'
    m_commit = 'الالتزام'; m_commit_d = 'ما وُعدت به البرامج من ذاكرة مقابل الحد الأقصى'
    m_page = 'ملف الصفحة'; m_page_d = 'المستخدم من ملف الصفحة على القرص'
    t_admin = 'أعد التشغيل كمسؤول'; t_admin_d = 'يصل إلى العمليات المحمية ويفعّل تفريغ الكاش'
    t_flush = 'فرِّغ الكاش الاحتياطي'; t_flush_d = 'يمسح قائمة Standby كاملة (يحتاج صلاحيات مسؤول)'
    t_deep = 'تنظيف عميق'; t_deep_d = 'تقليص كل البرامج ثم تفريغ الكاش (يحتاج صلاحيات مسؤول)'
    t_report = 'احفظ تقريرًا'; t_report_d = 'ملف نصي على سطح المكتب بخريطة الذاكرة وأكبر 25 برنامجًا'
    t_taskmgr = 'مدير المهام'; t_taskmgr_d = 'يفتح Task Manager'
    t_resmon = 'مراقب الموارد'; t_resmon_d = 'يفتح Resource Monitor على تبويب الذاكرة'
    need_admin = 'هذه الأداة تحتاج صلاحيات مسؤول. اضغط «أعد التشغيل كمسؤول» أولًا.'
    flush_done = 'تم التفريغ. المتاح الآن {0:N1} جيجا (كان {1:N1}).'
    flush_fail = 'رفض النظام الطلب (الرمز 0x{0:X8}).'
    report_saved = 'حُفظ التقرير في:'
    st_admin = 'الوضع: مسؤول'; st_user = 'الوضع: مستخدم عادي'; st_dev = 'المطوّر: د. محمد توفيق'
    nav_net = 'الاتصالات'; nav_sec = 'الأمان'
    n_proc = 'البرنامج'; n_pid = 'PID'; n_state = 'الحالة'; n_remote = 'العنوان'; n_host = 'اسم الموقع'; n_scope = 'النطاق'; n_sig = 'التوقيع'
    n_pubonly = 'الإنترنت فقط'; n_summary = '{0} اتصال بالإنترنت من {1} برنامج، {2} منها يعمل بلا نافذة'
    sc_public = 'إنترنت'; sc_lan = 'شبكة محلية'; sc_loop = 'الجهاز نفسه'; sc_any = 'كل الواجهات'; sc_multi = 'بث'; sc_none = ''
    st_Established = 'متصل'; st_Listen = 'يستمع'; st_Bound = 'مفتوح'
    sig_Valid = 'موقَّع'; sig_NotSigned = 'غير موقَّع'; sig_pkg = 'حزمة المتجر'; sig_NoPath = 'محمي'; sig_other = 'غير مؤكد'
    open_loc = 'مكان الملف'; end_proc = 'أنهِ العملية'; no_path = 'لا يوجد مسار ملف لهذا العنصر'; no_pid = 'هذا العنصر ليس عملية تعمل الآن'
    s_scan = 'افحص الآن'; s_scanning = '... جارٍ الفحص'; s_save = 'احفظ التقرير'
    s_sev = 'الخطورة'; s_cat = 'النوع'; s_subj = 'العنصر'; s_find = 'ما وُجد'
    sev3 = 'خطر'; sev2 = 'راجِع'; sev1 = 'منخفض'; sev0 = 'للعلم'
    cat_proc = 'عملية'; cat_net = 'شبكة'; cat_privacy = 'خصوصية'; cat_startup = 'إقلاع'; cat_system = 'نظام'
    s_hint = 'اضغط «افحص الآن». الفحص يأخذ نحو 20 ثانية ولا يرسل أي شيء خارج الجهاز.'
    s_summary = 'خطر: {0}     راجِع: {1}     منخفض: {2}     للعلم: {3}'
    s_checked = 'فُحصت {0} عملية و{1} مدخل إقلاع. {2} عملية نظام لم يمكن التحقق من ملفها بلا صلاحيات مسؤول.'
    a_ver = 'الإصدار {0}'
    a_what = 'ويندوز لا يسحب الذاكرة من البرامج إلا إذا ضاقت، فتتمدد البرامج بقدر الرام الموجودة. RamTrim يطلب من كل برنامج أن يتخلى فورًا عن الصفحات التي لا يستعملها الآن، فتنتقل إلى الكاش الاحتياطي وتصبح متاحة لأي برنامج آخر. ما يحتاجه البرنامج فعلًا يعود إليه عند أول استعمال. تبويبا الاتصالات والأمان يعرضان من يتصل بالإنترنت ويفحصان عمليات النظام والميكروفون والكاميرا وما يبدأ مع ويندوز.'
    a_dev = 'المطوّر'; a_name = 'د. محمد توفيق'; a_aff = 'قسم الأمن السيبراني، كلية تكنولوجيا المعلومات، جامعة عجلون الوطنية'
}
en = @{
    title = 'RamTrim  ·  Memory & Security'; lang_btn = 'العربية'
    nav_home = 'Home'; nav_proc = 'Processes'; nav_map = 'Memory'; nav_tools = 'Tools'; nav_about = 'About'
    used_now = 'In use now   -   {0:N1} GB available'
    trim_now = 'Trim now'; trimming = 'Trimming ...'; auto = 'Auto-trim every'; minutes = 'minutes'
    col_name = 'Program'; col_count = 'Processes'; col_ws = 'RAM (GB)'; col_priv = 'Private (GB)'
    refresh = 'Refresh'; trim_sel = 'Trim selected'; end_sel = 'End selected'
    sel_first = 'Select a program in the table first.'
    confirm_end = 'End "{0}" ({1} processes)? Any unsaved work in it will be lost.'
    protected = '"{0}" is a core system process and cannot be ended from here.'
    trim_done = '{0}:   {1:N2}  ->  {2:N2} GB'
    col_item = 'Item'; col_val = 'Size'; col_mean = 'Meaning'
    m_active = 'Active (in use)'; m_active_d = 'Pages programs and the system are working on now'
    m_modified = 'Modified'; m_modified_d = 'Pages taken from programs, waiting to be copied to the page file'
    m_standby = 'Standby cache'; m_standby_d = 'File copies and old pages, released instantly on demand'
    m_free = 'Free'; m_free_d = 'Not used at all'
    m_comp = 'Compression store'; m_comp_d = 'Pages compressed inside RAM instead of written to disk'
    m_kernel = 'Kernel memory'; m_kernel_d = 'Drivers and system structures'
    m_commit = 'Commit'; m_commit_d = 'Memory promised to programs versus the limit'
    m_page = 'Page file'; m_page_d = 'Page file space in use on disk'
    t_admin = 'Restart as administrator'; t_admin_d = 'Reaches protected processes and enables cache flushing'
    t_flush = 'Flush standby cache'; t_flush_d = 'Clears the whole Standby list (needs administrator)'
    t_deep = 'Deep clean'; t_deep_d = 'Trim every program, then flush the cache (needs administrator)'
    t_report = 'Save a report'; t_report_d = 'Text file on the Desktop: memory map and top 25 programs'
    t_taskmgr = 'Task Manager'; t_taskmgr_d = 'Opens Task Manager'
    t_resmon = 'Resource Monitor'; t_resmon_d = 'Opens Resource Monitor on the Memory tab'
    need_admin = 'This tool needs administrator rights. Press "Restart as administrator" first.'
    flush_done = 'Flushed. {0:N1} GB available now (was {1:N1}).'
    flush_fail = 'The system refused the request (code 0x{0:X8}).'
    report_saved = 'Report saved to:'
    st_admin = 'Mode: administrator'; st_user = 'Mode: standard user'; st_dev = 'Developer: Dr. Mohammed Tawfik'
    nav_net = 'Network'; nav_sec = 'Security'
    n_proc = 'Program'; n_pid = 'PID'; n_state = 'State'; n_remote = 'Address'; n_host = 'Host name'; n_scope = 'Scope'; n_sig = 'Signature'
    n_pubonly = 'Internet only'; n_summary = '{0} internet connections from {1} programs, {2} of them running without a window'
    sc_public = 'Internet'; sc_lan = 'Local network'; sc_loop = 'This PC'; sc_any = 'All interfaces'; sc_multi = 'Broadcast'; sc_none = ''
    st_Established = 'connected'; st_Listen = 'listening'; st_Bound = 'open'
    sig_Valid = 'Signed'; sig_NotSigned = 'Unsigned'; sig_pkg = 'Store package'; sig_NoPath = 'Protected'; sig_other = 'Unverified'
    open_loc = 'File location'; end_proc = 'End process'; no_path = 'This item has no file path'; no_pid = 'This item is not a running process'
    s_scan = 'Scan now'; s_scanning = 'Scanning ...'; s_save = 'Save report'
    s_sev = 'Severity'; s_cat = 'Type'; s_subj = 'Item'; s_find = 'Finding'
    sev3 = 'HIGH'; sev2 = 'REVIEW'; sev1 = 'LOW'; sev0 = 'INFO'
    cat_proc = 'Process'; cat_net = 'Network'; cat_privacy = 'Privacy'; cat_startup = 'Startup'; cat_system = 'System'
    s_hint = 'Press "Scan now". The scan takes about 20 seconds and sends nothing off this PC.'
    s_summary = 'HIGH: {0}     REVIEW: {1}     LOW: {2}     INFO: {3}'
    s_checked = '{0} processes and {1} startup entries checked. {2} system processes could not be file-verified without administrator rights.'
    a_ver = 'Version {0}'
    a_what = 'Windows takes memory back from programs only when it runs short, so programs grow to fit whatever RAM exists. RamTrim asks every program to give up, right now, the pages it is not using. They move to the standby cache and become available to any other program. Whatever a program really needs comes back on first use. The Network and Security pages show who talks to the internet and check system processes, microphone, camera and startup items.'
    a_dev = 'Developer'; a_name = 'Dr. Mohammed Tawfik'; a_aff = 'Department of Cyber Security, Faculty of Information Technology, Ajloun National University'
}
}
$LangFile = Join-Path $env:LOCALAPPDATA 'RamTrim\lang.txt'
$script:Lang = 'ar'
if (Test-Path $LangFile) { $v = (Get-Content $LangFile -TotalCount 1).Trim(); if ($S.ContainsKey($v)) { $script:Lang = $v } }
function T([string]$k) { $S[$script:Lang][$k] }

# ---------------------------------------------------------------- UI
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$cBg = [Drawing.Color]::FromArgb(18, 18, 18); $cPanel = [Drawing.Color]::FromArgb(30, 30, 30)
$cAcc = [Drawing.Color]::FromArgb(255, 214, 10); $cText = [Drawing.Color]::White; $cDim = [Drawing.Color]::FromArgb(170, 170, 170)
$cSeg = @{ active = $cAcc; modified = [Drawing.Color]::FromArgb(255, 122, 0); standby = [Drawing.Color]::FromArgb(0, 150, 255); free = [Drawing.Color]::FromArgb(70, 70, 70) }
function Font($size, [switch]$Bold) { New-Object Drawing.Font('Segoe UI', $size, $(if ($Bold) { [Drawing.FontStyle]::Bold } else { [Drawing.FontStyle]::Regular })) }

function New-Button([int]$w, [int]$h, [switch]$Accent) {
    $b = New-Object Windows.Forms.Button
    $b.Size = New-Object Drawing.Size($w, $h); $b.FlatStyle = 'Flat'; $b.Margin = '4,4,4,4'
    $b.FlatAppearance.BorderColor = $cAcc; $b.FlatAppearance.BorderSize = 1
    if ($Accent) { $b.BackColor = $cAcc; $b.ForeColor = [Drawing.Color]::Black; $b.Font = Font 11 -Bold }
    else { $b.BackColor = $cPanel; $b.ForeColor = $cText }
    $b
}
function New-Grid {
    $g = New-Object Windows.Forms.DataGridView
    $g.Dock = 'Fill'; $g.ReadOnly = $true; $g.AllowUserToAddRows = $false; $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false; $g.SelectionMode = 'FullRowSelect'; $g.MultiSelect = $false
    $g.AutoSizeColumnsMode = 'Fill'; $g.BorderStyle = 'None'; $g.BackgroundColor = $cBg; $g.GridColor = [Drawing.Color]::FromArgb(55, 55, 55)
    $g.EnableHeadersVisualStyles = $false; $g.ColumnHeadersHeight = 34; $g.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $g.ColumnHeadersDefaultCellStyle.BackColor = $cAcc; $g.ColumnHeadersDefaultCellStyle.ForeColor = [Drawing.Color]::Black
    $g.ColumnHeadersDefaultCellStyle.Font = Font 10 -Bold
    $g.DefaultCellStyle.BackColor = $cPanel; $g.DefaultCellStyle.ForeColor = $cText
    $g.DefaultCellStyle.SelectionBackColor = [Drawing.Color]::FromArgb(80, 68, 0); $g.DefaultCellStyle.SelectionForeColor = $cText
    $g.RowTemplate.Height = 28
    $g
}
function Show-Msg([string]$text, [string]$buttons = 'OK', [string]$icon = 'Information') {
    $opt = if ($script:Lang -eq 'ar') { [Windows.Forms.MessageBoxOptions]'RtlReading, RightAlign' } else { [Windows.Forms.MessageBoxOptions]0 }
    [Windows.Forms.MessageBox]::Show($form, $text, 'RamTrim', $buttons, $icon, 'Button1', $opt)
}

$form = New-Object Windows.Forms.Form
$form.ClientSize = New-Object Drawing.Size(780, 620); $form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'; $form.MaximizeBox = $false
$form.BackColor = $cBg; $form.ForeColor = $cText; $form.Font = Font 10.5
$icoPath = if ($RamTrimExe) { $RamTrimExe } else { Join-Path (Split-Path $PSScriptRoot -Parent) 'assets\RamTrim.ico' }
try { if (Test-Path $icoPath) { $form.Icon = $(if ($RamTrimExe) { [Drawing.Icon]::ExtractAssociatedIcon($icoPath) } else { New-Object Drawing.Icon($icoPath) }) } } catch { }

# header: title + language switch
$top = New-Object Windows.Forms.Panel; $top.Dock = 'Top'; $top.Height = 54; $top.BackColor = $cAcc
$lblTitle = New-Object Windows.Forms.Label; $lblTitle.Dock = 'Fill'; $lblTitle.Font = Font 16 -Bold
$lblTitle.ForeColor = [Drawing.Color]::Black; $lblTitle.TextAlign = 'MiddleLeft'; $lblTitle.Padding = '14,0,14,0'; $lblTitle.UseMnemonic = $false
$btnLang = New-Object Windows.Forms.Button; $btnLang.Width = 110; $btnLang.FlatStyle = 'Flat'
$btnLang.BackColor = [Drawing.Color]::Black; $btnLang.ForeColor = $cAcc; $btnLang.Font = Font 10.5 -Bold
$top.Controls.AddRange(@($lblTitle, $btnLang))

# navigation
$nav = New-Object Windows.Forms.FlowLayoutPanel; $nav.Dock = 'Top'; $nav.Height = 48; $nav.Padding = '10,4,10,0'; $nav.WrapContents = $false
$pageKeys = 'home', 'proc', 'map', 'net', 'sec', 'tools', 'about'
$navBtn = @{}; $page = @{}
foreach ($k in $pageKeys) {
    $b = New-Button 102 36; $b.Tag = $k; $b.Font = Font 9.5 -Bold; $b.Margin = '3,3,3,3'
    $b.Add_Click({ Show-Page $this.Tag })
    $navBtn[$k] = $b; $nav.Controls.Add($b)
    $p = New-Object Windows.Forms.Panel; $p.Dock = 'Fill'; $p.Padding = '16,10,16,12'; $p.Visible = $false
    $page[$k] = $p
}

$status = New-Object Windows.Forms.Label; $status.Dock = 'Bottom'; $status.Height = 26
$status.BackColor = $cPanel; $status.ForeColor = $cDim; $status.TextAlign = 'MiddleLeft'; $status.Padding = '10,0,10,0'; $status.Font = Font 9

$content = New-Object Windows.Forms.Panel; $content.Dock = 'Fill'
foreach ($k in $pageKeys) { $content.Controls.Add($page[$k]) }
$form.Controls.AddRange(@($content, $status, $nav, $top))

# ---- page: home
$tlHome = New-Object Windows.Forms.TableLayoutPanel; $tlHome.Dock = 'Fill'; $tlHome.ColumnCount = 1
[void]$tlHome.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
foreach ($h in 76, 30, 26, 70, 44) { [void]$tlHome.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, $h))) }
[void]$tlHome.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))

$lblUsed = New-Object Windows.Forms.Label; $lblUsed.Dock = 'Fill'; $lblUsed.TextAlign = 'MiddleCenter'
$lblUsed.Font = Font 30 -Bold; $lblUsed.ForeColor = $cAcc; $lblUsed.RightToLeft = 'No'
$lblSub = New-Object Windows.Forms.Label; $lblSub.Dock = 'Fill'; $lblSub.TextAlign = 'MiddleCenter'; $lblSub.ForeColor = $cDim
$barHome = New-Object Windows.Forms.Panel; $barHome.Dock = 'Fill'; $barHome.Margin = '3,4,3,4'; $barHome.BackColor = $cPanel
$barFill = New-Object Windows.Forms.Panel; $barFill.Dock = 'Left'; $barFill.BackColor = $cAcc; $barFill.Width = 0
$barHome.Controls.Add($barFill)
$btnTrim = New-Button 100 60 -Accent; $btnTrim.Dock = 'Fill'; $btnTrim.Font = Font 18 -Bold
$flAuto = New-Object Windows.Forms.FlowLayoutPanel; $flAuto.Dock = 'Fill'; $flAuto.WrapContents = $false; $flAuto.Padding = '0,6,0,0'
$chkAuto = New-Object Windows.Forms.CheckBox; $chkAuto.AutoSize = $true; $chkAuto.Margin = '3,4,3,3'
$numAuto = New-Object Windows.Forms.NumericUpDown; $numAuto.Width = 64; $numAuto.Minimum = 1; $numAuto.Maximum = 240; $numAuto.Value = 10
$numAuto.BackColor = $cPanel; $numAuto.ForeColor = $cText; $numAuto.RightToLeft = 'No'
$lblMin = New-Object Windows.Forms.Label; $lblMin.AutoSize = $true; $lblMin.Margin = '3,6,3,3'
$flAuto.Controls.AddRange(@($chkAuto, $numAuto, $lblMin))
$boxLog = New-Object Windows.Forms.TextBox; $boxLog.Dock = 'Fill'; $boxLog.Multiline = $true; $boxLog.ReadOnly = $true
$boxLog.ScrollBars = 'Vertical'; $boxLog.RightToLeft = 'No'; $boxLog.BorderStyle = 'FixedSingle'
$boxLog.BackColor = $cPanel; $boxLog.ForeColor = [Drawing.Color]::Gainsboro; $boxLog.Font = New-Object Drawing.Font('Consolas', 10)
$r = 0; foreach ($c in $lblUsed, $lblSub, $barHome, $btnTrim, $flAuto, $boxLog) { $tlHome.Controls.Add($c, 0, $r); $r++ }
$page.home.Controls.Add($tlHome)

# ---- page: processes
$gridProc = New-Grid
'name', 'count', 'ws', 'priv' | ForEach-Object { [void]$gridProc.Columns.Add($_, '') }
$gridProc.Columns['name'].FillWeight = 220
'count', 'ws', 'priv' | ForEach-Object { $gridProc.Columns[$_].DefaultCellStyle.Alignment = 'MiddleCenter'; $gridProc.Columns[$_].DefaultCellStyle.Format = 'N2' }
$gridProc.Columns['count'].DefaultCellStyle.Format = 'N0'
$flProc = New-Object Windows.Forms.FlowLayoutPanel; $flProc.Dock = 'Bottom'; $flProc.Height = 52; $flProc.Padding = '0,6,0,0'
$btnRefresh = New-Button 150 38; $btnTrimSel = New-Button 170 38 -Accent; $btnEndSel = New-Button 170 38
$btnEndSel.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(255, 80, 80); $btnEndSel.ForeColor = [Drawing.Color]::FromArgb(255, 120, 120)
$flProc.Controls.AddRange(@($btnTrimSel, $btnRefresh, $btnEndSel))
$lblProcMsg = New-Object Windows.Forms.Label; $lblProcMsg.Dock = 'Bottom'; $lblProcMsg.Height = 26; $lblProcMsg.ForeColor = $cAcc; $lblProcMsg.TextAlign = 'MiddleLeft'; $lblProcMsg.RightToLeft = 'No'
$page.proc.Controls.AddRange(@($gridProc, $lblProcMsg, $flProc))

# ---- page: memory map
$barMap = New-Object Windows.Forms.Panel; $barMap.Dock = 'Top'; $barMap.Height = 46; $barMap.BackColor = $cPanel
$script:Map = $null
$barMap.Add_Paint({
    param($s, $e)
    $m = $script:Map; if (-not $m) { return }
    $w = $s.ClientSize.Width; $x = 0.0
    foreach ($seg in @(@('active', $m.Active), @('modified', $m.Modified), @('standby', $m.Standby), @('free', $m.Free))) {
        $sw = $w * $seg[1] / $m.Total
        $br = New-Object Drawing.SolidBrush($cSeg[$seg[0]])
        $e.Graphics.FillRectangle($br, [single]$x, 0, [single]$sw, $s.ClientSize.Height); $br.Dispose()
        $x += $sw
    }
})
$gridMap = New-Grid
'item', 'val', 'mean' | ForEach-Object { [void]$gridMap.Columns.Add($_, '') }
$gridMap.Columns['item'].FillWeight = 90; $gridMap.Columns['val'].FillWeight = 70; $gridMap.Columns['mean'].FillWeight = 240
$gridMap.Columns['val'].DefaultCellStyle.Alignment = 'MiddleCenter'
$gridMap.DefaultCellStyle.SelectionBackColor = $cPanel
$spMap = New-Object Windows.Forms.Panel; $spMap.Dock = 'Top'; $spMap.Height = 10
$flMap = New-Object Windows.Forms.FlowLayoutPanel; $flMap.Dock = 'Bottom'; $flMap.Height = 52; $flMap.Padding = '0,6,0,0'
$btnMapRefresh = New-Button 150 38; $flMap.Controls.Add($btnMapRefresh)
$page.map.Controls.AddRange(@($gridMap, $spMap, $barMap, $flMap))

# ---- page: network
$gridNet = New-Grid; $gridNet.DefaultCellStyle.Font = Font 9
'proc', 'pid', 'state', 'remote', 'host', 'scope', 'sig' | ForEach-Object { [void]$gridNet.Columns.Add($_, '') }
$w = @{ proc = 110; pid = 44; state = 74; remote = 250; host = 130; scope = 66; sig = 66 }
foreach ($k in $w.Keys) { $gridNet.Columns[$k].FillWeight = $w[$k] }
foreach ($k in 'proc', 'remote', 'host') { $gridNet.Columns[$k].DefaultCellStyle.Alignment = 'MiddleLeft' }
$flNet = New-Object Windows.Forms.FlowLayoutPanel; $flNet.Dock = 'Bottom'; $flNet.Height = 52; $flNet.Padding = '0,6,0,0'
$btnNetRefresh = New-Button 120 38 -Accent; $btnNetLoc = New-Button 140 38; $btnNetEnd = New-Button 140 38
$btnNetEnd.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(255, 80, 80); $btnNetEnd.ForeColor = [Drawing.Color]::FromArgb(255, 120, 120)
$chkPub = New-Object Windows.Forms.CheckBox; $chkPub.AutoSize = $true; $chkPub.Checked = $true; $chkPub.Margin = '12,12,12,3'
$flNet.Controls.AddRange(@($btnNetRefresh, $btnNetLoc, $btnNetEnd, $chkPub))
$lblNetMsg = New-Object Windows.Forms.Label; $lblNetMsg.Dock = 'Bottom'; $lblNetMsg.Height = 26; $lblNetMsg.ForeColor = $cAcc; $lblNetMsg.TextAlign = 'MiddleLeft'
$page.net.Controls.AddRange(@($gridNet, $lblNetMsg, $flNet))

# ---- page: security
$gridSec = New-Grid; $gridSec.DefaultCellStyle.Font = Font 9.5
'sev', 'cat', 'subj', 'find' | ForEach-Object { [void]$gridSec.Columns.Add($_, '') }
$w = @{ sev = 62; cat = 62; subj = 170; find = 430 }
foreach ($k in $w.Keys) { $gridSec.Columns[$k].FillWeight = $w[$k] }
$gridSec.Columns['sev'].DefaultCellStyle.Alignment = 'MiddleCenter'; $gridSec.Columns['cat'].DefaultCellStyle.Alignment = 'MiddleCenter'
$gridSec.Columns['find'].DefaultCellStyle.WrapMode = 'True'; $gridSec.Columns['subj'].DefaultCellStyle.WrapMode = 'True'
$gridSec.AutoSizeRowsMode = 'AllCells'
$flSec = New-Object Windows.Forms.FlowLayoutPanel; $flSec.Dock = 'Top'; $flSec.Height = 50
$btnScan = New-Button 170 38 -Accent; $btnSecSave = New-Button 140 38; $btnSecLoc = New-Button 140 38; $btnSecEnd = New-Button 140 38
$btnSecEnd.FlatAppearance.BorderColor = [Drawing.Color]::FromArgb(255, 80, 80); $btnSecEnd.ForeColor = [Drawing.Color]::FromArgb(255, 120, 120)
$flSec.Controls.AddRange(@($btnScan, $btnSecSave, $btnSecLoc, $btnSecEnd))
$pbSec = New-Object Windows.Forms.ProgressBar; $pbSec.Dock = 'Top'; $pbSec.Height = 8
$lblSec = New-Object Windows.Forms.Label; $lblSec.Dock = 'Top'; $lblSec.Height = 66; $lblSec.ForeColor = $cAcc; $lblSec.TextAlign = 'MiddleLeft'
$page.sec.Controls.AddRange(@($gridSec, $lblSec, $pbSec, $flSec))
$script:ScanResult = $null

# ---- page: tools
$tlTools = New-Object Windows.Forms.TableLayoutPanel; $tlTools.Dock = 'Top'; $tlTools.ColumnCount = 2; $tlTools.Height = 6 * 62
[void]$tlTools.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 250)))
[void]$tlTools.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
$toolKeys = 'admin', 'flush', 'deep', 'report', 'taskmgr', 'resmon'
$toolBtn = @{}; $toolLbl = @{}; $r = 0
foreach ($k in $toolKeys) {
    [void]$tlTools.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 62)))
    $b = New-Button 236 46 -Accent:($k -in 'deep', 'flush'); $b.Tag = $k; $b.Dock = 'Fill'; $b.Margin = '4,7,4,7'
    $b.Add_Click({ Invoke-Tool $this.Tag })
    $l = New-Object Windows.Forms.Label; $l.Dock = 'Fill'; $l.TextAlign = 'MiddleLeft'; $l.ForeColor = $cDim; $l.Padding = '8,0,8,0'
    $toolBtn[$k] = $b; $toolLbl[$k] = $l
    $tlTools.Controls.Add($b, 0, $r); $tlTools.Controls.Add($l, 1, $r); $r++
}
$lblToolMsg = New-Object Windows.Forms.Label; $lblToolMsg.Dock = 'Bottom'; $lblToolMsg.Height = 60; $lblToolMsg.ForeColor = $cAcc; $lblToolMsg.TextAlign = 'MiddleLeft'
$page.tools.Controls.AddRange(@($tlTools, $lblToolMsg))

# ---- page: about
$tlAbout = New-Object Windows.Forms.TableLayoutPanel; $tlAbout.Dock = 'Fill'; $tlAbout.ColumnCount = 1
[void]$tlAbout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
foreach ($h in 62, 30, 150, 34, 44, 30, 30, 30) { [void]$tlAbout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, $h))) }
function New-AboutLabel($size, $color, [switch]$Bold, [switch]$Ltr) {
    $l = New-Object Windows.Forms.Label; $l.Dock = 'Fill'; $l.TextAlign = 'MiddleLeft'; $l.ForeColor = $color; $l.Font = Font $size -Bold:$Bold
    if ($Ltr) { $l.RightToLeft = 'No' }
    $l
}
$abName = New-AboutLabel 26 $cAcc -Bold; $abName.Text = 'RamTrim'
$abVer = New-AboutLabel 10.5 $cDim
$abWhat = New-AboutLabel 11 $cText; $abWhat.TextAlign = 'TopLeft'; $abWhat.Padding = '0,8,0,0'
$abDevH = New-AboutLabel 10.5 $cDim
$abDev = New-AboutLabel 18 $cAcc -Bold
$abAff = New-AboutLabel 10.5 $cText
$abMail = New-AboutLabel 10.5 $cText; $abMail.Text = 'kmkhol01@gmail.com'
$abOrcid = New-AboutLabel 10.5 $cText; $abOrcid.Text = 'ORCID  0000-0002-1227-387X'
$r = 0; foreach ($c in $abName, $abVer, $abWhat, $abDevH, $abDev, $abAff, $abMail, $abOrcid) { $tlAbout.Controls.Add($c, 0, $r); $r++ }
$page.about.Controls.Add($tlAbout)

# ---------------------------------------------------------------- behaviour
function Update-Gauge {
    $m = Get-Mem
    $lblUsed.Text = ('{0:N1} / {1:N0} GB' -f $m.Used, $m.Total)
    $lblSub.Text = ((T 'used_now') -f $m.Avail)
    $barFill.Width = [int]($barHome.ClientSize.Width * $m.Used / $m.Total)
}

function Update-Proc {
    $gridProc.Rows.Clear()
    (Get-Groups).Values | Sort-Object WS -Descending | Select-Object -First 60 | ForEach-Object {
        [void]$gridProc.Rows.Add($_.Name, $_.Count, $_.WS, $_.Priv)
    }
}

function Update-Map {
    $m = Get-MemMap; $script:Map = $m
    $gridMap.Rows.Clear()
    $gb = if ($script:Lang -eq 'ar') { 'جيجا' } else { 'GB' }
    $rows = @(
        @('active', ('{0:N1} {1}' -f $m.Active, $gb), 'active'), @('modified', ('{0:N1} {1}' -f $m.Modified, $gb), 'modified'),
        @('standby', ('{0:N1} {1}' -f $m.Standby, $gb), 'standby'), @('free', ('{0:N1} {1}' -f $m.Free, $gb), 'free'),
        @('comp', ('{0:N1} {1}' -f $m.Compressed, $gb), $null), @('kernel', ('{0:N1} {1}' -f $m.Kernel, $gb), $null),
        @('commit', ('{0:N1} / {1:N1} {2}' -f $m.Commit, $m.CommitLimit, $gb), $null), @('page', ('{0:N1} / {1:N1} {2}' -f $m.PageUsed, $m.PageSize, $gb), $null)
    )
    foreach ($row in $rows) {
        $i = $gridMap.Rows.Add((T "m_$($row[0])"), $row[1], (T "m_$($row[0])_d"))
        if ($row[2]) {
            $cell = $gridMap.Rows[$i].Cells[0]; $cell.Style.BackColor = $cSeg[$row[2]]; $cell.Style.SelectionBackColor = $cSeg[$row[2]]
            $fg = if ($row[2] -in 'active', 'modified') { [Drawing.Color]::Black } else { $cText }
            $cell.Style.ForeColor = $fg; $cell.Style.SelectionForeColor = $fg
        }
    }
    $gridMap.ClearSelection(); $barMap.Invalidate()
}

function Start-TrimUi {
    $btnTrim.Enabled = $false; $btnTrim.Text = (T 'trimming'); $form.Refresh()
    $x = Invoke-TrimMeasured
    $lines = @(
        ('{0:HH:mm:ss}   {1:N1} GB  ->  {2:N1} GB    (freed {3:N1} GB)' -f (Get-Date), $x.Before.Used, $x.After.Used, $x.Freed),
        ('processes: {0} trimmed, {1} protected' -f $x.Trimmed, $x.Denied), ''
    )
    $lines += $x.Top | ForEach-Object { '{0,-22} {1,6:N2} -> {2,6:N2} GB' -f $_.Name, $_.Before, $_.After }
    $boxLog.Text = ($lines -join "`r`n") + "`r`n`r`n" + $boxLog.Text
    $btnTrim.Text = (T 'trim_now'); $btnTrim.Enabled = $true
    Update-Gauge
}

function Get-SelectedName {
    if ($gridProc.SelectedRows.Count -eq 0) { $lblProcMsg.Text = (T 'sel_first'); return $null }
    [string]$gridProc.SelectedRows[0].Cells[0].Value
}
function Invoke-TrimSelected {
    $n = Get-SelectedName; if (-not $n) { return }
    $before = (Get-Process -Name $n -ErrorAction SilentlyContinue | Measure-Object WorkingSet64 -Sum).Sum / 1GB
    [void](Invoke-Trim $n); Start-Sleep -Milliseconds 800
    $after = (Get-Process -Name $n -ErrorAction SilentlyContinue | Measure-Object WorkingSet64 -Sum).Sum / 1GB
    Update-Proc; $lblProcMsg.Text = ((T 'trim_done') -f $n, $before, $after)
}
$CoreProcs = 'System', 'Idle', 'Registry', 'Memory Compression', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'dwm', 'fontdrvhost', 'Secure System', 'MsMpEng'
function Invoke-EndSelected {
    $n = Get-SelectedName; if (-not $n) { return }
    if ($CoreProcs -contains $n) { [void](Show-Msg ((T 'protected') -f $n) 'OK' 'Warning'); return }
    $count = @(Get-Process -Name $n -ErrorAction SilentlyContinue).Count
    if ((Show-Msg ((T 'confirm_end') -f $n, $count) 'YesNo' 'Warning') -ne 'Yes') { return }
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600; Update-Proc; $lblProcMsg.Text = ''
}

function Invoke-Flush {
    $before = (Get-Mem).Avail
    [void][RamTrimNative]::MemoryListCommand(3)
    $rc = [RamTrimNative]::MemoryListCommand(4)
    if ($rc -ne 0) { return ((T 'flush_fail') -f $rc) }
    Start-Sleep -Milliseconds 500
    ((T 'flush_done') -f (Get-Mem).Avail, $before)
}
function Invoke-Tool([string]$k) {
    $lblToolMsg.Text = ''
    switch ($k) {
        'admin' {
            if ($IsAdmin) { $lblToolMsg.Text = (T 'st_admin'); return }
            try {
                if ($RamTrimExe) { Start-Process $RamTrimExe -Verb RunAs }
                else { Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" }
                $form.Close()
            } catch { }      # user declined the elevation prompt
        }
        'flush' { if (-not $IsAdmin) { $lblToolMsg.Text = (T 'need_admin') } else { $form.Cursor = 'WaitCursor'; $lblToolMsg.Text = Invoke-Flush; $form.Cursor = 'Default' } }
        'deep' {
            if (-not $IsAdmin) { $lblToolMsg.Text = (T 'need_admin'); return }
            $form.Cursor = 'WaitCursor'; [void](Invoke-Trim); Start-Sleep -Seconds 3; $lblToolMsg.Text = Invoke-Flush; $form.Cursor = 'Default'
        }
        'report' {
            $path = Join-Path ([Environment]::GetFolderPath('Desktop')) ("RamTrim_report_{0:yyyyMMdd_HHmm}.txt" -f (Get-Date))
            [IO.File]::WriteAllText($path, (Get-ReportText), (New-Object Text.UTF8Encoding($true)))
            $lblToolMsg.Text = (T 'report_saved') + "`r`n" + $path
        }
        'taskmgr' { Start-Process taskmgr }
        'resmon' { Start-Process resmon }
    }
    Update-Gauge
}

function Ltr([string]$t) { if ($t) { [char]0x202A + $t + [char]0x202C } else { '' } }
function Update-Net {
    $form.Cursor = 'WaitCursor'
    $procs = Get-ProcTable; $all = @(Get-Connections $procs)
    $pub = @($all | Where-Object { $_.State -eq 'Established' -and $_.Scope -eq 'public' })
    $rows = if ($chkPub.Checked) { $pub } else { $all }
    $rank = @{ public = 0; any = 1; lan = 2; multi = 3; loop = 4; none = 5 }
    $gridNet.Rows.Clear()
    foreach ($c in $rows | Sort-Object @{ e = { $rank[$_.Scope] } }, Name, Remote) {
        $sig = Get-Sig $c.Path
        $bad = $false
        $sigText = switch ($sig.Status) {
            'Valid' { T 'sig_Valid' }
            'NotSigned' { if ($c.Path -like "$env:ProgramFiles\WindowsApps\*") { T 'sig_pkg' } else { $bad = $true; T 'sig_NotSigned' } }
            'NoPath' { T 'sig_NoPath' }
            default { T 'sig_other' }
        }
        $i = $gridNet.Rows.Add((Ltr $c.Name), $c.Id, ('{0} {1}' -f $c.Proto, (T "st_$($c.State)")), (Ltr $(if ($c.Remote) { $c.Remote } else { $c.Local })), (Ltr $c.Host), (T "sc_$($c.Scope)"), $sigText)
        $gridNet.Rows[$i].Tag = $c
        if ($bad -or -not $c.Known) { $gridNet.Rows[$i].DefaultCellStyle.ForeColor = [Drawing.Color]::FromArgb(255, 140, 60) }
    }
    $gridNet.ClearSelection()
    $lblNetMsg.Text = ((T 'n_summary') -f $pub.Count, @($pub | Select-Object -ExpandProperty Id -Unique).Count, @($pub | Where-Object { -not $_.Window } | Select-Object -ExpandProperty Id -Unique).Count)
    $form.Cursor = 'Default'
}

function Show-SecFindings {
    $gridSec.Rows.Clear(); $r = $script:ScanResult
    if (-not $r) { $lblSec.Text = (T 's_hint'); return }
    $sevColor = @{ 3 = [Drawing.Color]::FromArgb(215, 38, 38); 2 = [Drawing.Color]::FromArgb(255, 122, 0); 1 = [Drawing.Color]::FromArgb(110, 95, 0); 0 = [Drawing.Color]::FromArgb(60, 60, 60) }
    foreach ($f in $r.Findings) {
        $txt = if ($script:Lang -eq 'ar') { $f.Ar -replace '("?[A-Za-z]:\\.*)$', ([char]0x202A + '$1' + [char]0x202C) } else { $f.En }
        $i = $gridSec.Rows.Add((T "sev$($f.Sev)"), (T "cat_$($f.Cat)"), (Ltr $f.Subject), $txt)
        $gridSec.Rows[$i].Tag = $f
        $cell = $gridSec.Rows[$i].Cells[0]; $cell.Style.BackColor = $sevColor[$f.Sev]; $cell.Style.SelectionBackColor = $sevColor[$f.Sev]
        $fg = if ($f.Sev -eq 2) { [Drawing.Color]::Black } else { $cText }
        $cell.Style.ForeColor = $fg; $cell.Style.SelectionForeColor = $fg; $cell.Style.Font = Font 9.5 -Bold
    }
    $gridSec.ClearSelection()
    $n = @{}; foreach ($v in 0..3) { $n[$v] = @($r.Findings | Where-Object Sev -eq $v).Count }
    $lblSec.Text = ((T 's_summary') -f $n[3], $n[2], $n[1], $n[0]) + "`r`n" + ((T 's_checked') -f $r.Stats.Processes, $r.Stats.Startup, $r.Stats.CoreUnverified)
}

function Invoke-ScanUi {
    $btnScan.Text = (T 's_scanning'); $nav.Enabled = $false; $flSec.Enabled = $false; $pbSec.Value = 0; $form.Refresh()
    try { $script:ScanResult = Invoke-SecurityScan { param($pct) $pbSec.Value = [math]::Max(0, [math]::Min(100, $pct)); [Windows.Forms.Application]::DoEvents() } }
    finally { $btnScan.Text = (T 's_scan'); $nav.Enabled = $true; $flSec.Enabled = $true }
    Show-SecFindings
}

function Get-RowTag($grid) { if ($grid.SelectedRows.Count -eq 0) { return $null }; $grid.SelectedRows[0].Tag }
function Open-Location($item, $label) {
    if (-not $item) { $label.Text = (T 'sel_first'); return }
    if (-not $item.Path -or -not (Test-Path -LiteralPath $item.Path)) { $label.Text = (T 'no_path'); return }
    Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $item.Path)
}
function Stop-ById($item, $label) {
    if (-not $item) { $label.Text = (T 'sel_first'); return }
    $p = if ($item.Id -gt 4) { Get-Process -Id $item.Id -ErrorAction SilentlyContinue } else { $null }
    if (-not $p) { $label.Text = (T 'no_pid'); return }
    if ($CoreProcs -contains $p.ProcessName) { [void](Show-Msg ((T 'protected') -f $p.ProcessName) 'OK' 'Warning'); return }
    if ((Show-Msg ((T 'confirm_end') -f "$($p.ProcessName) (PID $($p.Id))", 1) 'YesNo' 'Warning') -ne 'Yes') { return }
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}

function Show-Page([string]$k) {
    $script:CurPage = $k
    foreach ($n in $pageKeys) {
        $page[$n].Visible = ($n -eq $k)
        if ($n -eq $k) { $navBtn[$n].BackColor = $cAcc; $navBtn[$n].ForeColor = [Drawing.Color]::Black }
        else { $navBtn[$n].BackColor = $cPanel; $navBtn[$n].ForeColor = $cText }
    }
    if ($k -eq 'proc') { Update-Proc } elseif ($k -eq 'map') { Update-Map } elseif ($k -eq 'net') { Update-Net }
}

function Set-Lang([string]$l) {
    $script:Lang = $l
    $rtl = ($l -eq 'ar')
    $form.RightToLeft = $(if ($rtl) { 'Yes' } else { 'No' })
    $form.Text = (T 'title'); $lblTitle.Text = (T 'title'); $btnLang.Text = (T 'lang_btn')
    $btnLang.Dock = $(if ($rtl) { 'Left' } else { 'Right' })
    # 'Left' already means the start side under RightToLeft, so only the forced-LTR label needs flipping
    $lblProcMsg.TextAlign = $(if ($rtl) { 'MiddleRight' } else { 'MiddleLeft' })
    foreach ($k in $pageKeys) { $navBtn[$k].Text = (T "nav_$k") }
    $btnTrim.Text = (T 'trim_now'); $chkAuto.Text = (T 'auto'); $lblMin.Text = (T 'minutes')
    $gridProc.Columns['name'].HeaderText = (T 'col_name'); $gridProc.Columns['count'].HeaderText = (T 'col_count')
    $gridProc.Columns['ws'].HeaderText = (T 'col_ws'); $gridProc.Columns['priv'].HeaderText = (T 'col_priv')
    $btnRefresh.Text = (T 'refresh'); $btnMapRefresh.Text = (T 'refresh'); $btnTrimSel.Text = (T 'trim_sel'); $btnEndSel.Text = (T 'end_sel')
    $gridMap.Columns['item'].HeaderText = (T 'col_item'); $gridMap.Columns['val'].HeaderText = (T 'col_val'); $gridMap.Columns['mean'].HeaderText = (T 'col_mean')
    foreach ($c in 'proc', 'pid', 'state', 'remote', 'host', 'scope', 'sig') { $gridNet.Columns[$c].HeaderText = (T "n_$c") }
    $btnNetRefresh.Text = (T 'refresh'); $btnNetLoc.Text = (T 'open_loc'); $btnNetEnd.Text = (T 'end_proc'); $chkPub.Text = (T 'n_pubonly')
    foreach ($c in 'sev', 'cat', 'subj', 'find') { $gridSec.Columns[$c].HeaderText = (T "s_$c") }
    $btnScan.Text = (T 's_scan'); $btnSecSave.Text = (T 's_save'); $btnSecLoc.Text = (T 'open_loc'); $btnSecEnd.Text = (T 'end_proc')
    Show-SecFindings
    foreach ($k in $toolKeys) { $toolBtn[$k].Text = (T "t_$k"); $toolLbl[$k].Text = (T "t_${k}_d") }
    $toolBtn.admin.Enabled = -not $IsAdmin
    $abVer.Text = ((T 'a_ver') -f $Version); $abWhat.Text = (T 'a_what'); $abDevH.Text = (T 'a_dev'); $abDev.Text = (T 'a_name'); $abAff.Text = (T 'a_aff')
    $status.Text = ('{0}     |     {1}' -f (T 'st_dev'), $(if ($IsAdmin) { T 'st_admin' } else { T 'st_user' }))
    $lblProcMsg.Text = ''; $lblToolMsg.Text = ''
    Update-Gauge
    if ($script:CurPage -eq 'map') { Update-Map } elseif ($script:CurPage -eq 'net') { Update-Net }
}

$gauge = New-Object Windows.Forms.Timer; $gauge.Interval = 2000; $gauge.Add_Tick({ Update-Gauge })
$auto = New-Object Windows.Forms.Timer; $auto.Add_Tick({ Start-TrimUi })
$setAuto = { $auto.Stop(); if ($chkAuto.Checked) { $auto.Interval = [int]$numAuto.Value * 60000; $auto.Start() } }
$chkAuto.Add_CheckedChanged($setAuto); $numAuto.Add_ValueChanged($setAuto)
$btnTrim.Add_Click({ Start-TrimUi })
$btnRefresh.Add_Click({ Update-Proc; $lblProcMsg.Text = '' }); $btnMapRefresh.Add_Click({ Update-Map })
$btnTrimSel.Add_Click({ Invoke-TrimSelected }); $btnEndSel.Add_Click({ Invoke-EndSelected })
$btnNetRefresh.Add_Click({ Update-Net }); $chkPub.Add_CheckedChanged({ if ($script:CurPage -eq 'net') { Update-Net } })
$btnNetLoc.Add_Click({ Open-Location (Get-RowTag $gridNet) $lblNetMsg }); $btnNetEnd.Add_Click({ Stop-ById (Get-RowTag $gridNet) $lblNetMsg; Update-Net })
$btnScan.Add_Click({ Invoke-ScanUi })
$btnSecLoc.Add_Click({ Open-Location (Get-RowTag $gridSec) $lblSec }); $btnSecEnd.Add_Click({ Stop-ById (Get-RowTag $gridSec) $lblSec })
$btnSecSave.Add_Click({
    if (-not $script:ScanResult) { $lblSec.Text = (T 's_hint'); return }
    $path = Join-Path ([Environment]::GetFolderPath('Desktop')) ("RamTrim_security_{0:yyyyMMdd_HHmm}.txt" -f (Get-Date))
    [IO.File]::WriteAllText($path, (Get-SecurityReportText $script:ScanResult), (New-Object Text.UTF8Encoding($true)))
    $lblSec.Text = (T 'report_saved') + "`r`n" + $path
})
$btnLang.Add_Click({
    $new = $(if ($script:Lang -eq 'ar') { 'en' } else { 'ar' })
    Set-Lang $new
    try { [void](New-Item -ItemType Directory -Force (Split-Path $LangFile)); Set-Content -Path $LangFile -Value $new -Encoding ascii } catch { }
})

$script:CurPage = 'home'
Set-Lang $script:Lang; Show-Page 'home'

if ($Snap) {
    # self-test: exercise every page in both languages, save a PNG of each, then exit
    $form.Add_Shown({
        function Save-Snap($name) {
            $form.Refresh(); [Windows.Forms.Application]::DoEvents()
            $bmp = New-Object Drawing.Bitmap($form.Width, $form.Height)
            $form.DrawToBitmap($bmp, (New-Object Drawing.Rectangle(0, 0, $form.Width, $form.Height)))
            $bmp.Save((Join-Path $Snap "$name.png")); $bmp.Dispose()
        }
        $log = @()
        foreach ($l in 'ar', 'en') {
            Set-Lang $l
            foreach ($k in $pageKeys) {
                Show-Page $k
                if ($k -eq 'home' -and $l -eq 'ar') { Start-TrimUi; $log += "home: " + ($boxLog.Lines | Select-Object -First 2) -join ' | ' }
                if ($k -eq 'proc') {
                    $gridProc.ClearSelection(); $gridProc.Rows[1].Selected = $true
                    if ($l -eq 'ar') { Invoke-TrimSelected; $gridProc.ClearSelection(); $gridProc.Rows[1].Selected = $true }
                    $log += "proc[$l]: rows=$($gridProc.Rows.Count) msg=$($lblProcMsg.Text)"
                }
                if ($k -eq 'map') { $log += "map[$l]: rows=$($gridMap.Rows.Count) active=$('{0:N1}' -f $script:Map.Active) standby=$('{0:N1}' -f $script:Map.Standby)" }
                if ($k -eq 'net') { $log += "net[$l]: rows=$($gridNet.Rows.Count) msg=$($lblNetMsg.Text)" }
                if ($k -eq 'sec') {
                    if ($l -eq 'ar') { Invoke-ScanUi }
                    $log += "sec[$l]: findings=$($gridSec.Rows.Count) | $($lblSec.Text -replace '\s+', ' ')"
                }
                if ($k -eq 'tools' -and $l -eq 'en') { Invoke-Tool 'flush'; $log += "tools flush (non-admin): $($lblToolMsg.Text)" }
                Save-Snap "snap_${l}_$k"
            }
        }
        [IO.File]::WriteAllLines((Join-Path $Snap 'snap_log.txt'), $log, (New-Object Text.UTF8Encoding($true)))
        $form.Close()
    })
}

Update-Gauge; $gauge.Start()
[void]$form.ShowDialog()
$gauge.Stop(); $auto.Stop()
