'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { exec, execSync, execFile, execFileSync, spawn } = require('child_process');

const IS_WIN = process.platform === 'win32';
const DATA_DIR = path.join(process.env.ProgramData || 'C:\\ProgramData', 'Focus Guard');
const P = (n) => path.join(DATA_DIR, n);
const F = {
    state: P('state.json'),
    guardPid: P('guardian.pid'),
    uiPid: P('ui.pid'),
    events: P('events.jsonl'),
    webRules: P('web-rules.json'),
    watcherPs: P('watcher.ps1'),
    watcherPid: P('watcher.pid'),
    aliases: P('aliases.json'),
    clock: P('clock.json'),
    mute: P('mute.json'),
    log: P('guardian.log')
};
const TASK_GUARD = 'Focus Guard';
const TASK_UI = 'Focus Guard UI';
const REG_KEY = 'HKLM\\SOFTWARE\\Focus Guard';

const HOSTS_OVERRIDE = process.env.COMEBACK_HOSTS || '';      
const HOSTS_PATH = HOSTS_OVERRIDE ||
    path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts');
const MARK_START = '# --- Focus Guard START ---';
const MARK_END = '# --- Focus Guard END ---';
const BLOCK_RE = new RegExp('\\r?\\n?' + MARK_START + '[\\s\\S]*?' + MARK_END + '[^\\r\\n]*(\\r?\\n)?', 'g');

const CLOCK_SYNC_MS = 60000;
const CLOSE_GRACE_MS = 8000;         
const CLOCK_NOISE_MS = 4000;      
const TIME_SOURCES = ['1.1.1.1', 'www.msftconnecttest.com', 'clients3.google.com', 'neverssl.com'];

/* ---------------- helpers ---------------- */
const norm = (s) => String(s || '').toLowerCase().replace(/\.exe$/, '').replace(/[^a-z0-9]/g, '');
const mono = () => Number(process.hrtime.bigint() / 1000000n);     // system clock bodlale o thik thake

function log(...a) {
    try { fs.appendFileSync(F.log, new Date().toISOString() + ' ' + a.join(' ') + '\n'); } catch (e) { /* ignore */ }
}
function emit(evt) {
    try { fs.appendFileSync(F.events, JSON.stringify(Object.assign({ ts: Date.now() }, evt)) + '\n'); } catch (e) { /* ignore */ }
}
function readJson(file) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; }
}

function writeAtomic(file, data, enc) {
    const tmp = file + '.tmp' + process.pid;
    try {
        fs.writeFileSync(tmp, data, enc || 'utf8');
        fs.renameSync(tmp, file);
        return true;
    } catch (e) {
        try { fs.unlinkSync(tmp); } catch (e2) { /* ignore */ }
        try { fs.writeFileSync(file, data, enc || 'utf8'); return true; } catch (e3) { return false; }
    }
}
function writeUtf16(file, text) {
    fs.writeFileSync(file, Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(text, 'utf16le')]));
}
function heartbeat(file) { writeAtomic(file, JSON.stringify({ pid: process.pid, ts: Date.now() })); }
function readPidFile(file) { return readJson(file); }
function aliveFile(file, maxAge) {
    const d = readPidFile(file);
    if (!d || !d.pid || Math.abs(Date.now() - d.ts) > (maxAge || 6000)) return false;
    try { process.kill(d.pid, 0); } catch (e) { if (e.code !== 'EPERM') return false; }
    return true;
}
function readAliases() { return readJson(F.aliases) || {}; }

function isAdminSync() {
    if (!IS_WIN) return false;
    try {
        execFileSync('fsutil', ['dirty', 'query', process.env.SystemDrive || 'C:'], { stdio: 'ignore', windowsHide: true });
        return true;
    } catch (e) { return false; }
}

/* ---------------- trusted time (clock tamper protection) ---------------- */
let clockState = { offset: 0, readAt: -1e9 };

function clockOffset() {
    const t = mono();
    if (t - clockState.readAt > 1000) {
        clockState.readAt = t;
        const c = readJson(F.clock);
        if (c && typeof c.offset === 'number' && isFinite(c.offset)) clockState.offset = c.offset;
    }
    return clockState.offset;
}

function nowMs() { return Date.now() + clockOffset(); }

function setOffset(off) {
    clockState.offset = off;
    clockState.readAt = mono();
    writeAtomic(F.clock, JSON.stringify({ offset: off, syncedAt: Date.now() }));
}


function httpOffset(host, timeoutMs) {
    return new Promise((resolve) => {
        let done = false;
        const fin = (v) => { if (!done) { done = true; resolve(v); } };
        try {
            const t0 = Date.now();
            const req = http.request({
                host, port: 80, path: '/', method: 'HEAD', timeout: timeoutMs, agent: false,
                headers: { 'User-Agent': 'Mozilla/5.0', Connection: 'close' }
            }, (res) => {
                const t1 = Date.now();
                const d = Date.parse(res.headers.date || '');
                res.resume();
                if (!isFinite(d)) return fin(null);
                fin(d + 500 - (t0 + t1) / 2);          // header e second porjonto thake, tai +500ms
            });
            req.on('timeout', () => { req.destroy(); fin(null); });
            req.on('error', () => { req.destroy(); fin(null); });
            req.end();
        } catch (e) { fin(null); }
    });
}


function pickOffset(vals, current) {
    const v = vals.filter((x) => typeof x === 'number' && isFinite(x)).sort((a, b) => a - b);
    if (!v.length) return null;
    // Ekta-i source pele (onno gulo block / offline) boro lafh mani na; ager offset er kachakachi hole tobei nei
    if (v.length === 1) return (typeof current === 'number' && Math.abs(v[0] - current) <= 120000) ? v[0] : null;
    const med = v[Math.floor(v.length / 2)];
    const agree = v.filter((x) => Math.abs(x - med) <= 5000);
    if (agree.length < 2) return null;
    return agree.reduce((s, x) => s + x, 0) / agree.length;
}

let lastClockCheck = -1e9;
let syncPromise = null;
async function doSyncClock() {
    try {
        const res = await Promise.all(TIME_SOURCES.map((h) => httpOffset(h, 4000)));
        lastClockCheck = mono();
        const off = pickOffset(res, clockState.offset);
        if (off === null) return;
        const val = Math.abs(off) < CLOCK_NOISE_MS ? 0 : Math.round(off / 1000) * 1000;
        if (Math.abs(val - clockState.offset) >= 1000) log('clock offset set to', val, 'ms');
        setOffset(val);
    } catch (e) { log('clock sync error:', e.message); }
}
function syncClock() {
    if (!syncPromise) syncPromise = doSyncClock().then(() => { syncPromise = null; }, () => { syncPromise = null; });
    return syncPromise;
}

/* ---------------- known apps ---------------- */
const APP_DB = {
    youtube:   { procs: [], domains: ['youtube.com', 'youtu.be', 'youtube-nocookie.com'] },
    facebook:  { procs: ['facebook.exe'], domains: ['facebook.com', 'fb.com', 'fb.watch'] },
    instagram: { procs: ['instagram.exe'], domains: ['instagram.com', 'instagr.am'] },
    tiktok:    { procs: ['tiktok.exe'], domains: ['tiktok.com'] },
    whatsapp:  { procs: ['whatsapp.exe', 'whatsapp.root.exe'], domains: ['whatsapp.com', 'whatsapp.net'] },
    messenger: { procs: ['messenger.exe'], domains: ['messenger.com'] },
    telegram:  { procs: ['telegram.exe', 'telegramdesktop.exe'], domains: ['telegram.org', 't.me', 'telegram.me'] },
    snapchat:  { procs: ['snapchat.exe'], domains: ['snapchat.com'] },
    xtwitter:  { procs: [], domains: ['x.com', 'twitter.com'] },
    reddit:    { procs: [], domains: ['reddit.com', 'redd.it'] },
    netflix:   { procs: ['netflix.exe'], domains: ['netflix.com'] },
    spotify:   { procs: ['spotify.exe'], domains: ['spotify.com'] },
    discord:   { procs: ['discord.exe', 'discordptb.exe', 'discordcanary.exe'], domains: ['discord.com', 'discordapp.com', 'discord.gg'] },
    pinterest: { procs: ['pinterest.exe'], domains: ['pinterest.com'] },
    twitch:    { procs: ['twitch.exe'], domains: ['twitch.tv'] },
    steam:     { procs: ['steam.exe', 'steamwebhelper.exe', 'steamservice.exe'], domains: ['steampowered.com', 'steamcommunity.com'] }
};

const APP_SECTION_RULES = {
    'Youtube Shorts':   { label: 'Youtube Shorts',   paths: ['/shorts', '*/shorts'] },
    'Youtube Videos':   { label: 'Youtube Videos',   paths: ['/watch', '/embed'], hosts: ['youtu.be'] },
    'Youtube Live':     { label: 'Youtube Live',     paths: ['/live'] },
    'Facebook Reels':   { label: 'Facebook Reels',   paths: ['/reel', '/reels', '/share/r', '*/reel'] },
    'Facebook Video':   { label: 'Facebook Video',   paths: ['/watch', '/videos', '*/videos', '/share/v'], hosts: ['fb.watch'] },
    'Facebook Post':    { label: 'Facebook Post',    paths: ['/posts', '*/posts', '/permalink.php', '/photo', '/photo.php', '*/photos', '/story.php', '/share/p'] },
    'Instagram Reels':  { label: 'Instagram Reels',  paths: ['/reels', '/reel', '*/reel', '*/reels'] },
    'Instagram Post':   { label: 'Instagram Post',   paths: ['/p', '*/p'] }
};

const BASE_PREFIXES = ['', 'www.', 'm.', 'mobile.', 'web.'];
const EXTRA_SUBS = {
    'youtube.com':       ['music', 'studio', 'tv', 'kids', 'gaming'],
    'facebook.com':      ['l', 'lm', 'mbasic', 'touch', 'business', 'developers', 'free'],
    'instagram.com':     ['l', 'help'],
    'reddit.com':        ['old', 'new', 'np', 'amp'],
    'twitter.com':       ['mobile', 'api'],
    'x.com':             ['mobile'],
    'tiktok.com':        ['vm', 'vt'],
    'discord.com':       ['canary', 'ptb'],
    'steampowered.com':  ['store', 'help'],
    'twitch.tv':         ['player', 'clips'],
    'netflix.com':       ['help'],
    'spotify.com':       ['open']
};

const PROTECTED = new Set([
    'electron', 'system', 'systemidleprocess', 'idle', 'registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services',
    'lsass', 'svchost', 'explorer', 'dwm', 'conhost', 'cmd', 'powershell', 'pwsh', 'sihost', 'fontdrvhost',
    'ctfmon', 'audiodg', 'spoolsv', 'msmpeng', 'runtimebroker', 'taskhostw', 'searchhost', 'textinputhost',
    'startmenuexperiencehost', 'shellexperiencehost', 'lockapp', 'logonui', 'userinit', 'wmiprvse',
    'securityhealthservice', 'securityhealthsystray', 'wscript', 'taskeng', 'schtasks',
    'dllhost', 'applicationframehost', 'smartscreen', 'searchindexer', 'searchapp', 'searchui', 'sgrmbroker',
    'wudfhost', 'dashost', 'memorycompression', 'securityhealthhost', 'ntoskrnl', 'msdtc', 'taskmgr'
]);

const validDomain = (d) => typeof d === 'string' && d.length <= 253 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(d);

function buildEffective(rules, aliases) {
    aliases = aliases || {};
    const web = [];
    const hostDomains = new Set();
    const procExact = new Set();
    const procFuzzy = new Set();
    const cleanDomains = (arr) => (arr || []).map((d) => String(d).toLowerCase()).filter(validDomain);

    rules.forEach((r) => {
        const n = norm(r.target);
        if (r.kind === 'website') {
            const domains = cleanDomains((r.domains && r.domains.length) ? r.domains : (r.host ? [r.host] : []));
            if (!domains.length) return;
            web.push({ target: r.target, domains, all: !!r.all, sections: r.sections || [], endAt: r.endAt });
            if (r.all) domains.forEach((d) => hostDomains.add(d));
            return;
        }
        const known = APP_DB[n];
        if (known) {
            if (r.all) {
                known.procs.forEach((p) => procExact.add(p));
                web.push({ target: r.target, domains: known.domains, all: true, sections: [], endAt: r.endAt });
                known.domains.forEach((d) => hostDomains.add(d));
            } else {
                const sections = (r.sections || []).map((s) => {
                    if (s && ((Array.isArray(s.paths) && s.paths.length) || (Array.isArray(s.hosts) && s.hosts.length))) {
                        const o = { label: s.label, paths: Array.isArray(s.paths) ? s.paths : [] };
                        if (Array.isArray(s.hosts) && s.hosts.length) o.hosts = s.hosts;
                        return o;
                    }
                    return APP_SECTION_RULES[s.label] || APP_SECTION_RULES[r.target + ' ' + s.label];
                }).filter(Boolean);
                if (sections.length) {
                    web.push({ target: r.target, domains: known.domains, all: false, sections, endAt: r.endAt });
                } else {
                    // section web path diye enforce kora jay na -> pura app block (kichu na kora theke nirapod)
                    known.procs.forEach((p) => procExact.add(p));
                    web.push({ target: r.target, domains: known.domains, all: true, sections: [], endAt: r.endAt });
                    known.domains.forEach((d) => hostDomains.add(d));
                }
            }
        } else if (aliases[n] && aliases[n].length) {
            aliases[n].forEach((p) => procExact.add(String(p).toLowerCase()));
        } else if (n.length >= 3) {
            procFuzzy.add(n);
        }
    });
    return { web, hostDomains: [...hostDomains], procExact, procFuzzy };
}

/* ---------------- hosts file ---------------- */
function prefixesFor(domain) {
    const extra = (EXTRA_SUBS[domain] || []).map((s) => s + '.');
    return [...new Set(BASE_PREFIXES.concat(extra))];
}

function hostsBlockText(domains) {
    const safe = domains.filter(validDomain);
    if (!safe.length) return '';
    const lines = [MARK_START];
    safe.forEach((d) => {
        prefixesFor(d).forEach((p) => {
            lines.push(`0.0.0.0 ${p}${d}`);
            lines.push(`::1 ${p}${d}`);
        });
    });
    lines.push(MARK_END);
    return lines.join('\r\n');
}

function setHostsBlock(domains) {
    const content = fs.readFileSync(HOSTS_PATH, 'utf8');
    const cleaned = content.replace(BLOCK_RE, '');
    const block = hostsBlockText(domains);
    const next = block ? cleaned.replace(/\s*$/, '') + '\r\n' + block + '\r\n' : cleaned;
    if (next === content) return false;
    try {
        fs.writeFileSync(HOSTS_PATH, next, 'utf8');
    } catch (e) {
        try { fs.chmodSync(HOSTS_PATH, 0o666); } catch (e2) { /* ignore */ }
        fs.writeFileSync(HOSTS_PATH, next, 'utf8');
    }
    if (IS_WIN && !HOSTS_OVERRIDE) exec('ipconfig /flushdns', { windowsHide: true }, () => {});
    return true;
}

let hostsTouched = false;
let hostsErrAt = -1e9;
let hostsErrNotified = false;
function ensureHosts(domains) {
    if (!domains.length && !hostsTouched) return;
    if (mono() - hostsErrAt < 10000) return;
    try {
        if (setHostsBlock(domains)) log('hosts (re)applied:', domains.slice().sort().join(',') || '(cleared)');
        if (domains.length) hostsTouched = true;
        hostsErrNotified = false;
    } catch (err) {
        hostsErrAt = mono();
        log('hosts error:', err.message);
        if (!hostsErrNotified) { hostsErrNotified = true; emit({ type: 'hosts' }); }
    }
}

/* ---------------- app process killer ---------------- */
function selectVictims(names, eff, ownName) {
    const victims = [];
    names.forEach((name) => {
        const lower = name.toLowerCase();
        const n = norm(lower);
        if (PROTECTED.has(n) || n === ownName) return;
        let hit = eff.procExact.has(lower);
        if (!hit) {
            for (const f of eff.procFuzzy) {
                if (n === f || (f.length >= 6 && n.startsWith(f))) { hit = true; break; }
            }
        }
        if (hit) victims.push(name);
    });
    return victims;
}

const closeAsked = new Map();
function killLoop(eff) {
    if (!IS_WIN) return;
    if (!eff.procExact.size && !eff.procFuzzy.size) return;
    exec('tasklist /fo csv /nh', { windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (err, out) => {
        if (err || !out) return;
        const own = norm(path.basename(process.execPath));
        const names = new Set();
        out.split(/\r?\n/).forEach((line) => {
            const m = /^"([^"]+)"/.exec(line);
            if (m) names.add(m[1]);
        });
        const present = new Set([...names].map((x) => x.toLowerCase()));
        closeAsked.forEach((v, k) => { if (!present.has(k)) closeAsked.delete(k); });

        const victims = selectVictims([...names], eff, own);
        const t = mono();
        victims.forEach((name) => {
            const key = name.toLowerCase();
            const asked = closeAsked.get(key);
            if (asked === undefined) {
                closeAsked.set(key, t);
                execFile('taskkill', ['/t', '/im', name], { windowsHide: true }, () => {});
                emit({ type: 'app-closing', name });
                log('close requested:', name);
            } else if (t - asked >= CLOSE_GRACE_MS) {
                execFile('taskkill', ['/f', '/t', '/im', name], { windowsHide: true }, () => {});
                emit({ type: 'app', name });
                log('force killed:', name);
            }
        });
    });
}

/* ---------------- browser watcher (PowerShell + UI Automation) ---------------- */
const WATCHER_PS1 = String.raw`param([string]$RulesPath, [int]$ParentPid)
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class CbWin {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
}
"@

$browsers = @('chrome','msedge','firefox','brave','opera','vivaldi','chromium','arc','thorium','librewolf','waterfox','yandex','iexplore')
$scope = [System.Windows.Automation.TreeScope]::Descendants
$script:lastUrl = ''
$script:streak = 0
$script:cache = @{}

function Load-Rules {
    if (-not (Test-Path $RulesPath)) { return @() }
    try {
        $raw = Get-Content -Raw -Encoding UTF8 $RulesPath
        if (-not $raw) { return @() }
        $all = $raw | ConvertFrom-Json
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        return @($all | Where-Object { $_.endAt -gt $now })
    } catch { return @() }
}

function Test-Blocked($url, $rules) {
    $v = $url.Trim()
    if (-not $v -or $v -match '\s') { return $null }
    if ($v -notmatch '^[a-z][a-z0-9+.\-]*://') { $v = 'https://' + $v }
    try { $u = [Uri]$v } catch { return $null }
    if ($u.Scheme -ne 'http' -and $u.Scheme -ne 'https') { return $null }
    $h = $u.Host.ToLower() -replace '^www\.',''
    $p = $u.AbsolutePath.ToLower() -replace '/{2,}','/'
    if ($p.Length -gt 1) { $p = $p.TrimEnd('/') }
    foreach ($r in $rules) {
        $hit = $false
        foreach ($d in $r.domains) { if ($h -eq $d -or $h.EndsWith('.' + $d)) { $hit = $true; break } }
        if (-not $hit) { continue }
        if ($r.all) { return @{ reason = [string]$r.target; all = $true } }
        foreach ($s in $r.sections) {
            if ($s.hosts -and ($s.hosts -contains $h) -and $p -ne '/') { return @{ reason = [string]$s.label; all = $false } }
            foreach ($q in $s.paths) {
                $q = $q.ToLower()
                if ($q -eq '/') { if ($p -eq '/') { return @{ reason = [string]$s.label; all = $false } } }
                elseif ($q.StartsWith('*/')) {
                    $mm = [regex]::Match($p, '^/[^/]+')
                    if ($mm.Success) {
                        $rest = $p.Substring($mm.Length)
                        $tt = $q.Substring(1)
                        if ($rest -eq $tt -or $rest.StartsWith($tt + '/')) { return @{ reason = [string]$s.label; all = $false } }
                    }
                }
                elseif ($p -eq $q -or $p.StartsWith($q + '/')) { return @{ reason = [string]$s.label; all = $false } }
            }
        }
    }
    return $null
}

function Find-AddressBar($root) {
    $c1 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, 'OmniboxViewViews')
    $el = $root.FindFirst($scope, $c1)
    if ($el) { return $el }
    $c2 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, 'urlbar-input')
    $el = $root.FindFirst($scope, $c2)
    if ($el) { return $el }
    $c3 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, 'Address and search bar')
    $el = $root.FindFirst($scope, $c3)
    if ($el) { return $el }
    $c4 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
    foreach ($e in $root.FindAll($scope, $c4)) {
        if ($e.Current.Name -match 'address|search or enter|search with') { return $e }
    }
    return $null
}

function Read-Bar($el) {
    $vp = $el.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    return @{ url = [string]$vp.Current.Value; focus = [bool]$el.Current.HasKeyboardFocus; el = $el }
}

function Get-BrowserInfo($hwnd) {
    $key = $hwnd.ToInt64()
    $cached = $script:cache[$key]
    if ($cached) {
        try { return Read-Bar $cached } catch { $script:cache.Remove($key) }
    }
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    if (-not $root) { return $null }
    $el = Find-AddressBar $root
    if (-not $el) { return $null }
    try {
        $info = Read-Bar $el
        if ($script:cache.Count -gt 20) { $script:cache.Clear() }
        $script:cache[$key] = $el
        return $info
    } catch { return $null }
}

function Same-Window($h) { return ([CbWin]::GetForegroundWindow().ToInt64() -eq $h.ToInt64()) }

function Still-Blocked($h, $rules) {
    if (-not (Same-Window $h)) { return $null }
    $fresh = Get-BrowserInfo $h
    if (-not $fresh -or -not $fresh.url) { return $null }
    if (-not (Test-Blocked $fresh.url $rules)) { return $null }
    return $fresh
}

function Go-To($h, $info, $url) {
    try {
        $el = $info.el
        $el.SetFocus()
        Start-Sleep -Milliseconds 80
        $vp = $el.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
        $vp.SetValue($url)
        Start-Sleep -Milliseconds 80
        if ((Same-Window $h) -and ([string]$vp.Current.Value -eq $url) -and $el.Current.HasKeyboardFocus) {
            [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
            Start-Sleep -Milliseconds 300
            return $true
        }
    } catch { }

    $old = $null
    $hadText = $false
    try {
        $hadText = [System.Windows.Forms.Clipboard]::ContainsText()
        if ($hadText) { $old = [System.Windows.Forms.Clipboard]::GetText() }
        else {
            $do = [System.Windows.Forms.Clipboard]::GetDataObject()
            if ($do -and $do.GetFormats().Length -gt 0) { return $false }
        }
    } catch { return $false }
    $ok = $false
    try {
        [System.Windows.Forms.Clipboard]::SetText($url)
        if (-not (Same-Window $h)) { throw 'moved' }
        [System.Windows.Forms.SendKeys]::SendWait('^l')
        Start-Sleep -Milliseconds 200
        $chk = Get-BrowserInfo $h
        if ($chk -and $chk.focus -and (Same-Window $h)) {
            [System.Windows.Forms.SendKeys]::SendWait('^v')
            Start-Sleep -Milliseconds 150
            [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
            Start-Sleep -Milliseconds 400
            $ok = $true
        } else {
            [System.Windows.Forms.SendKeys]::SendWait('{ESC}')
        }
    } catch { }
    try { if ($hadText) { [System.Windows.Forms.Clipboard]::SetText($old) } else { [System.Windows.Forms.Clipboard]::Clear() } } catch { }
    return $ok
}

while ($true) {
    Start-Sleep -Milliseconds 700
    if ($ParentPid -gt 0 -and -not (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) { exit }
    try {
        $rules = Load-Rules
        if ($rules.Count -eq 0) { $script:streak = 0; continue }

        $h = [CbWin]::GetForegroundWindow()
        if ($h -eq [IntPtr]::Zero) { continue }
        $procId = [uint32]0
        [void][CbWin]::GetWindowThreadProcessId($h, [ref]$procId)
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        if ($browsers -notcontains $proc.ProcessName.ToLower()) { $script:streak = 0; continue }

        $info = Get-BrowserInfo $h
        if (-not $info -or -not $info.url) { continue }

        $m = Test-Blocked $info.url $rules
        if (-not $m) { $script:streak = 0; $script:lastUrl = ''; continue }
        $reason = $m.reason

        if ($info.focus) {
            if ($info.url -eq $script:lastUrl) { $script:streak++ } else { $script:lastUrl = $info.url; $script:streak = 1 }
            if ($script:streak -lt 4) { continue }
        }

        $cur = Still-Blocked $h $rules
        if (-not $cur) { $script:streak = 0; $script:lastUrl = ''; continue }

        $redirect = $null
        if (-not $m.all) {
            $full = $cur.url
            if ($full -notmatch '^[a-z][a-z0-9+.\-]*://') { $full = 'https://' + $full }
            try { $hostName = ([Uri]$full).Host } catch { $hostName = $null }
            if ($hostName) {
                $homeUrl = 'https://' + $hostName + '/'
                if (-not (Test-Blocked $homeUrl $rules)) { $redirect = $homeUrl }
            }
        }

        $done = $false
        if ($redirect) { $done = Go-To $h $cur $redirect }
        if (-not $done) {
            $again = Still-Blocked $h $rules
            if ($again) { [System.Windows.Forms.SendKeys]::SendWait('^w'); $done = $true }
        }
        if ($done) {
            [Console]::Out.WriteLine('BLOCKED|' + $reason + '|' + $cur.url)
            [Console]::Out.Flush()
        }
        $script:streak = 0
        $script:lastUrl = ''
        Start-Sleep -Milliseconds 1200
    } catch { }
}
`;

let watcher = null;
function killStaleWatcher() {
    const d = readPidFile(F.watcherPid);
    if (d && d.pid) { try { execFileSync('taskkill', ['/f', '/pid', String(d.pid)], { stdio: 'ignore', windowsHide: true }); } catch (e) { /* ignore */ } }
}
function stopWatcher() {
    try { if (watcher) { const w = watcher; watcher = null; w.kill(); } } catch (e) { /* ignore */ }
    if (IS_WIN) killStaleWatcher();
    try { fs.unlinkSync(F.watcherPid); } catch (e) { /* ignore */ }
}
function ensureWatcher() {
    if (!IS_WIN || watcher) return;
    try {
        killStaleWatcher();
        fs.writeFileSync(F.watcherPs, WATCHER_PS1, 'utf8');
        watcher = spawn('powershell.exe', [
            '-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'Bypass',
            '-File', F.watcherPs, '-RulesPath', F.webRules, '-ParentPid', String(process.pid)
        ], { windowsHide: true });
        writeAtomic(F.watcherPid, JSON.stringify({ pid: watcher.pid, ts: Date.now() }));
        let buf = '';
        watcher.stdout.on('data', (chunk) => {
            buf += chunk.toString('utf8');
            let i;
            while ((i = buf.indexOf('\n')) >= 0) {
                const line = buf.slice(0, i).trim();
                buf = buf.slice(i + 1);
                if (line.startsWith('BLOCKED|')) {
                    const parts = line.split('|');
                    log('tab handled:', parts[1], parts[2]);
                    emit({ type: 'web', label: parts[1] || '' });
                }
            }
        });
        watcher.on('exit', () => { watcher = null; });
    } catch (e) {
        log('watcher error:', e.message);
        watcher = null;
    }
}

/* ---------------- Scheduled Tasks ---------------- */
const escXml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function taskXml({ command, args, cwd, repeating }) {
    const user = escXml(`${process.env.USERDOMAIN || ''}\\${process.env.USERNAME || ''}`);
    const triggers = repeating ? `
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>PT1M</Interval></Repetition>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
    <LogonTrigger><Enabled>true</Enabled><UserId>${user}</UserId></LogonTrigger>
  </Triggers>` : '';
    return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Focus Guard</Description></RegistrationInfo>${triggers}
  <Principals>
    <Principal id="Author">
      <UserId>${user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${escXml(command)}</Command>
      <Arguments>${escXml(args)}</Arguments>${cwd ? `
      <WorkingDirectory>${escXml(cwd)}</WorkingDirectory>` : ''}
    </Exec>
  </Actions>
</Task>`;
}

function schtasks(args) {
    return new Promise((resolve) => {
        exec(`schtasks ${args}`, { windowsHide: true }, (err) => resolve(!err));
    });
}

async function installTasks(launch) {
    try {
        ensureDataDir();
        const q = (a) => `"${a}"`;
        const guardXml = P('task-guardian.xml');
        const uiXml = P('task-ui.xml');
        writeUtf16(guardXml, taskXml({
            command: launch.exe, args: launch.args.map(q).concat(['--guardian']).join(' '), cwd: launch.cwd, repeating: true
        }));
        writeUtf16(uiXml, taskXml({
            command: launch.exe, args: launch.args.map(q).join(' '), cwd: launch.cwd, repeating: false
        }));
        const a = await schtasks(`/Create /TN "${TASK_GUARD}" /XML "${guardXml}" /F`);
        const b = await schtasks(`/Create /TN "${TASK_UI}" /XML "${uiXml}" /F`);
        return a && b;
    } catch (e) {
        log('installTasks failed:', e.message);
        return false;
    }
}

/* ---------------- data folder (permission + helper scripts) ---------------- */
const CLEANUP_PS1 = String.raw`$ErrorActionPreference = 'SilentlyContinue'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$c = [IO.File]::ReadAllText($hosts)
$n = [regex]::Replace($c, '(?s)\r?\n?# --- Focus Guard START ---.*?# --- Focus Guard END ---[^\r\n]*(\r?\n)?', '')
if ($n -ne $c) { [IO.File]::WriteAllText($hosts, $n) }
$mf = Join-Path $env:ProgramData 'Focus Guard\mute.json'
if (Test-Path $mf) {
    $tk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications'
    try { $m = Get-Content -Raw $mf | ConvertFrom-Json } catch { $m = $null }
    if ($m -and $m.prev -ne $null) { Set-ItemProperty -Path $tk -Name ToastEnabled -Value ([int]$m.prev) -Type DWord } else { Remove-ItemProperty -Path $tk -Name ToastEnabled }
}
reg delete 'HKLM\SOFTWARE\Focus Guard' /f | Out-Null
schtasks /Delete /TN "Focus Guard" /F | Out-Null
schtasks /Delete /TN "Focus Guard UI" /F | Out-Null
ipconfig /flushdns | Out-Null
`;

const LOCKCHECK_PS1 = String.raw`$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:ProgramData 'Focus Guard'
$off = 0
try { $off = [double]((Get-Content -Raw (Join-Path $dir 'clock.json') | ConvertFrom-Json).offset) } catch { }
$now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + $off
$active = $false
try {
    $st = Get-Content -Raw -Encoding UTF8 (Join-Path $dir 'state.json') | ConvertFrom-Json
    foreach ($r in @($st.rules)) { if ($r.endAt -gt $now) { $active = $true } }
} catch { }
if (-not $active) {
    try {
        $k = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64).OpenSubKey('SOFTWARE\Focus Guard')
        $b = $k.GetValue('S')
        if ($b) {
            $rules = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)) | ConvertFrom-Json
            foreach ($r in @($rules)) { if ($r.endAt -gt $now) { $active = $true } }
        }
    } catch { }
}
if ($active) { exit 7 } else { exit 0 }
`;

let aclDone = false;
function lockDownDataDir() {
    // BONDHO: pura folder e tala dile admin chhara chalano UI state.json / ui.pid likhte pare na, tai kono block-i guardian er kache pouchay na.
    // (shudhu lockcheck.ps1 / cleanup.ps1 e file-level tala dewa ache - ensureHelperScripts() dekho)
    return;
    if (!IS_WIN || aclDone) return;
    if (!isAdminSync()) return;
    aclDone = true;
    try {
        execFileSync('icacls', [DATA_DIR, '/inheritance:r',
            '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX',
            '/T', '/C', '/Q'], { stdio: 'ignore', windowsHide: true, timeout: 20000 });
    } catch (e) { log('acl failed:', e.message); }
}

/* Ager version e pura folder e tala (Users = shudhu read) deowa hoyechhilo. Oi tala ekbar boshe gele thake (folder er ACL permanent),
 * tai UI (admin chhara) state.json likhte parto na. Admin hole ekbar sei tala shoriye Users ke abar Modify dei. */
const ACL_FIX_MARK = 'acl-fix-v1';
function repairDataDirAcl() {
    if (!IS_WIN) return;
    const mark = P(ACL_FIX_MARK);
    if (fs.existsSync(mark)) return;
    if (!isAdminSync()) return;
    try {
        execFileSync('icacls', [DATA_DIR, '/reset', '/T', '/C', '/Q'], { stdio: 'ignore', windowsHide: true, timeout: 20000 });
        execFileSync('icacls', [DATA_DIR, '/grant', '*S-1-5-32-545:(OI)(CI)M', '/C', '/Q'], { stdio: 'ignore', windowsHide: true, timeout: 20000 });
        fs.writeFileSync(mark, '1');
        log('data folder permissions repaired');
    } catch (e) { log('acl repair failed:', e.message); }
}

function ensureDataDir() {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (IS_WIN) {
        repairDataDirAcl();
        lockDownDataDir();
        try { writeAtomic(P('cleanup.ps1'), CLEANUP_PS1); writeAtomic(P('lockcheck.ps1'), LOCKCHECK_PS1); } catch (e) { /* ignore */ }
    }
}

/* uninstaller ei duita file er upor nirbhor kore: muche felle / bodle felle prati second e abar thik kore dei,
 * ar admin hole file duita te "shudhu admin e bodlate pare" tala dei (pura folder e tala dilam na, karon UI admin chhara chalale state.json likhte parbe na) */
const aclDoneFor = new Set();
function lockGuardFile(file) {
    if (!IS_WIN || !ctx.isAdmin || aclDoneFor.has(file)) return;
    aclDoneFor.add(file);
    try {
        execFileSync('icacls', [file, '/inheritance:r', '/grant:r', '*S-1-5-18:F', '*S-1-5-32-544:F', '*S-1-5-32-545:RX', '/C', '/Q'],
            { stdio: 'ignore', windowsHide: true, timeout: 10000 });
    } catch (e) { log('acl failed:', path.basename(file), e.message); }
}

function ensureHelperScripts() {
    if (!IS_WIN) return;
    try {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        [['lockcheck.ps1', LOCKCHECK_PS1], ['cleanup.ps1', CLEANUP_PS1]].forEach(([name, text]) => {
            const f = P(name);
            let cur = null;
            try { cur = fs.readFileSync(f, 'utf8'); } catch (e) { /* nei */ }
            if (cur !== text) {
                if (writeAtomic(f, text)) { aclDoneFor.delete(f); log(name + ' (re)written'); }
            }
            lockGuardFile(f);
        });
    } catch (e) { /* ignore */ }
}

/* ---------------- state: file + memory + registry backup ---------------- */
const ruleKey = (r) => r.kind + '|' + norm(r.target);
const validRule = (r) => r && typeof r === 'object' && r.kind && r.target && typeof r.endAt === 'number';

function readState() {
    const s = readJson(F.state);
    return { rules: s && Array.isArray(s.rules) ? s.rules.filter(validRule) : [] };
}

function writeBackup(rules) {
    if (!IS_WIN) return;
    try {
        const b64 = Buffer.from(JSON.stringify(rules), 'utf8').toString('base64');
        if (b64.length > 30000) return;
        execFileSync('reg', ['add', REG_KEY, '/v', 'S', '/t', 'REG_SZ', '/d', b64, '/f'], { stdio: 'ignore', windowsHide: true });
    } catch (e) { log('backup write failed:', e.message); }
}
function readBackup() {
    if (!IS_WIN) return [];
    try {
        const out = execFileSync('reg', ['query', REG_KEY, '/v', 'S'], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
        const m = /\sS\s+REG_SZ\s+(\S+)/.exec(out);
        if (!m) return [];
        const arr = JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'));
        return Array.isArray(arr) ? arr.filter(validRule) : [];
    } catch (e) { return []; }
}
function clearBackup() {
    if (!IS_WIN) return;
    try { execFileSync('reg', ['delete', REG_KEY, '/f'], { stdio: 'ignore', windowsHide: true }); } catch (e) { /* ignore */ }
}

const held = new Map();
function mergeHeld(rules) {
    rules.forEach((r) => {
        if (!validRule(r)) return;
        const k = ruleKey(r);
        const old = held.get(k);
        if (!old || r.endAt >= old.endAt) held.set(k, r);
    });
}

function needsRestore(stateRules, now) {
    let need = false;
    held.forEach((r, k) => {
        if (r.endAt <= now + 5000) return;
        const s = stateRules.find((x) => validRule(x) && ruleKey(x) === k);
        if (!s || !(s.endAt >= r.endAt)) need = true;
    });
    return need;
}

/* ---------------- UI relaunch ---------------- */
let lastUiLaunch = -1e9;
function ensureUI(launch) {
    if (aliveFile(F.uiPid)) return;
    if (mono() - lastUiLaunch < 12000) return;
    lastUiLaunch = mono();
    log('UI dead - relaunching');
    exec(`schtasks /Run /TN "${TASK_UI}"`, { windowsHide: true }, (err) => {
        if (err && launch && launch.exe) {
            try {
                spawn(launch.exe, launch.args || [], { cwd: launch.cwd || undefined, detached: true, stdio: 'ignore' }).unref();
            } catch (e) { log('direct UI launch failed:', e.message); }
        }
    });
}

let lastTaskCheck = -1e9;
function ensureTasks(launch, isAdmin) {
    if (!IS_WIN || !isAdmin) return;
    if (mono() - lastTaskCheck < 20000) return;
    lastTaskCheck = mono();
    exec(`schtasks /Query /TN "${TASK_GUARD}"`, { windowsHide: true }, (e1) => {
        exec(`schtasks /Query /TN "${TASK_UI}"`, { windowsHide: true }, (e2) => {
            if (e1 || e2) {
                log('scheduled task missing - recreating');
                installTasks(launch).catch(() => {});
            }
        });
    });
}

/* ---------------- notification mute (Hell Mode) ---------------- */
const TOAST_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications';
let muted = false;
let muteErrAt = -1e9;
function readToastEnabled() {
    try {
        const out = execFileSync('reg', ['query', TOAST_KEY, '/v', 'ToastEnabled'], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
        const m = /ToastEnabled\s+REG_DWORD\s+0x([0-9a-f]+)/i.exec(out);
        return m ? parseInt(m[1], 16) : null;
    } catch (e) { return null; }
}
function writeToastEnabled(v) {
    try {
        if (v === null) execFileSync('reg', ['delete', TOAST_KEY, '/v', 'ToastEnabled', '/f'], { stdio: 'ignore', windowsHide: true });
        else execFileSync('reg', ['add', TOAST_KEY, '/v', 'ToastEnabled', '/t', 'REG_DWORD', '/d', String(v), '/f'], { stdio: 'ignore', windowsHide: true });
        return true;
    } catch (e) { return false; }
}
function restoreToast() {
    if (!IS_WIN) return;
    const st = readJson(F.mute);
    if (!st) { muted = false; return; }
    if (writeToastEnabled(typeof st.prev === 'number' ? st.prev : null)) {
        try { fs.unlinkSync(F.mute); } catch (e) { /* ignore */ }
        muted = false;
        log('notifications restored');
    }
}
function ensureMute(want) {
    if (!IS_WIN) return;
    if (want) {
        if (muted || mono() - muteErrAt < 10000) return;
        if (!readJson(F.mute)) writeAtomic(F.mute, JSON.stringify({ prev: readToastEnabled() }));   // ager obostha mone rakhi (crash hole-o ferot dewa jabe)
        if (writeToastEnabled(0)) { muted = true; log('notifications muted'); } else { muteErrAt = mono(); log('notification mute failed'); }
    } else if (muted || fs.existsSync(F.mute)) {
        restoreToast();
    }
}

/* ---------------- cleanup ---------------- */
function cleanAll() {
    try { restoreToast(); } catch (e) { /* ignore */ }
    try { setHostsBlock([]); } catch (e) { log('clean hosts error:', e.message); }
    hostsTouched = false;
    try { writeAtomic(F.webRules, '[]'); } catch (e) { /* ignore */ }
    stopWatcher();
    clearBackup();
    if (IS_WIN) {
        [TASK_GUARD, TASK_UI].forEach((n) => {
            try { execFileSync('schtasks', ['/Delete', '/TN', n, '/F'], { stdio: 'ignore', windowsHide: true }); } catch (e) { /* ignore */ }
        });
    }
    try { fs.writeFileSync(F.events, '', 'utf8'); } catch (e) { /* ignore */ }
}

/* ---------------- main loop ---------------- */
let ctx = { launch: null, isAdmin: false };
let webSig = null;
let backupSig = null;
let tickCount = 0;
let tickBusy = false;

async function tickInner() {
    ensureHelperScripts();
    heartbeat(F.guardPid);
    const state = readState();
    mergeHeld(state.rules);

    let now = nowMs();
    const anyExpired = () => { for (const r of held.values()) if (r.endAt <= now) return true; return false; };

    if (!held.size) mergeHeld(readBackup());
    if (anyExpired()) {
        if (mono() - lastClockCheck > 5000) await syncClock();
        now = nowMs();
    }
    for (const [k, r] of [...held]) if (r.endAt <= now) held.delete(k);

    if (!held.size) {
        log('no active locks - cleaning up and exiting');
        cleanAll();
        try { fs.unlinkSync(F.guardPid); } catch (e) { /* ignore */ }
        process.exit(0);
    }
    const rules = [...held.values()];

    if (needsRestore(state.rules, now)) {
        writeAtomic(F.state, JSON.stringify({ rules, updatedAt: Date.now() }));
        log('state.json was changed/removed - restored from memory');
    }
    const bsig = JSON.stringify(rules);
    if (bsig !== backupSig) { backupSig = bsig; writeBackup(rules); }

    const live = rules.filter((r) => !(r.breakUntil && r.breakUntil > now));      // Light mode break cholar somoy block pause
    const eff = buildEffective(live, readAliases());
    ensureMute(rules.some((r) => r.intensity === 'deep'));
    const off = clockOffset();
    const wj = JSON.stringify(eff.web.map((w) => Object.assign({}, w, { endAt: Math.round(w.endAt - off) })));
    if (wj !== webSig) { webSig = wj; if (!writeAtomic(F.webRules, wj)) log('web-rules write failed'); }

    if (IS_WIN || HOSTS_OVERRIDE) ensureHosts(eff.hostDomains);
    ensureWatcher();
    if (tickCount % 2 === 0) killLoop(eff);
    ensureUI(ctx.launch);
    ensureTasks(ctx.launch, ctx.isAdmin);
    tickCount++;
}

async function tick() {
    if (tickBusy) return;
    tickBusy = true;
    try { await tickInner(); } catch (e) { log('tick error:', e && e.stack || e); } finally { tickBusy = false; }
}

function run(opts) {
    ctx.launch = opts.launch;
    try { ensureDataDir(); } catch (e) { /* ignore */ }
    ctx.isAdmin = isAdminSync();
    try { if (fs.statSync(F.log).size > 200 * 1024) fs.writeFileSync(F.log, ''); } catch (e) { /* ignore */ }

    if (opts.role === 'cleanup') {
        const now = nowMs();
        const active = readState().rules.some((r) => r.endAt > now) || readBackup().some((r) => r.endAt > now);
        if (!active) cleanAll();
        process.exit(0);
    }

    const other = readPidFile(F.guardPid);
    if (other && other.pid !== process.pid && aliveFile(F.guardPid)) process.exit(0);

    process.on('uncaughtException', (e) => log('uncaught:', e && e.stack || e));
    process.on('unhandledRejection', (e) => log('unhandled:', e && e.stack || e));
    log('guardian started, pid', process.pid, ctx.isAdmin ? '(admin)' : '(NOT admin)');
    heartbeat(F.guardPid);

    setTimeout(() => {
        const d = readPidFile(F.guardPid);
        if (d && d.pid !== process.pid && aliveFile(F.guardPid)) { log('duplicate guardian - exiting'); process.exit(0); }
        syncClock().then(() => tick());
        setInterval(tick, 1000);
        setInterval(syncClock, CLOCK_SYNC_MS);
    }, 400);
}

module.exports = {
    run, installTasks, schtasks, ensureDataDir, isAdminSync, readState, nowMs, clockOffset, writeAtomic, readJson,
    DATA_DIR, F, P, norm,
    _t: { buildEffective, hostsBlockText, setHostsBlock, selectVictims, pickOffset, needsRestore, mergeHeld, held, tickInner, validDomain, taskXml }
};