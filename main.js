'use strict';
const { app, BrowserWindow, dialog, Notification, Tray, Menu, nativeImage, ipcMain, session, powerMonitor } = require('electron');
const path = require('path');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const G = require('./guardian.js');

/*
 * Focus Guard - ekhon ei ekta exe-ই 3 rokom bhumikay chole:
 *
 *   comeback.exe              -> UI (window, tray, notification)
 *   comeback.exe --guardian   -> background engine (window nei). Task Scheduler eta chalay
 *   comeback.exe --cleanup    -> ekbar clean kore ber hoye jay
 *
 * Asol block korar kaj guardian.js kore. UI "End task" korleo guardian bondho hoy na, ar UI nijei abar chalu hoy.
 */

const IS_WIN = process.platform === 'win32';
const ARGV = process.argv.slice(1);
const ROLE = ARGV.includes('--guardian') ? 'guardian' : (ARGV.includes('--cleanup') ? 'cleanup' : 'ui');

const launchInfo = () => ({
    exe: process.execPath,
    args: app.isPackaged ? [] : [app.getAppPath()],
    cwd: app.isPackaged ? path.dirname(process.execPath) : app.getAppPath()
});

if (ROLE !== 'ui') {
    /* ------------------------- guardian / cleanup role ------------------------- */
    app.disableHardwareAcceleration();                 // window nei, GPU lagbe na
    app.on('window-all-closed', () => { /* kichu na: process cholte thakbe */ });
    G.run({ role: ROLE, launch: launchInfo() });
} else {
    startUI();
}

function startUI() {
    const { F, P } = G;
    const ICON_PATH = path.join(__dirname, 'focusguard.ico');

    let mainWindow = null;
    let isBlockingActive = false;
    let latestEndAt = 0;
    let quitting = false;
    let adminOk = true;
    let stateSig = null;
    let lastGuardianStart = 0;
    let startupCleanDone = false;
    let evOffset = 0;
    let tray = null;
    let hiddenForLock = false;
    let syncBusy = false;
    const restoreTried = new Map();      // ruleKey -> shesh kobe renderer e firiye anar chesta hoyechhe

    if (IS_WIN) { try { app.setAppUserModelId('com.focusguard.app'); } catch (e) { /* ignore */ } }

    const norm = G.norm;

    /* ------------------------------------------------------------------ */
    /*  Notification                                                      */
    /* ------------------------------------------------------------------ */
    function fmtTime(ts) {
        const local = ts - G.clockOffset();            // trusted somoy -> PC-r ghorir somoy (user ja dekhe)
        try { return new Date(local).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
        catch (e) { return new Date(local).toLocaleTimeString(); }
    }

    let appIconImg = null;
    function appIcon() {
        try {
            if (!appIconImg && fs.existsSync(ICON_PATH)) {
                const img = nativeImage.createFromPath(ICON_PATH);
                if (!img.isEmpty()) appIconImg = img;
            }
        } catch (e) { /* ignore */ }
        return appIconImg || undefined;
    }

    const lastNotice = {};
    function notify(title, body, key) {
        const k = key || title + body;
        const now = Date.now();
        if (lastNotice[k] && now - lastNotice[k] < 8000) return;
        lastNotice[k] = now;
        try { if (Notification.isSupported()) new Notification({ title, body, icon: appIcon() }).show(); } catch (e) { /* ignore */ }
    }

    function handleEvent(ev) {
        if (!ev || !ev.type) return;
        if (ev.type === 'app-closing') {
            notify('Focus Guard', `${ev.name} is blocked right now. Save your work - it will be closed in a few seconds.`, 'closing-' + ev.name);
        } else if (ev.type === 'app') {
            notify('Focus Guard', `Blocked app closed: ${ev.name}`, 'app-' + ev.name);
        } else if (ev.type === 'web') {
            notify('Blocked!', `${ev.label || 'This website'} is blocked right now. You can open it again when the timer ends.`, 'web-' + ev.label);
        } else if (ev.type === 'hosts') {
            notify('Focus Guard', 'To fully block websites, run the app as Administrator.', 'hosts-fail');
        }
    }


    function pumpEvents() {
        try {
            const st = fs.statSync(F.events);
            if (st.size < evOffset) evOffset = 0;
            if (st.size > evOffset) {
                const fd = fs.openSync(F.events, 'r');
                const buf = Buffer.alloc(st.size - evOffset);
                fs.readSync(fd, buf, 0, buf.length, evOffset);
                fs.closeSync(fd);
                const lastNl = buf.lastIndexOf(0x0a);
                if (lastNl < 0) return;                       // ekhono puro line ashe nai
                evOffset += lastNl + 1;
                buf.toString('utf8', 0, lastNl + 1).split('\n').filter(Boolean).forEach((l) => {
                    try { handleEvent(JSON.parse(l)); } catch (e) { /* ignore */ }
                });
            }
        } catch (e) { /* file nei */ }
    }

    /* ------------------------------------------------------------------ */
    /*  Custom app name validation (typo dhorar jonno: "crome" -> "Chrome") */
    /* ------------------------------------------------------------------ */
    const INVENTORY_PS = String.raw`$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items = New-Object System.Collections.ArrayList
$shell = New-Object -ComObject WScript.Shell
$dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:AppData\Microsoft\Windows\Start Menu\Programs")
foreach ($d in $dirs) {
    Get-ChildItem -Path $d -Recurse -Filter *.lnk | ForEach-Object {
        $t = $shell.CreateShortcut($_.FullName).TargetPath
        $exe = ''
        if ($t -and $t.ToLower().EndsWith('.exe')) { $exe = [IO.Path]::GetFileName($t) }
        [void]$items.Add(@{ name = $_.BaseName; exe = $exe })
    }
}
Get-StartApps | ForEach-Object { [void]$items.Add(@{ name = $_.Name; exe = ''; appid = [string]$_.AppID }) }
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths')) {
    Get-ChildItem $k | ForEach-Object { $n = $_.PSChildName; [void]$items.Add(@{ name = ($n -replace '\.exe$', ''); exe = $n }) }
}
Get-Process | Select-Object -ExpandProperty ProcessName -Unique | ForEach-Object { [void]$items.Add(@{ name = $_; exe = ($_ + '.exe') }) }
ConvertTo-Json -InputObject @($items) -Compress
`;

    let inventoryCache = { ts: 0, items: [] };
    function runPowerShellScript(scriptText, name, timeout, cb) {
        const opts = { windowsHide: true, maxBuffer: 32 * 1024 * 1024, timeout };
        let file = null;
        try {
            G.ensureDataDir();
            file = P(name);
            fs.writeFileSync(file, scriptText, 'utf8');
        } catch (e) { file = null; }
        if (file) {
            exec(`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${file}"`, opts, cb);
        } else {
            const b64 = Buffer.from(scriptText, 'utf16le').toString('base64');
            exec(`powershell -NoProfile -NonInteractive -EncodedCommand ${b64}`, opts, cb);
        }
    }

    function loadInventory() {
        return new Promise((resolve) => {
            if (inventoryCache.items.length && Date.now() - inventoryCache.ts < 30000) return resolve(inventoryCache.items);
            runPowerShellScript(INVENTORY_PS, 'inventory.ps1', 30000, (err, out) => {
                let items = [];
                try { items = JSON.parse(out); } catch (e) { /* ignore */ }
                if (!Array.isArray(items)) items = [];
                inventoryCache = { ts: Date.now(), items };
                resolve(items);
            });
        });
    }

    const IGNORE_EXE = new Set(['update', 'setup', 'uninstall', 'uninstaller', 'unins000', 'installer', 'msiexec', 'cmd',
        'powershell', 'pwsh', 'explorer', 'rundll32', 'wscript', 'cscript', 'conhost', 'svchost', 'regsvr32', 'mshta']);

    const PFN_RE = /^[A-Za-z0-9.\-]+_[a-z0-9]{13}$/;

    function resolveApp(name, items) {
        const n = norm(name);
        let hits = items.filter((i) => norm(i.name) === n || norm(i.exe) === n);
        if (!hits.length && n.length >= 5) hits = items.filter((i) => norm(i.name).includes(n));
        const procs = [...new Set(hits
            .map((i) => String(i.exe || '').toLowerCase())
            .filter((x) => x.endsWith('.exe') && !IGNORE_EXE.has(norm(x))))];
        const uwp = [...new Set(hits
            .map((i) => String(i.appid || '').split('!')[0])
            .filter((x) => PFN_RE.test(x)))];
        return { found: hits.length > 0, procs, uwp };
    }

    function resolveUwpExes(pfn) {
        return new Promise((resolve) => {
            if (!PFN_RE.test(pfn)) return resolve([]);
            const ps = `$ErrorActionPreference='SilentlyContinue'; $o=@(); Get-AppxPackage -PackageFamilyName '${pfn}' | ` +
                `ForEach-Object { $m = Get-AppxPackageManifest -Package $_; foreach ($a in @($m.Package.Applications.Application)) ` +
                `{ if ($a.Executable) {$o += [string]$a.Executable } } }; ConvertTo-Json -InputObject @($o) -Compress`;
            exec(`powershell -NoProfile -NonInteractive -Command "${ps}"`, { windowsHide: true, timeout: 20000 }, (err, out) => {
                let arr = [];
                try { arr = JSON.parse(out); } catch (e) { /* ignore */ }
                if (!Array.isArray(arr)) arr = [];
                resolve([...new Set(arr
                    .map((x) => path.win32.basename(String(x)).toLowerCase())
                    .filter((x) => x.endsWith('.exe') && !IGNORE_EXE.has(norm(x))))]);
            });
        });
    }

    function editDistance(a, b) {
        const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
        for (let j = 1; j <= b.length; j++) dp[0][j] = j;
        for (let i = 1; i <= a.length; i++) {
            for (let j = 1; j <= b.length; j++) {
                dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
            }
        }
        return dp[a.length][b.length];
    }

    function suggestApp(name, items) {
        const n = norm(name);
        let best = null;
        let bestD = 99;
        items.forEach((i) => {
            const cand = norm(i.name);
            if (cand.length < 3) return;
            const d = editDistance(n, cand);
            if (d < bestD) { bestD = d; best = i.name; }
        });
        return bestD <= Math.max(1, Math.floor(n.length / 4)) ? best : null;
    }

    function saveAlias(name, procs) {
        if (!procs.length) return;
        try {
            G.ensureDataDir();
            const cur = G.readJson(F.aliases) || {};
            cur[norm(name)] = procs;
            G.writeAtomic(F.aliases, JSON.stringify(cur));
        } catch (e) { console.error('alias save failed:', e.message); }
    }

    function trustedSender(e) {
        try {
            if (!mainWindow || mainWindow.isDestroyed() || e.sender !== mainWindow.webContents) return false;
            const url = (e.senderFrame && e.senderFrame.url) || e.sender.getURL();
            return /^file:\/\//i.test(url);
        } catch (err) { return false; }
    }

    ipcMain.handle('validate-app', async (e, rawName) => {
        if (!trustedSender(e)) return { ok: false, message: 'Not allowed' };
        if (typeof rawName !== 'string') return { ok: false, message: 'Invalid name' };
        const name = rawName.trim().replace(/\s+/g, ' ').slice(0, 24);
        if (!IS_WIN || !name) return { ok: true };
        const items = await loadInventory();
        if (!items.length) return { ok: true };
        const r = resolveApp(name, items);
        if (!r.found) {
            const s = suggestApp(name, items);
            return {
                ok: false,
                message: `No app named "${name}" was found on this PC.` +
                    (s ? ` Did you mean "${s}"?` : ' Check the spelling, or open the app once and try again.')
            };
        }
        let procs = r.procs;
        if (!procs.length && r.uwp.length) procs = await resolveUwpExes(r.uwp[0]);
        saveAlias(name, procs);
        return { ok: true };
    });

    const HOOK_JS = String.raw`(function () {
  if (window.__cbHook) return;
  window.__cbHook = true;
  var api = window.cbApi;
  var input = document.getElementById('new-app-name');
  var btn = document.getElementById('add-app-btn');
  if (!api || !input || !btn) return;
  var bypass = false, busy = false;
  function isCatalog(name) {
    var lower = name.toLowerCase();
    return CATALOG.some(function (c) {
      return c.label.toLowerCase() === lower || c.key.toLowerCase() === lower || (c.key === 'X' && lower === 'twitter');
    });
  }
  function proceed() { bypass = true; try { btn.click(); } finally { bypass = false; } }
  function handle(e) {
    if (bypass) return;
    var name = input.value.trim().replace(/\s+/g, ' ');
    if (!name || name.length > 24 || isCatalog(name)) return;
    e.stopImmediatePropagation();
    e.preventDefault();
    if (busy) return;
    busy = true;
    showAppError('Checking app...');
    api.validateApp(name).then(function (res) {
      busy = false;
      if (res && res.ok) { showAppError(''); proceed(); }
      else showAppError((res && res.message) || 'App not found');
    }).catch(function () { busy = false; proceed(); });
  }
  document.addEventListener('click', function (e) {
    if (e.target && e.target.closest && e.target.closest('#add-app-btn')) handle(e);
  }, true);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && e.target === input) handle(e);
  }, true);
})();`;

    /* ------------------------------------------------------------------ */
    /*  Window                                                             */
    /* ------------------------------------------------------------------ */
    function showWindow() {
        if (!mainWindow) { createWindow(); return; }
        hiddenForLock = false;
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.show();
        mainWindow.focus();
    }

    function ensureTray() {
        if (tray) return;
        try {
            if (!fs.existsSync(ICON_PATH)) return;
            const img = nativeImage.createFromPath(ICON_PATH);
            if (img.isEmpty()) return;
            tray = new Tray(img);
            tray.setToolTip('Focus Guard');
            tray.on('click', showWindow);
            tray.setContextMenu(Menu.buildFromTemplate([
                { label: 'Open Focus Guard', click: showWindow },
                {
                    label: 'Quit',
                    click: () => {
                        if (isBlockingActive) {
                            notify('Focus Guard', `Blocking is still active until ${fmtTime(latestEndAt)}. You can't quit before the timer ends.`, 'quit-denied');
                        } else {
                            quitting = true;
                            app.quit();
                        }
                    }
                }
            ]));
        } catch (e) { console.error('tray failed:', e.message); }
    }

    function hideToBackground() {
        if (!mainWindow) return;
        ensureTray();
        hiddenForLock = true;
        mainWindow.hide();
        notify('Focus Guard is still running',
            `Blocking continues in the background until ${fmtTime(latestEndAt)}.` + (tray ? ' Click the tray icon to reopen.' : ' Launch the app again to reopen.'),
            'bg-running');
    }

    function createWindow() {
        mainWindow = new BrowserWindow({
            width: 1100,
            height: 750,
            icon: appIcon(),
            webPreferences: {
                preload: path.join(__dirname, 'preload.js'),
                nodeIntegration: false,
                contextIsolation: true,
                sandbox: true,
                webSecurity: true,
                devTools: !app.isPackaged,
                backgroundThrottling: false
            }
        });

        try { const ic = appIcon(); if (ic) mainWindow.setIcon(ic); } catch (e) { /* ignore */ }
        mainWindow.removeMenu();   // File/Edit/View/Window menu bar (sada ongsho) bad
        mainWindow.loadFile('index.html');
        mainWindow.webContents.on('did-finish-load', () => {
            mainWindow.webContents.executeJavaScript(HOOK_JS).catch((e) => console.error('hook failed:', e.message));
        });

        mainWindow.webContents.on('render-process-gone', () => {
            try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.reload(); } catch (e) { /* ignore */ }
        });
        mainWindow.on('unresponsive', () => {
            try { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.reload(); } catch (e) { /* ignore */ }
        });

        mainWindow.webContents.on('devtools-opened', () => {
            if (isBlockingActive) mainWindow.webContents.closeDevTools();
        });

        mainWindow.on('close', (e) => {
            if (isBlockingActive && !quitting) {
                e.preventDefault();
                hideToBackground();
            }
        });

        mainWindow.on('closed', () => { mainWindow = null; });
    }

    /* ------------------------------------------------------------------ */
    /*  Admin check / auto-elevate                                         */
    /* ------------------------------------------------------------------ */
    function relaunchElevated() {
        return new Promise((resolve) => {
            const q = (s) => String(s).replace(/'/g, "''");
            const argList = app.isPackaged ? '' : ` -ArgumentList '"${q(app.getAppPath())}"'`;
            const cmd = `Start-Process -FilePath '${q(process.execPath)}'${argList} -WorkingDirectory '${q(process.cwd())}' -Verb RunAs`;
            // -EncodedCommand: quote/space niye kono escape jhamela nei (path e space thakleo thik thake)
            const b64 = Buffer.from(cmd, 'utf16le').toString('base64');
            exec(`powershell -NoProfile -EncodedCommand ${b64}`, { windowsHide: true }, (err) => resolve(!err));
        });
    }

    /* ------------------------------------------------------------------ */
    /*  State file + guardian management                                   */
    /* ------------------------------------------------------------------ */
    const ruleKey = (r) => r.kind + '|' + norm(r.target);
    function mergeRules(stored, fresh, now) {
        const map = new Map();
        (stored || []).forEach((r) => { if (r && r.endAt > now) map.set(ruleKey(r), r); });
        (fresh || []).forEach((r) => {
            if (!r || !(r.endAt > now)) return;
            const k = ruleKey(r);
            const old = map.get(k);
            if (!old || r.endAt >= old.endAt) map.set(k, r);
        });
        return [...map.values()];
    }

    function writeStateIfChanged(rules) {
        const sig = JSON.stringify(rules);
        if (sig === stateSig) return;
        stateSig = sig;
        if (!G.writeAtomic(F.state, JSON.stringify({ rules, launch: launchInfo(), updatedAt: Date.now() }))) {
            console.error('state write failed');
        }
    }

    function heartbeatUI() {
        G.writeAtomic(F.uiPid, JSON.stringify({ pid: process.pid, ts: Date.now() }));
    }

    function guardianAlive() {
        try {
            const d = G.readJson(F.guardPid);
            if (!d || !d.pid || Math.abs(Date.now() - d.ts) > 6000) return false;
            try { process.kill(d.pid, 0); } catch (e) { if (e.code !== 'EPERM') return false; }
            return true;
        } catch (e) { return false; }
    }

    function startGuardianDirect(extraArgs) {
        try {
            G.ensureDataDir();
            const l = launchInfo();
            spawn(l.exe, l.args.concat(extraArgs && extraArgs.length ? extraArgs : ['--guardian']), {
                detached: true,
                stdio: 'ignore',
                windowsHide: true,
                cwd: l.cwd
            }).unref();
        } catch (e) { console.error('guardian start failed:', e.message); }
    }

    let guardianTries = 0;
    function ensureGuardian() {
        if (!IS_WIN) return;
        if (guardianAlive()) { guardianTries = 0; return; }
        const now = Date.now();
        if (now - lastGuardianStart < 8000) return;
        lastGuardianStart = now;
        guardianTries++;



        if (!adminOk || guardianTries > 1) startGuardianDirect();
        if (adminOk) {
            G.installTasks(launchInfo()).then((ok) => {
                if (ok) G.schtasks('/Run /TN "ComebackGuardian"');
            });
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Sync loop                                                          */
    /* ------------------------------------------------------------------ */
    async function readRules() {
        if (!mainWindow || mainWindow.isDestroyed() || mainWindow.webContents.isLoading()) return null;
        try {
            const json = await mainWindow.webContents.executeJavaScript(
                'window.FocusBlocker ? JSON.stringify(window.FocusBlocker.getActiveRules()) : "[]"', true);
            const arr = JSON.parse(json);
            return Array.isArray(arr) ? arr : null;
        } catch (e) { return null; }
    }

    function restoreInRenderer(rules, off) {
        if (!mainWindow || mainWindow.isDestroyed()) return;
        const t = Date.now();
        const todo = rules.filter((r) => {
            const k = ruleKey(r);
            if (restoreTried.get(k) && t - restoreTried.get(k) < 15000) return false;
            restoreTried.set(k, t);
            return true;
        });
        if (!todo.length) return;
        const local = todo.map((r) => Object.assign({}, r, { endAt: r.endAt - off }));
        const lit = JSON.stringify(JSON.stringify(local));
        mainWindow.webContents.executeJavaScript(
            `window.FocusBlocker && window.FocusBlocker.restore ? window.FocusBlocker.restore(JSON.parse(${lit})) : 0`, true
        ).catch((e) => console.error('restore failed:', e.message));
    }

    async function syncLoop() {
        if (syncBusy) return;
        syncBusy = true;
        try {
            heartbeatUI();
            pumpEvents();
            const fresh = await readRules();
            if (fresh === null) return;

            const off = G.clockOffset();
            const freshTrusted = off ? fresh.map((r) => Object.assign({}, r, { endAt: r.endAt + off }, r.breakUntil ? { breakUntil: r.breakUntil + off } : {})) : fresh;
            const merged = mergeRules(G.readState().rules, freshTrusted, G.nowMs());
            writeStateIfChanged(merged);
            const inUi = new Set(fresh.map(ruleKey));
            const missing = merged.filter((r) => !inUi.has(ruleKey(r)));
            if (missing.length) restoreInRenderer(missing, off);
            isBlockingActive = merged.length > 0;
            const prevEnd = latestEndAt;
            latestEndAt = merged.reduce((m, r) => Math.max(m, r.endAt || 0), 0);

            if (hiddenForLock && !isBlockingActive) {
                notify('Focus Guard', 'Timer finished. Great job staying focused!', 'done');
                quitting = true;
                setTimeout(() => app.quit(), 1500);
                return;
            }
            if (!latestEndAt) latestEndAt = prevEnd;

            if (IS_WIN) {
                if (merged.length) {
                    ensureGuardian();
                } else if (!startupCleanDone) {
                    startupCleanDone = true;
                    startGuardianDirect(['--cleanup']);
                }
            }
        } catch (e) {
            console.error('sync error:', e.message);
        } finally {
            syncBusy = false;
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Lifecycle                                                          */
    /* ------------------------------------------------------------------ */
    app.on('before-quit', () => {
        quitting = true;
        if (!isBlockingActive) { try { fs.unlinkSync(F.uiPid); } catch (e) { /* ignore */ } }
    });

    app.on('window-all-closed', () => {
        if (process.platform !== 'darwin') app.quit();
    });

    app.on('web-contents-created', (event, contents) => {
        contents.on('will-navigate', (e) => e.preventDefault());
        contents.setWindowOpenHandler(() => ({ action: 'deny' }));
    });

    app.whenReady().then(async () => {
        app.setAppUserModelId('com.focusguard.app');
        try { session.defaultSession.setPermissionRequestHandler((wc, permission, cb) => cb(false)); } catch (e) { /* ignore */ }

        if (IS_WIN) {
            adminOk = G.isAdminSync();
            if (!adminOk) {
                const ok = await relaunchElevated();
                if (ok) { quitting = true; app.quit(); return; }
                dialog.showMessageBoxSync({
                    type: 'warning',
                    title: 'Focus Guard',
                    message: 'Administrator permission needed',
                    detail: 'Permission was not granted, so full website blocking (hosts file) and auto-restart will not work. App blocking and browser tab blocking will still run, but closing the app from Task Manager will stop the blocking.',
                    buttons: ['OK']
                });
            }
        }

        if (!app.requestSingleInstanceLock()) { quitting = true; app.quit(); return; }
        app.on('second-instance', () => showWindow());

        try {
            G.ensureDataDir();
            try { evOffset = fs.statSync(F.events).size; } catch (e) { evOffset = 0; }
        } catch (e) { console.error(e.message); }

        createWindow();
        heartbeatUI();
        setInterval(syncLoop, 1000);

        try {
            powerMonitor.on('resume', () => {
                if (mainWindow && !mainWindow.isDestroyed()) {
                    mainWindow.webContents.executeJavaScript('window.__cbResumeAt = Date.now()', true).catch(() => { /* ignore */ });
                }
            });
        } catch (e) { console.error('powerMonitor failed:', e.message); }

        app.on('activate', () => {
            if (BrowserWindow.getAllWindows().length === 0) createWindow();
        });
    });
}