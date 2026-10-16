'use strict';
/*
 * Dev mode (npm start) e Windows taskbar / notification e "Electron" er bodole "Focus Guard" dekhanor jonno
 * node_modules/electron/dist/electron.exe er metadata (FileDescription, ProductName) change kore.
 * Packaged build (npm run build) e eta dorkar nei - electron-builder nije kore.
 * Electron bondho obosthay chalate hobe, na hole file locked thakbe (tokhon skip kore, start e problem hobe na).
 */
const fs = require('fs');

const NAME = 'Focus Guard';

async function main() {
    if (process.platform !== 'win32') return;

    let exe;
    try { exe = require('electron'); } catch (e) { return; }
    if (typeof exe !== 'string' || !fs.existsSync(exe)) return;

    let rcedit;
    try {
        const m = require('rcedit');
        rcedit = m.rcedit || m.default || m;
    } catch (e) {
        const m = await import('rcedit');
        rcedit = m.rcedit || m.default;
    }

    await rcedit(exe, {
        'version-string': {
            FileDescription: NAME,
            ProductName: NAME,
            InternalName: NAME,
            OriginalFilename: NAME + '.exe',
            CompanyName: NAME
        }
    });
    console.log('[set-dev-name] electron.exe metadata ->', NAME);
}

main().catch((e) => {
    console.warn('[set-dev-name] skipped:', e && e.message ? e.message : e);
});