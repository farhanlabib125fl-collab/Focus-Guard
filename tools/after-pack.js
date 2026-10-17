'use strict';
/*
 * electron-builder er afterPack hook: packaged "Focus Guard.exe" er metadata (FileDescription, ProductName)
 * jore "Focus Guard" kore dey, jate Windows taskbar / notification e "Electron" na dekhay.
 * (electron-builder er nijer rcedit step Windows e kokhono silently skip hoye jay.)
 */
const fs = require('fs');
const path = require('path');

const NAME = 'Focus Guard';

async function loadRcedit() {
    try {
        const m = require('rcedit');
        return m.rcedit || m.default || m;
    } catch (e) {
        const m = await import('rcedit');
        return m.rcedit || m.default;
    }
}

module.exports = async function afterPack(context) {
    if (context.electronPlatformName !== 'win32') return;

    const exeName = (context.packager.appInfo.productFilename || NAME) + '.exe';
    const exePath = path.join(context.appOutDir, exeName);
    if (!fs.existsSync(exePath)) throw new Error('[after-pack] exe not found: ' + exePath);

    const rcedit = await loadRcedit();
    const opts = {
        'version-string': {
            FileDescription: NAME,
            ProductName: NAME,
            InternalName: NAME,
            OriginalFilename: exeName,
            CompanyName: NAME
        }
    };
    const ico = path.join(context.packager.projectDir, 'focusguard.ico');
    if (fs.existsSync(ico)) opts.icon = ico;

    await rcedit(exePath, opts);
    console.log('  • [after-pack] exe metadata set to "' + NAME + '":', exeName);
};