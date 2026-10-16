'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

if (process.platform !== 'win32') { console.log('Skipped (Windows only).'); process.exit(0); }

const root = path.join(__dirname, '..');
const exe = path.join(root, 'node_modules', 'electron', 'dist', 'electron.exe');
const ico = path.join(root, 'focusguard.ico');
const bin = path.join(root, 'node_modules', 'rcedit', 'bin', process.arch === 'ia32' ? 'rcedit.exe' : 'rcedit-x64.exe');

const missing = [['electron.exe', exe], ['focusguard.ico', ico], ['rcedit', bin]].find(([, p]) => !fs.existsSync(p));
if (missing) {
    console.error(missing[0] + ' not found: ' + missing[1]);
    if (missing[0] === 'rcedit') console.error('Run this first:  npm install');
    process.exit(1);
}

try {
    execFileSync(bin, [exe, '--set-icon', ico], { stdio: 'inherit' });
    console.log('Done. Start the app again with: npm start');
} catch (e) {
    console.error('Failed. Close every running Focus Guard / electron.exe (also in Task Manager) and try again.\n' + e.message);
    process.exit(1);
}