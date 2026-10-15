'use strict';




const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cbApi', Object.freeze({
    validateApp: (name) => ipcRenderer.invoke('validate-app', String(name == null ? '' : name).slice(0, 64))
}));