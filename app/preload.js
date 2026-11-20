const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('xdis', {
    call: (req) => ipcRenderer.invoke('rpc', req),
    pickFile: (opts) => ipcRenderer.invoke('pick-file', opts),
    saveFile: (opts) => ipcRenderer.invoke('save-file', opts),
    writeText: (filePath, text) => ipcRenderer.invoke('write-text', { filePath, text }),
    readText: () => ipcRenderer.invoke('read-text'),
    loadPrefs: () => ipcRenderer.invoke('load-prefs'),
    savePrefs: (obj) => ipcRenderer.invoke('save-prefs', obj),
    runScript: (code, curVa) => ipcRenderer.invoke('run-script', { code, curVa }),
    runPython: (code, curVa) => ipcRenderer.invoke('run-python', { code, curVa }),
    exportReport: (filePath, fmt) => ipcRenderer.invoke('export-report', { filePath, fmt }),
    initialFile: () => ipcRenderer.invoke('initial-file'),
    filePath: (file) => webUtils.getPathForFile(file),
    setTitleColors: (bg, fg) => ipcRenderer.send('title-colors', { bg, fg }),
    collabHost: (opts) => ipcRenderer.invoke('collab-host', opts),
    collabJoin: (opts) => ipcRenderer.invoke('collab-join', opts),
    collabSend: (msg) => ipcRenderer.invoke('collab-send', msg),
    collabStop: () => ipcRenderer.invoke('collab-stop'),
    collabStatus: () => ipcRenderer.invoke('collab-status'),
    onCollabEvent: (cb) => {
        const fn = (_, ev) => cb(ev);
        ipcRenderer.on('collab-event', fn);
        return () => ipcRenderer.removeListener('collab-event', fn);
    }
});
