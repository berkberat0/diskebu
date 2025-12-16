const { contextBridge, ipcRenderer } = require("electron");

// Window controls
contextBridge.exposeInMainWorld("controls", {
  minimize: () => ipcRenderer.send("win-min"),
  maximize: () => ipcRenderer.send("win-max"),
  close: () => ipcRenderer.send("win-close")
});

// Dialogs
contextBridge.exposeInMainWorld("dialog", {
  alert: (message) => ipcRenderer.sendSync("show-alert", message),
  confirm: (message) => ipcRenderer.sendSync("show-confirm", message),
  prompt: async (message, defaultValue = "") => {
    const result = await ipcRenderer.invoke("show-prompt", message, defaultValue);
    return result; // string veya null
  }
});

// Override global alert/confirm/prompt
window.alert = (msg) => window.dialog.alert(msg);
window.confirm = (msg) => window.dialog.confirm(msg);
window.prompt = (msg, def) => window.dialog.prompt(msg, def);
