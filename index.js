const { app, BrowserWindow, BrowserView, ipcMain, dialog } = require('electron');
const path = require('path');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library'); // 🔑 YENİ EKLENDİ

let checkWindow = null;

// ------------------------------------
// GOOGLE AUTH AYARLARI 🔑
// ------------------------------------
// 🚨 BURAYI KENDİ CLIENT ID'NİZ İLE DEĞİŞTİRİN
const GOOGLE_CLIENT_ID = '1060101852132-krfeafcdco40np9h0pirl8njusi3uikp.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);


// ------------------------------------
// CHECK WINDOW (Discord update tarzı)
// ------------------------------------
function createCheckWindow() {
  checkWindow = new BrowserWindow({
    width: 350,
    height: 400,
    frame: false,
    resizable: false,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  checkWindow.loadFile("check.html");
}

// ------------------------------------
// MAIN APPLICATION WINDOW
// ------------------------------------
function createWindow() {
  const iconPath = process.platform === "win32"
  ? path.join(__dirname, "favicon.ico")   // Windows
  : path.join(__dirname, "favicon.png"); // Linux
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    frame: false,
    titleBarStyle: "hidden",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
                                contextIsolation: true,
                                nodeIntegration: false
    },
    icon: iconPath
  });

  win.maximize();

  // Title bar
  win.loadFile("titlebar.html");

  // Browser view
  const view = new BrowserView({
    webPreferences: {
      contextIsolation: true,
      preload: path.join(__dirname, "preload.js"),
                               nodeIntegration: false
    }
  });

  win.setBrowserView(view);

  const titleBarHeight = 25;
  const [width, height] = win.getContentSize();

  view.setBounds({
    x: 0,
    y: titleBarHeight,
    width: width,
    height: height - titleBarHeight
  });

  view.setAutoResize({ width: true, height: true });

  view.webContents.setUserAgent("dkwebpc");
  view.webContents.loadURL("https://sibyl-globate-unmannishly.ngrok-free.dev");

  win.on('resize', () => {
    const [w, h] = win.getContentSize();
    view.setBounds({
      x: 0,
      y: titleBarHeight,
      width: w,
      height: h - titleBarHeight
    });
  });

  // Window controls
  ipcMain.on("win-min", () => win.minimize());
  ipcMain.on("win-max", () => win.isMaximized() ? win.unmaximize() : win.maximize());
  ipcMain.on("win-close", () => win.close());

  // Alerts
  ipcMain.on("show-alert", (event, message) => {
    dialog.showMessageBoxSync(win, {
      type: "info",
      message: message,
      buttons: ["OK"]
    });
    event.returnValue = true;
  });

  ipcMain.on("show-confirm", (event, message) => {
    const result = dialog.showMessageBoxSync(win, {
      type: "question",
      message: message,
      buttons: ["OK", "Cancel"],
      defaultId: 0,
        cancelId: 1
    });
    event.returnValue = result === 0;
  });

  // Prompt
  ipcMain.handle("show-prompt", async (event, message, defaultValue) => {
    const promptWin = new BrowserWindow({
      parent: win,
      modal: true,
      show: false,
      width: 400,
      height: 180,
      resizable: false,
      minimizable: false,
      maximizable: false,
      webPreferences: {
        nodeIntegration: true,
        contextIsolation: false
      }
    });

    promptWin.loadURL(`data:text/html,
                      <html>
                      <body style="font-family:sans-serif; display:flex; flex-direction:column; justify-content:center; align-items:center; height:100%; margin:0;">
                      <div style="margin-bottom:10px;">${message}</div>
                      <input id="input" value="${defaultValue}" style="width:90%; margin-bottom:10px;" />
                      <div>
                      <button onclick="require('electron').ipcRenderer.send('prompt-response', document.getElementById('input').value); window.close();">OK</button>
                      <button onclick="require('electron').ipcRenderer.send('prompt-response', null); window.close();">Cancel</button>
                      </div>
                      </body>
                      </html>`);

    promptWin.once('ready-to-show', () => promptWin.show());

    return new Promise(resolve => {
      ipcMain.once('prompt-response', (event, value) => {
        resolve(value);
      });
    });
  });
}

// ------------------------------------
// CONNECTION CHECK LOGIC
// ------------------------------------
ipcMain.handle("check-site", async () => {
  try {
    await axios.get("https://sibyl-globate-unmannishly.ngrok-free.dev", {
      timeout: 3000
    });
    return true;
  } catch (e) {
    return false;
  }
});

// Start main window when check OK
ipcMain.on("start-main", () => {
  createWindow();
  if (checkWindow) checkWindow.close();
});

// ------------------------------------
// GOOGLE AUTH LOGIC (JWT Doğrulama) 🔑 YENİ EKLENDİ
// ------------------------------------
ipcMain.handle('google-login-token', async (event, token) => {
  try {
    // 1. JWT Token'ı Doğrulama
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID, // Token'ın bu istemci için olduğunu kontrol eder
    });

    // 2. Kullanıcı Bilgilerini Çıkarma
    const payload = ticket.getPayload();

    const googleId = payload.sub; // Google'ın benzersiz kullanıcı kimliği
    const email = payload.email; // Kullanıcının e-posta adresi
    const name = payload.name;   // Kullanıcının adı

    console.log(`Giriş Yapmaya Çalışan Kullanıcı: ${email}`);

    // 3. Veritabanı İşlemleri (Kullanıcıyı bul veya kaydet)
    const user = await findOrCreateUser(googleId, email, name);

    // 4. Başarılı Yanıt Döndürme
    return {
      success: true,
      userId: user.id
    };

  } catch (error) {
    console.error("GOOGLE AUTH VEYA VERİTABANI HATASI:", error);
    return { success: false, message: "Giriş sırasında sunucu hatası oluştu." };
  }
});

// ------------------------------------
// VERITABANI İŞLEVİ (Placeholder) 🔑 YENİ EKLENDİ
// ------------------------------------
// 🚨 BURAYI DOLDURUN: Basit bir dosya tabanlı kayıt sistemi kullanabiliriz.
async function findOrCreateUser(googleId, email, name) {
  // Bu kısım, kullanıcıyı veritabanınıza (veya bir dosyaya) kaydetme/bulma mantığınızdır.

  // Konsola Kayıt Bilgisi
  console.log(`[DB SIMÜLASYONU] Kullanıcı kaydı/girişi başarılı: ${email}`);

  // Uygulamanın kullanabileceği bir kullanıcı kimliği döndürülür.
  return { id: googleId, email: email };
}


// ------------------------------------
// APP START
// ------------------------------------
app.whenReady().then(() => {
  createCheckWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
