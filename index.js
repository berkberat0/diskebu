import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from 'bcryptjs';
import http from "http";
import https from "https";
import ngrok from '@ngrok/ngrok'
import { WebSocketServer } from "ws";
import crypto from "crypto";
import { fileURLToPath } from "url";
import 'dotenv/config';
import * as db from './db.js';

// Read configuration from .env
const SECRET = process.env.JWT_SECRET || "lkasjvdşlkashrşlkashvdşalvdh4a564vea6w4e465şifre31";
const JWT_EXPIRATION = process.env.JWT_EXPIRATION || "30d";
const MIN_PASSWORD_LENGTH = parseInt(process.env.MIN_PASSWORD_LENGTH) || 5;
// Deterministic encryption key used for message persistence
const ENC_KEY = crypto.createHash('sha256').update(SECRET).digest();

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, iv);
    let enc = cipher.update(text, "utf8", "hex");
    enc += cipher.final("hex");
    return { iv: iv.toString('hex'), enc };
}
function decrypt(enc, ivHex) {
    try {
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, iv);
        let dec = decipher.update(enc, "hex", "utf8");
        dec += decipher.final("utf8");
        return dec;
    } catch (e) {
        try { return Buffer.from(enc, 'hex').toString('utf8'); } catch (_) { return enc; }
    }
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const AVATARS_DIR = path.join(__dirname, "avatars");
const PHOTOS_DIR = path.join(__dirname, "photos");

// Ensure directories exist
if (!fs.existsSync(AVATARS_DIR)) fs.mkdirSync(AVATARS_DIR);
if (!fs.existsSync(PHOTOS_DIR)) fs.mkdirSync(PHOTOS_DIR);

// In-memory cache for voice channel users (not persisted to DB)
const voiceUsers = {};

// Message cleanup configuration
const MESSAGE_RETENTION_DAYS = parseInt(process.env.MESSAGE_RETENTION_DAYS || '150', 10);
const CLEANUP_INTERVAL_HOURS = 3;

// Cleanup old messages and their photos
function cleanupOldMessages() {
    if (MESSAGE_RETENTION_DAYS <= 0) {
        console.log('Message cleanup disabled (MESSAGE_RETENTION_DAYS = 0)');
        return;
    }

    try {
        const cutoffTimestamp = Date.now() - (MESSAGE_RETENTION_DAYS * 24 * 60 * 60 * 1000);
        console.log(`Starting message cleanup. Deleting messages older than ${MESSAGE_RETENTION_DAYS} days...`);

        // First, get all old messages with photos to delete the photo files
        const messagesWithPhotos = db.getOldMessagesWithPhotos(cutoffTimestamp);
        let photosDeleted = 0;

        messagesWithPhotos.forEach(msg => {
            if (msg.photo) {
                const photoPath = path.join(PHOTOS_DIR, msg.photo);
                try {
                    if (fs.existsSync(photoPath)) {
                        fs.unlinkSync(photoPath);
                        photosDeleted++;
                    }
                } catch (e) {
                    console.warn(`Failed to delete photo ${msg.photo}:`, e.message);
                }
            }
        });

        // Now delete all old messages from database
        const result = db.deleteOldMessages(cutoffTimestamp);

        console.log(`Message cleanup complete. Deleted ${result.changes} messages and ${photosDeleted} photos.`);
    } catch (e) {
        console.error('Message cleanup error:', e);
    }
}

// Run cleanup on startup
setTimeout(() => cleanupOldMessages(), 5000); // 5 second delay after startup

// Schedule cleanup every 3 hours
if (MESSAGE_RETENTION_DAYS > 0) {
    setInterval(() => cleanupOldMessages(), CLEANUP_INTERVAL_HOURS * 60 * 60 * 1000);
}

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, "../frontend")));
// For development / compatibility we serve avatars and photos statically so
// browser <img> and CSS background-image work without special fetch logic.
// Note: this relaxes the strict access checks implemented in the secure
// endpoints above. For production consider using signed URLs or cookie-based
// auth so images can be requested directly from <img> tags while remaining secure.
// Do NOT expose avatars/photos via plain static middleware here. We will
// serve them via authenticated handlers below which accept either a valid
// JWT or a short-lived signed URL. This prevents unauthenticated access.
// (If you are in rapid dev and rely on static files, you can re-enable
// static serving temporarily, but production should use the secure handlers.)


// Helper to create a short-lived signature for a file
function makeFileSig(file, expires) {
    return crypto.createHmac('sha256', SECRET).update(`${file}:${expires}`).digest('hex');
}
// Return a short-lived signed URL for an avatar (caller must be requester or share a guild)
app.get('/sign/avatar/:file', (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('No');
    let requester;
    try { requester = jwt.verify(token, SECRET).username; } catch (e) { return res.status(401).send('No'); }

    // Rate limit: 60 per 60s
    if (!rateLimit(req, res, 'signAvatar', 60)) return;

    const file = req.params.file;
    if (!file || !isValidFilename(file)) return res.status(400).send('Bad request');
    if (file === 'default.png') return res.json({ url: `/avatars/${file}` });

    const requesterUser = db.getUserByUsername(requester);
    if (!requesterUser) return res.status(403).send('Forbidden');

    const parts = file.split('_');
    if (parts.length < 2) return res.status(403).send('Forbidden');
    // Handle guild icons named like: guild_<guildId>_<ts>.<ext>
    if (parts[0] === 'guild' && parts.length >= 2) {
        const gid = parts[1];
        const guild = db.getGuildById(gid);
        if (guild && db.isGuildMember(gid, requesterUser.id)) {
            const expires = Date.now() + 60 * 1000; // 60s
            const sig = makeFileSig(file, expires);
            return res.json({ url: `/avatars/${file}?expires=${expires}&sig=${sig}`, expires });
        }
        return res.status(403).send('Forbidden');
    }
    const ownerUsername = parts[0];
    const ownerUser = db.getUserByUsername(ownerUsername);
    if (!ownerUser) return res.status(403).send('Forbidden');
    if (!(ownerUser.id === requesterUser.id || sharesGuild(ownerUser.id, requesterUser.id))) return res.status(403).send('Forbidden');

    const expires = Date.now() + 60 * 1000; // 60s
    const sig = makeFileSig(file, expires);
    res.json({ url: `/avatars/${file}?expires=${expires}&sig=${sig}`, expires });
});

// Return a short-lived signed URL for a photo (caller must be member of guild containing the photo)
app.get('/sign/photo/:file', (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('No');
    let requester;
    try { requester = jwt.verify(token, SECRET).username; } catch (e) { return res.status(401).send('No'); }

    // Rate limit: 60 per 60s
    if (!rateLimit(req, res, 'signPhoto', 60)) return;

    const file = req.params.file;
    if (!file || !isValidFilename(file)) return res.status(400).send('Bad request');

    const requesterUser = db.getUserByUsername(requester);
    if (!requesterUser) return res.status(403).send('Forbidden');

    // Find which guild contains this photo
    const foundGuildId = db.getPhotoGuild(file);
    if (!foundGuildId) return res.status(404).send('Not found');

    // requester must be member of that guild
    if (!db.isGuildMember(foundGuildId, requesterUser.id)) return res.status(403).send('Forbidden');

    const expires = Date.now() + 60 * 1000; // 60s
    const sig = makeFileSig(file, expires);
    res.json({ url: `/photos/${file}?expires=${expires}&sig=${sig}`, expires });
});
app.use('/guilds', express.static(path.join(__dirname, '../backend/guilds')));

// Global error handler
process.on('uncaughtException', function (err) {
    console.error('UNCAUGHT EXCEPTION:', err);
});
process.on('unhandledRejection', function (err) {
    console.error('UNHANDLED REJECTION:', err);
});

// Try to start HTTPS if certificate/key provided (useful for LAN mobile access)
const certDir = __dirname;
function createServerWithOptionalHttps() {
    const certPath = path.join(certDir, 'localhost.pem');
    const keyPath = path.join(certDir, 'localhost-key.pem');

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        try {
            const cert = fs.readFileSync(certPath);
            const key = fs.readFileSync(keyPath);
            console.log("HTTPS hazır. localhost:3000");
            return https.createServer({ cert, key }, app);
        } catch (e) {
            console.error("HTTPS load error, falling back to HTTP:", e);
        }
    }

    return http.createServer(app);
}
const server = createServerWithOptionalHttps();
const wss = new WebSocketServer({ server });

// Ping/pong keepalive - prevents idle connection drops
const WS_PING_INTERVAL = 30000; // 30 seconds
setInterval(() => {
    wss.clients.forEach(ws => {
        if (ws.isAlive === false) {
            console.log('Terminating unresponsive WebSocket');
            return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
    });
}, WS_PING_INTERVAL);

let onlineWS = {};
let typingUsers = {}; // Track typing users per guild/channel
// Simple in-memory rate limiters (sufficient for small deployments)
const ipActionMap = new Map(); // key: ip:action -> { count, firstTs, blockedUntil }
const inviteBruteMap = new Map(); // key: ip -> { count, firstTs, blockedUntil }
const loginAttemptMap = new Map(); // ip -> { count, firstTs, blockedUntil }
const messageRateMap = new Map(); // username -> { timestamps: [], blockedUntil }

function isBlocked(map, key) {
    const entry = map.get(key);
    if (!entry) return false;
    if (entry.blockedUntil && Date.now() < entry.blockedUntil) return true;
    return false;
}

function incrementAction(map, key, windowMs, maxCount, blockMs) {
    const now = Date.now();
    let e = map.get(key);
    if (!e) { e = { count: 1, firstTs: now }; map.set(key, e); return { allowed: e.count <= maxCount } }
    if (e.blockedUntil && now < e.blockedUntil) return { allowed: false, blockedUntil: e.blockedUntil };
    if (now - e.firstTs > windowMs) {
        // reset
        e.count = 1; e.firstTs = now; e.blockedUntil = null; map.set(key, e); return { allowed: true };
    }
    e.count += 1;
    if (e.count > maxCount) {
        e.blockedUntil = now + blockMs;
        map.set(key, e);
        return { allowed: false, blockedUntil: e.blockedUntil };
    }
    map.set(key, e);
    return { allowed: true };
}

// ==================== SECURITY HELPERS ====================

// Rate limit helper - returns true if allowed, sends 429 if blocked
function rateLimit(req, res, action, maxCount, windowMs = 60000, blockMs = 300000) {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const key = `${ip}:${action}`;
    const result = incrementAction(ipActionMap, key, windowMs, maxCount, blockMs);
    if (!result.allowed) {
        res.status(429).send('Çok fazla istek. Lütfen bekleyin.');
        return false;
    }
    return true;
}

// User-based rate limit helper
function userRateLimit(req, res, username, action, maxCount, windowMs = 60000, blockMs = 300000) {
    const key = `${username}:${action}`;
    const result = incrementAction(ipActionMap, key, windowMs, maxCount, blockMs);
    if (!result.allowed) {
        res.status(429).send('Çok fazla istek. Lütfen bekleyin.');
        return false;
    }
    return true;
}

// Path traversal protection - validates filename doesn't contain dangerous patterns
function isValidFilename(filename) {
    if (!filename || typeof filename !== 'string') return false;
    // Block path traversal attempts
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) return false;
    // Block null bytes
    if (filename.includes('\0')) return false;
    // Only allow safe characters
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(filename)) return false;
    return true;
}

// Generate secure invite code using crypto
function generateSecureInviteCode() {
    return crypto.randomBytes(4).toString('hex'); // 8 hex characters = more entropy than Math.random
}

// Warn if default secret is being used
if (SECRET === "WasChatApp_SuperSecretKey_ChangeThisInProduction_2024") {
    console.warn('⚠️  UYARI: Varsayılan JWT secret kullanılıyor! Production için JWT_SECRET ortam değişkenini ayarlayın.');
}


// ------------------- REGISTER -------------------
app.post("/register", (req, res) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    // rate limit account creation per IP: 5 per 60s, block 10 minutes on exceed
    const r = incrementAction(ipActionMap, ip + ':register', 60 * 1000, 5, 10 * 60 * 1000);
    if (!r.allowed) return res.status(429).send('Too many registrations from this IP. Try later.');

    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Eksik alan');
    if (db.getUserByUsername(username)) return res.status(400).send("Kullanıcı zaten var");
    // hash password
    const hashed = bcrypt.hashSync(password, 10);
    const userId = 'U' + crypto.randomBytes(6).toString('hex');
    db.createUser(userId, username, hashed, 'default.png', '');
    res.send("Kayıt başarılı");
    console.log(username + " REGISTERED")
});

// ------------------- LOGIN -------------------
app.post("/login", (req, res) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    // rate limit login attempts per IP: 20 per hour, block 1 hour
    const r = incrementAction(loginAttemptMap, ip + ':login', 60 * 60 * 1000, 20, 60 * 60 * 1000);
    if (!r.allowed) return res.status(429).send('Too many login attempts. Try later.');

    const { username, password } = req.body;
    const u = db.getUserByUsername(username);
    if (!u) return res.status(401).send("Hatalı giriş");

    try {
        // if stored password looks like bcrypt hash, compare accordingly
        if (typeof u.password === 'string' && u.password.startsWith('$2')) {
            if (!bcrypt.compareSync(password, u.password)) return res.status(401).send('Hatalı giriş');
        } else {
            // legacy plain text fallback: on success, re-hash
            if (u.password !== password) return res.status(401).send('Hatalı giriş');
            const newHash = bcrypt.hashSync(password, 10);
            db.updateUserPassword(u.id, newHash);
        }
    } catch (e) {
        return res.status(500).send('Login error');
    }

    const token = jwt.sign({ username }, SECRET, { expiresIn: JWT_EXPIRATION });
    res.json({ token, avatar: u.avatar });
});

// ------------------- UPLOAD AVATAR -------------------
app.post("/upload/avatar", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 10 per 60s
    if (!userRateLimit(req, res, username, 'uploadAvatar', 10)) return;

    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    // Simple base64 avatar upload
    const { avatar } = req.body;
    if (!avatar) return res.status(400).send("Avatar yok");

    try {
        // Check format
        const formatMatch = avatar.match(/^data:image\/(png|jpg|jpeg);base64,/);
        if (!formatMatch) return res.status(400).send("Sadece PNG ve JPG kabul edilir");
        const format = formatMatch[1] === "jpg" ? "jpg" : "png";

        // Decode base64 and check size (max 5MB)
        const base64Data = avatar.replace(/^data:image\/\w+;base64,/, "");
        const buffer = Buffer.from(base64Data, "base64");

        if (buffer.length > 5 * 1024 * 1024) {
            return res.status(400).send("Avatar 5MB'dan küçük olmalı");
        }

        // Remove old avatar if exists
        if (user.avatar && user.avatar !== "default.png") {
            const oldPath = path.join(AVATARS_DIR, user.avatar);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
            }
        }

        // Generate unique filename
        const fileName = username + "_" + Date.now() + "." + format;
        const filePath = path.join(AVATARS_DIR, fileName);

        // Save file
        fs.writeFileSync(filePath, buffer);

        // Update DB
        db.updateUserAvatar(user.id, fileName);

        // Notify shared users about avatar change
        notifySharedUsers(user.id, { type: 'avatarUpdated', user: username, avatar: fileName });

        res.json({ avatar: fileName });
    } catch (e) {
        console.error("Avatar upload error:", e);
        res.status(500).send("Avatar yükleme hatası");
    }
});

// ------------------- DELETE USER AVATAR -------------------
app.delete("/upload/avatar/delete", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 10 per 60s
    if (!userRateLimit(req, res, username, 'deleteAvatar', 10)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        // Delete file if exists
        if (user.avatar && user.avatar !== "default.png") {
            const filePath = path.join(AVATARS_DIR, user.avatar);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }

        db.updateUserAvatar(user.id, "default.png");

        // Notify shared users about avatar removal
        notifySharedUsers(user.id, { type: 'avatarUpdated', user: username, avatar: "default.png" });

        res.send("Avatar kaldırıldı");
    } catch (e) {
        console.error('Delete avatar error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- UPDATE USER BIO -------------------
app.post("/user/bio", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 20 per 60s
    if (!userRateLimit(req, res, username, 'updateBio', 20)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const { bio } = req.body;
        if (!bio && bio !== "") return res.status(400).send("Bio boş");
        if (bio.length > 200) return res.status(400).send("Bio çok uzun (max 200 karakter)");

        db.updateUserBio(user.id, bio);

        // Notify only users who share a guild with this user
        notifySharedUsers(user.id, { type: "userBioUpdated", user: username, bio: bio });

        res.send("Bio güncellendi");
    } catch (e) {
        console.error('Update bio error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- CHANGE PASSWORD -------------------
app.post("/user/password", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 5 per 60s (security critical)
    if (!userRateLimit(req, res, username, 'changePassword', 5)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).send("Eksik alan");
        if (newPassword.length < MIN_PASSWORD_LENGTH) return res.status(400).send(`Şifre en az ${MIN_PASSWORD_LENGTH} karakter olmalı`);

        if (!bcrypt.compareSync(currentPassword, user.password)) return res.status(401).send("Mevcut şifre yanlış");

        db.updateUserPassword(user.id, bcrypt.hashSync(newPassword, 10));
        res.json({ success: true, message: "Şifre değiştirildi" });
    } catch (e) {
        console.error('Change password error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- CHANGE USERNAME -------------------
app.post("/user/username", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 5 per 60s (security critical)
    if (!userRateLimit(req, res, username, 'changeUsername', 5)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const { newUsername } = req.body;
        if (!newUsername) return res.status(400).send("Yeni kullanıcı adı gerekli");
        if (newUsername.length < 2 || newUsername.length > 32) return res.status(400).send("Kullanıcı adı 2-32 karakter olmalı");
        if (!/^[a-zA-Z0-9_]+$/.test(newUsername)) return res.status(400).send("Sadece harf, rakam ve _ kullanılabilir");
        if (db.getUserByUsername(newUsername)) return res.status(400).send("Bu kullanıcı adı zaten alınmış");

        // Rename avatar file if exists
        const oldAvatar = user.avatar;
        let newAvatar = oldAvatar;
        if (oldAvatar && oldAvatar !== "default.png" && oldAvatar.startsWith(username + "_")) {
            const ext = oldAvatar.split('.').pop();
            newAvatar = newUsername + "_" + Date.now() + "." + ext;
            const oldPath = path.join(AVATARS_DIR, oldAvatar);
            const newPath = path.join(AVATARS_DIR, newAvatar);
            try {
                if (fs.existsSync(oldPath)) {
                    fs.renameSync(oldPath, newPath);
                }
            } catch (e) {
                console.error("Avatar rename error:", e);
            }
        }

        // Update username and avatar in database
        db.updateUsername(user.id, newUsername);
        if (newAvatar !== oldAvatar) {
            db.updateUserAvatar(user.id, newAvatar);
        }

        const token = jwt.sign({ username: newUsername }, SECRET, { expiresIn: JWT_EXPIRATION });
        res.json({ success: true, token, username: newUsername, avatar: newAvatar });
    } catch (e) {
        console.error('Change username error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- UPLOAD GUILD ICON -------------------
app.post("/guild/:id/icon", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 10 per 60s
    if (!userRateLimit(req, res, username, 'uploadGuildIcon', 10)) return;

    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const id = req.params.id;
    const guild = db.getGuildById(id);
    if (!guild) return res.status(404).send("Sunucu bulunamadı");
    if (guild.owner_id !== user.id) return res.status(403).send("Sadece sahip resim değiştirebilir");

    const { icon } = req.body;
    if (!icon) return res.status(400).send("Icon yok");

    try {
        // Check format
        const formatMatch = icon.match(/^data:image\/(png|jpg|jpeg);base64,/);
        if (!formatMatch) return res.status(400).send("Sadece PNG ve JPG kabul edilir");
        const format = formatMatch[1] === "jpg" ? "jpg" : "png";

        // Decode base64 and check size (max 5MB)
        const base64Data = icon.replace(/^data:image\/\w+;base64,/, "");
        const buffer = Buffer.from(base64Data, "base64");

        if (buffer.length > 5 * 1024 * 1024) {
            return res.status(400).send("Icon 5MB'dan küçük olmalı");
        }

        // Remove old icon if exists
        if (guild.icon && guild.icon !== "default.png") {
            const oldPath = path.join(AVATARS_DIR, guild.icon);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
            }
        }

        // Generate unique filename
        const fileName = "guild_" + id + "_" + Date.now() + "." + format;
        const filePath = path.join(AVATARS_DIR, fileName);

        // Save file
        fs.writeFileSync(filePath, buffer);

        // Update DB
        db.updateGuildIcon(id, fileName);

        res.json({ icon: fileName });
    } catch (e) {
        console.error("Guild icon upload error:", e);
        res.status(500).send("Icon yükleme hatası");
    }
});

// ------------------- DELETE GUILD ICON -------------------
app.delete("/guild/:id/icon/delete", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 10 per 60s
    if (!userRateLimit(req, res, username, 'deleteGuildIcon', 10)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const id = req.params.id;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");

        const isOwner = guild.owner_id === user.id;
        const isAdmin = db.getIsGuildAdmin(id, user.id);
        if (!isOwner && !isAdmin) return res.status(403).send("Sadece sahip veya yönetici logoy kaldırabilir");

        // Delete file if exists
        if (guild.icon && guild.icon !== "default.png") {
            const filePath = path.join(AVATARS_DIR, guild.icon);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }

        db.updateGuildIcon(id, "default.png");
        res.send("Logo kaldırıldı");
    } catch (e) {
        console.error('Delete guild icon error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- UPLOAD PHOTO -------------------
app.post("/upload/photo", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 10 per 60s
    if (!userRateLimit(req, res, username, 'uploadPhoto', 10)) return;

    const { photo } = req.body;
    if (!photo) return res.status(400).send("Foto yok");

    try {
        // Check format
        const formatMatch = photo.match(/^data:image\/(png|jpg|jpeg);base64,/);
        if (!formatMatch) return res.status(400).send("Sadece PNG ve JPG kabul edilir");
        const format = formatMatch[1] === "jpg" ? "jpg" : "png";

        // Decode base64 and check size (max 10MB)
        const base64Data = photo.replace(/^data:image\/\w+;base64,/, "");
        const buffer = Buffer.from(base64Data, "base64");

        if (buffer.length > 10 * 1024 * 1024) {
            return res.status(400).send("Foto 10MB'dan küçük olmalı");
        }

        // Generate unique filename with security
        const fileName = crypto.randomBytes(8).toString('hex') + "_" + Date.now() + "." + format;
        const filePath = path.join(PHOTOS_DIR, fileName);

        // Save file
        fs.writeFileSync(filePath, buffer);

        res.json({ photo: fileName, url: `/photos/${fileName}` });
    } catch (e) {
        console.error("Photo upload error:", e);
        res.status(500).send("Foto yükleme hatası");
    }
});

// ------------------- GUILD LIST -------------------
app.get("/guild/list", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");
    const guilds = db.getUserGuilds(user.id);
    res.json({ guilds });
});

// Helper: check if two users share at least one guild
function sharesGuild(userIdA, userIdB) {
    return db.sharesGuild(userIdA, userIdB);
}

// Notify only online users who share at least one guild with targetUser
function notifySharedUsers(targetUserId, payload) {
    try {
        Object.keys(onlineWS).forEach(username => {
            if (username === targetUserId) return;
            if (!onlineWS[username]) return;
            try {
                const user = db.getUserByUsername(username);
                if (user && sharesGuild(user.id, targetUserId)) {
                    onlineWS[username].send(JSON.stringify(payload));
                }
            } catch (e) { /* ignore per-socket send errors */ }
        });
    } catch (e) { /* ignore */ }
}

// Secure avatar access: only allow if requester is the user or shares a guild
app.get('/avatars/:file', (req, res) => {
    const file = req.params.file;
    if (!file) return res.status(400).send('Bad request');
    // default avatar remains public
    if (file === 'default.png') return res.sendFile(path.join(AVATARS_DIR, file));

    // First, allow access via short-lived signature
    const sig = req.query.sig;
    const expires = parseInt(req.query.expires || '0', 10);
    if (sig && expires && Date.now() <= expires) {
        const expected = makeFileSig(file, expires);
        try {
            if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) {
                const p = path.join(AVATARS_DIR, file);
                if (fs.existsSync(p)) return res.sendFile(p);
                return res.status(404).send('Not found');
            }
        } catch (e) { /* fallthrough */ }
        return res.status(403).send('Forbidden');
    }

    // Fallback: require JWT and membership
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('No');
    let requester;
    try { requester = jwt.verify(token, SECRET).username; } catch (e) { return res.status(401).send('No'); }
    const requesterUser = db.getUserByUsername(requester);
    if (!requesterUser) return res.status(403).send('Forbidden');
    // attempt to derive owner from filename pattern 'username_<ts>.<ext>' else deny
    const parts = file.split('_');
    if (parts.length < 2) return res.status(403).send('Forbidden');
    const ownerUsername = parts[0];
    const ownerUser = db.getUserByUsername(ownerUsername);
    if (!ownerUser) return res.status(403).send('Forbidden');
    if (ownerUser.id === requesterUser.id || sharesGuild(ownerUser.id, requesterUser.id)) {
        const p = path.join(AVATARS_DIR, file);
        if (fs.existsSync(p)) return res.sendFile(p);
        return res.status(404).send('Not found');
    }
    return res.status(403).send('Forbidden');
});

// Secure photo access: only allow users who are member of guild that contains the message with that photo
app.get('/photos/:file', (req, res) => {
    const file = req.params.file;
    if (!file) return res.status(400).send('Bad request');

    // allow access via short-lived signature
    const sig = req.query.sig;
    const expires = parseInt(req.query.expires || '0', 10);
    if (sig && expires && Date.now() <= expires) {
        const expected = makeFileSig(file, expires);
        try {
            if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) {
                const p = path.join(PHOTOS_DIR, file);
                if (fs.existsSync(p)) return res.sendFile(p);
                return res.status(404).send('Not found');
            }
        } catch (e) { /* fallthrough */ }
        return res.status(403).send('Forbidden');
    }

    // fallback: require JWT and membership
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('No');
    let requester;
    try { requester = jwt.verify(token, SECRET).username; } catch (e) { return res.status(401).send('No'); }

    const requesterUser = db.getUserByUsername(requester);
    if (!requesterUser) return res.status(403).send('Forbidden');

    // Find which guild contains this photo
    const foundGuildId = db.getPhotoGuild(file);
    if (!foundGuildId) return res.status(404).send('Not found');

    // requester must be member of that guild
    if (!db.isGuildMember(foundGuildId, requesterUser.id)) return res.status(403).send('Forbidden');
    const p = path.join(PHOTOS_DIR, file);
    if (fs.existsSync(p)) return res.sendFile(p);
    return res.status(404).send('Not found');
});

// ------------------- CREATE GUILD -------------------
app.post("/guild/create", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    // rate limit guild creation per user: 5 per 60s, block 10min
    const rr = incrementAction(ipActionMap, username + ':createGuild', 60 * 1000, 5, 10 * 60 * 1000);
    if (!rr.allowed) return res.status(429).send('Too many guild creations; try later');

    const { name } = req.body;
    const id = "G" + Math.random().toString(36).substring(2, 8);

    // Create guild with default settings
    db.createGuild(id, name, user.id, "default.png", "genel", null, 0);
    db.addGuildMember(id, user.id, false);
    db.createChannel(id, "genel", 0, true, true);

    // Send system message
    db.createMessage(
        crypto.randomBytes(8).toString('hex'),
        id,
        "genel",
        null,
        "system",
        null,
        null,
        `Sunucu ${username} tarafından kuruldu`,
        null,
        null,
        null,
        null,
        Date.now()
    );

    res.send("Guild oluşturuldu");
});

// ------------------- GUILD INFO -------------------
app.get("/guild/:id/info", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const id = req.params.id;
    const guild = db.getGuildById(id);
    if (!guild) return res.status(404).send("Bulunamadı");

    // Security: Verify user is member of this guild
    if (!db.isGuildMember(id, user.id)) {
        return res.status(403).send("Access denied");
    }

    const isOwner = guild.owner_id === user.id;
    const isAdmin = db.getIsGuildAdmin(id, user.id);

    // Get members
    const membersData = db.getGuildMembers(id);
    const members = membersData.map(m => ({
        username: m.username,
        online: Boolean(onlineWS[m.username]),
        avatar: m.avatar || "default.png",
        bio: m.bio || "",
        admin: m.is_admin === 1
    }));

    // Get text channels
    const channelsData = db.getGuildChannels(id);
    const channels = channelsData
        .filter(ch => {
            if (ch.read_enabled) return true;
            return isOwner || isAdmin;
        })
        .map(ch => ch.name);

    // Get voice channels
    const voiceChannelsData = db.getGuildVoiceChannels(id);
    const voiceChannels = voiceChannelsData
        .filter(vc => {
            if (vc.read_enabled) return true;
            return isOwner || isAdmin;
        })
        .map(vc => ({
            id: vc.id,
            name: vc.name,
            users: voiceUsers[vc.id] || []
        }));

    // Get admin list
    const admins = db.getGuildAdmins(id);
    const adminUsernames = admins.map(adminId => {
        const adminUser = db.getUserById(adminId);
        return adminUser ? adminUser.username : null;
    }).filter(Boolean);

    // Build channel settings map
    const channelSettings = {};
    channelsData.forEach(ch => {
        channelSettings[ch.name] = {
            sendEnabled: ch.send_enabled === 1,
            readEnabled: ch.read_enabled === 1
        };
    });
    voiceChannelsData.forEach(vc => {
        channelSettings[vc.name] = {
            readEnabled: vc.read_enabled === 1,
            speakEnabled: vc.speak_enabled === 1,
            maxMembers: vc.max_members,
            isVoice: true
        };
    });

    const ownerUser = db.getUserById(guild.owner_id);

    res.json({
        name: guild.name,
        owner: ownerUser ? ownerUser.username : 'unknown',
        icon: guild.icon || "default.png",
        channels,
        voiceChannels,
        members,
        admins: adminUsernames,
        channelSettings,
        isPrivate: guild.is_private === 1,
        systemChannelId: guild.system_channel_id || channels[0] || "genel",
        inviteCode: guild.invite_code || null
    });
});

// ------------------- GET CHANNELS -------------------
app.get('/guild/:id/channels', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const id = req.params.id;
    const guild = db.getGuildById(id);
    if (!guild) return res.status(404).send("Sunucu bulunamadı");

    // Security: Verify user is member of this guild
    if (!db.isGuildMember(id, user.id)) return res.status(403).send("Access denied");

    const isOwner = guild.owner_id === user.id;
    const isAdmin = db.getIsGuildAdmin(id, user.id);

    const channelsData = db.getGuildChannels(id);
    const channels = channelsData
        .filter(ch => {
            if (ch.read_enabled) return true;
            return isOwner || isAdmin;
        })
        .map(ch => ch.name);

    res.json({ channels });
});

// ------------------- CREATE CHANNEL (HTTP)
app.post('/guild/:id/channel', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    // rate limit channel creation per user: 10 per 60s, block 10 minutes
    const rr = incrementAction(ipActionMap, username + ':createChannel', 60 * 1000, 10, 10 * 60 * 1000);
    if (!rr.allowed) return res.status(429).send('Too many channel creations; try later');

    const id = req.params.id;
    const { name } = req.body;
    const guild = db.getGuildById(id);
    if (!guild) return res.status(404).send('Sunucu bulunamadı');
    if (!db.isGuildMember(id, user.id)) return res.status(403).send('Üye değilsin');

    // only owner or designated admins may create channels
    const isOwner = guild.owner_id === user.id;
    const isAdmin = db.getIsGuildAdmin(id, user.id);
    if (!isOwner && !isAdmin) return res.status(403).send("Sadece sahip veya yönetici kanal oluşturabilir");

    // Check if channel already exists
    const existing = db.getChannel(id, name);
    if (existing) return res.status(400).send('Kanal zaten var');

    db.createChannel(id, name, 0, true, true);

    // Notify all members
    const members = db.getGuildMembers(id);
    members.forEach(m => {
        if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'newChannel', channel: name, guild: id }));
    });
    res.send('Kanal oluşturuldu');
});

// ------------------- CREATE VOICE CHANNEL -------------------
app.post('/guild/:id/voiceChannel', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const id = req.params.id;
    const { name } = req.body;
    const guild = db.getGuildById(id);
    if (!guild) return res.status(404).send('Sunucu bulunamadı');

    const isOwner = guild.owner_id === user.id;
    const isAdmin = db.getIsGuildAdmin(id, user.id);
    if (!isOwner && !isAdmin) return res.status(403).send('Sadece sahip veya yönetici oluşturabilir');

    // rate limit voice channel creation per owner: 5 per 60s, block 10min
    const rr = incrementAction(ipActionMap, username + ':createVoice', 60 * 1000, 5, 10 * 60 * 1000);
    if (!rr.allowed) return res.status(429).send('Too many voice channel creations; try later');

    // Check if voice channel already exists
    const existing = db.getVoiceChannelByName(id, name);
    if (existing) return res.status(400).send('Ses kanal zaten var');

    const voiceChannelId = crypto.randomBytes(6).toString('hex');
    db.createVoiceChannel(voiceChannelId, id, name, true, true, null);
    voiceUsers[voiceChannelId] = [];

    const voiceChannel = {
        id: voiceChannelId,
        name: name,
        users: []
    };

    // Notify all members
    const members = db.getGuildMembers(id);
    members.forEach(m => {
        if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'newVoiceChannel', voiceChannel: voiceChannel, guild: id }));
    });
    res.json({ voiceChannel });
});

// ------------------- DELETE CHANNEL -------------------
app.delete('/guild/:gid/channel/:channel', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const { gid, channel } = req.params;
    const guild = db.getGuildById(gid);
    if (!guild) return res.status(404).send('Sunucu bulunamadı');

    // Security: Verify user is member of this guild
    if (!db.isGuildMember(gid, user.id)) return res.status(403).send('Access denied');
    const isOwner = guild.owner_id === user.id;
    const isAdmin = db.getIsGuildAdmin(gid, user.id);
    if (!isOwner && !isAdmin) return res.status(403).send('Sadece sahip veya yönetici silebilir');

    // Get messages to delete photos
    const messages = db.getMessages(gid, channel, 999999, 0);
    messages.forEach(msg => {
        if (msg.photo) {
            const photoPath = path.join(PHOTOS_DIR, msg.photo);
            if (fs.existsSync(photoPath)) {
                fs.unlinkSync(photoPath);
            }
        }
    });

    // Delete channel and all messages
    db.deleteChannelMessages(gid, channel);
    db.deleteChannel(gid, channel);

    // Notify guild members only
    const members = db.getGuildMembers(gid);
    members.forEach(m => {
        if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'deleteChannel', channel: channel, guild: gid }));
    });
    res.send('Kanal silindi');
});

// ------------------- RENAME CHANNEL -------------------
app.patch('/guild/:gid/channel/:channel/rename', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const { gid, channel } = req.params;
    const { newName } = req.body;

    const guild = db.getGuildById(gid);
    if (!guild) return res.status(404).send('Sunucu bulunamadı');

    // Security: Verify user is member of this guild
    if (!db.isGuildMember(gid, user.id)) return res.status(403).send('Access denied');
    const isOwner = guild.owner_id === user.id;
    const isAdmin = db.getIsGuildAdmin(gid, user.id);
    if (!isOwner && !isAdmin) return res.status(403).send('Sadece sahip veya yönetici değiştirebilir');
    if (!newName || newName.trim() === '') return res.status(400).send('Kanal adı boş');

    // Check if new name already exists
    const existingChannel = db.getChannel(gid, newName);
    if (existingChannel) return res.status(400).send('Bu isimde kanal zaten var');

    // Check if old channel exists
    const oldChannel = db.getChannel(gid, channel);
    if (!oldChannel) return res.status(404).send('Kanal bulunamadı');

    // Rename channel (this updates all messages' channel_name via FK or manual update if needed)
    db.renameChannel(gid, channel, newName);

    // Update messages to point to new channel name
    // Note: SQLite doesn't auto-update denormalized channel names in messages
    // We need to manually update them using the secure prepared statement
    db.updateMessageChannelName(gid, channel, newName);

    // Notify guild members only
    const members = db.getGuildMembers(gid);
    members.forEach(m => {
        if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'renameChannel', oldName: channel, newName: newName, guild: gid }));
    });

    res.send('Kanal adı güncellendi');
});

// ------------------- REGENERATE INVITE CODE -------------------
app.post("/guild/:id/invite", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    // invite brute-force protection: limit per IP (200 per hour), block 1 hour
    const rr = incrementAction(inviteBruteMap, ip, 60 * 60 * 1000, 200, 60 * 60 * 1000);
    if (!rr.allowed) return res.status(429).send('Too many invite requests from this IP. Try later.');

    try {
        const id = req.params.id;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");
        // Security: Verify user is member of this guild
        if (!db.isGuildMember(id, user.id)) return res.status(403).send("Üye değilsin");

        // Allow both owner and admins to regenerate invite code
        const isOwner = guild.owner_id === user.id;
        const isAdmin = db.getIsGuildAdmin(id, user.id);
        if (!isOwner && !isAdmin) return res.status(403).send("Sadece sahip veya yönetici davet kodu yenileyebilir");

        // Generate new secure invite code using crypto
        const code = generateSecureInviteCode();
        db.updateGuildInviteCode(id, code);
        res.json({ inviteCode: code, message: "Davet kodu yenilendi" });
    } catch (e) {
        console.error('Regenerate invite error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- JOIN VIA INVITE -------------------
app.post("/invite/:code", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }
    const user = db.getUserByUsername(username);
    if (!user) return res.status(401).send("No");

    const code = req.params.code;
    // Only use persistent invite codes from guild object
    const guild = db.getGuildByInviteCode(code);
    if (!guild) return res.status(404).send("Kod geçersiz");
    const gid = guild.id;

    // Check if server is private
    if (guild.is_private) {
        return res.status(403).send("Bu sunucu yeni üye kabul etmiyor");
    }

    // Check if user is banned
    if (db.isBanned(gid, user.id)) {
        return res.status(403).send("Bu sunucudan banlandınız");
    }

    const wasAlreadyMember = db.isGuildMember(gid, user.id);
    if (!wasAlreadyMember) {
        db.addGuildMember(gid, user.id, false);
    }

    // Send system message if new member
    if (!wasAlreadyMember) {
        const sysChan = guild.system_channel_id;
        const sysMsg = {
            id: crypto.randomBytes(6).toString('hex'),
            type: "system",
            text: `${username} sunucuya katıldı`,
            ts: Date.now()
        };

        db.createMessage(
            sysMsg.id,
            gid,
            sysChan || 'genel',
            null,
            'system',
            null,
            null,
            sysMsg.text,
            null,
            null,
            null,
            null,
            sysMsg.ts
        );

        // Notify all members
        const members = db.getGuildMembers(gid);
        members.forEach(m => {
            if (onlineWS[m.username]) {
                onlineWS[m.username].send(JSON.stringify({
                    type: "newMessage",
                    msgType: "system",
                    text: sysMsg.text,
                    channel: sysChan || 'genel',
                    guild: gid,
                    ts: sysMsg.ts,
                    id: sysMsg.id
                }));
            }
        });
    }

    res.send("Sunucuya katıldın");
});

// ------------------- GET INVITE CODE -------------------
app.get("/guild/:id/invite", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 60 per 60s
    if (!rateLimit(req, res, 'getInvite', 60)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const id = req.params.id;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");
        if (!db.isGuildMember(id, user.id)) return res.status(403).send("Üye değilsin");

        // Return existing invite code or create one
        if (!guild.invite_code) {
            const code = generateSecureInviteCode();
            db.updateGuildInviteCode(id, code);
            return res.json({
                inviteCode: code,
                isPrivate: guild.is_private === 1
            });
        }
        res.json({
            inviteCode: guild.invite_code,
            isPrivate: guild.is_private === 1
        });
    } catch (e) {
        console.error('Get invite error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- BAN USER -------------------
app.post("/guild/:id/ban", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 30 per 60s
    if (!userRateLimit(req, res, username, 'banUser', 30)) return;

    try {
        const requester = db.getUserByUsername(username);
        if (!requester) return res.status(401).send("No");

        const id = req.params.id;
        const { user: targetUsername } = req.body;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");
        if (!db.isGuildMember(id, requester.id)) return res.status(403).send("Üye değilsin");

        const isOwner = guild.owner_id === requester.id;
        const isAdmin = db.getIsGuildAdmin(id, requester.id);
        if (!isOwner && !isAdmin) return res.status(403).send("İzin yok");

        const targetUser = db.getUserByUsername(targetUsername);
        if (!targetUser) return res.status(404).send("Kullanıcı bulunamadı");
        if (guild.owner_id === targetUser.id) return res.status(403).send("Sahibi banlayamazsınız");

        // Ban user and remove from guild
        db.banUser(id, targetUser.id);
        db.removeGuildMember(id, targetUser.id);
        db.setGuildAdmin(id, targetUser.id, false); // Remove admin if was admin

        // Notify
        const members = db.getGuildMembers(id);
        members.forEach(m => {
            if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'userKicked', guild: id, user: targetUsername }));
        });
        if (onlineWS[targetUsername]) onlineWS[targetUsername].send(JSON.stringify({ type: 'banned', guild: id }));

        res.send("Kullanıcı banlandı");
    } catch (e) {
        console.error('Ban user error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- UNBAN USER -------------------
app.post("/guild/:id/unban", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 30 per 60s
    if (!userRateLimit(req, res, username, 'unbanUser', 30)) return;

    try {
        const requester = db.getUserByUsername(username);
        if (!requester) return res.status(401).send("No");

        const id = req.params.id;
        const { user: targetUsername } = req.body;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");

        const isOwner = guild.owner_id === requester.id;
        const isAdmin = db.getIsGuildAdmin(id, requester.id);
        if (!isOwner && !isAdmin) return res.status(403).send("İzin yok");

        const targetUser = db.getUserByUsername(targetUsername);
        if (targetUser) {
            db.unbanUser(id, targetUser.id);
        }

        res.send("Ban kaldırıldı");
    } catch (e) {
        console.error('Unban user error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- GET BANNED USERS -------------------
app.get("/guild/:id/bannedUsers", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 60 per 60s
    if (!rateLimit(req, res, 'getBannedUsers', 60)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const id = req.params.id;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");

        const isOwner = guild.owner_id === user.id;
        const isAdmin = db.getIsGuildAdmin(id, user.id);
        if (!isOwner && !isAdmin) return res.status(403).send("İzin yok");

        const bannedUserIds = db.getBannedUsers(id);
        const bannedUsernames = bannedUserIds.map(userId => {
            const u = db.getUserById(userId);
            return u ? u.username : null;
        }).filter(Boolean);

        res.json({ bannedUsers: bannedUsernames });
    } catch (e) {
        console.error('Get banned users error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- SET GUILD PRIVATE -------------------
app.post("/guild/:id/private", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 10 per 60s
    if (!userRateLimit(req, res, username, 'setPrivate', 10)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const id = req.params.id;
        const { isPrivate } = req.body;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");
        if (guild.owner_id !== user.id) return res.status(403).send("Sadece sahip değiştirebilir");

        db.updateGuildPrivate(id, !!isPrivate);
        res.json({ isPrivate: !!isPrivate });
    } catch (e) {
        console.error('Set private error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- SET SYSTEM CHANNEL -------------------
app.patch("/guild/:id/systemChannel", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 10 per 60s
    if (!userRateLimit(req, res, username, 'setSystemChannel', 10)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const id = req.params.id;
        const { systemChannelId } = req.body;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");
        if (guild.owner_id !== user.id) return res.status(403).send("Sadece sahip değiştirebilir");

        db.updateGuildSystemChannel(id, systemChannelId);
        res.json({ systemChannelId: systemChannelId });
    } catch (e) {
        console.error('Set system channel error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- DELETE GUILD -------------------
app.delete("/guild/:id", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 5 per 60s (destructive action)
    if (!userRateLimit(req, res, username, 'deleteGuild', 5)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const id = req.params.id;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");
        // Security: Verify user is member of this guild
        if (!db.isGuildMember(id, user.id)) return res.status(403).send("Üye değilsin");
        if (guild.owner_id !== user.id) return res.status(403).send("İzin yok");

        // Delete all photos in this guild
        const channels = db.getGuildChannels(id);
        channels.forEach(ch => {
            const messages = db.getMessages(id, ch.name, 999999, 0);
            messages.forEach(msg => {
                if (msg.photo) {
                    const photoPath = path.join(PHOTOS_DIR, msg.photo);
                    if (fs.existsSync(photoPath)) {
                        fs.unlinkSync(photoPath);
                    }
                }
            });
        });

        const membersList = db.getGuildMembers(id).map(m => m.username);

        // Delete guild (cascades to all related data via FK constraints)
        db.deleteGuild(id);

        // Notify only the members of the deleted guild
        (membersList || []).forEach(m => {
            if (onlineWS[m]) onlineWS[m].send(JSON.stringify({ type: 'deleteGuild', guild: id }));
        });

        res.send("Sunucu silindi");
    } catch (e) {
        console.error('Delete guild error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- UNSET ADMIN -------------------
app.post('/guild/:id/admin/unset', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 20 per 60s
    if (!userRateLimit(req, res, username, 'unsetAdmin', 20)) return;

    try {
        const owner = db.getUserByUsername(username);
        if (!owner) return res.status(401).send("No");

        const id = req.params.id;
        const { user: targetUsername } = req.body;
        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send('Sunucu bulunamadı');
        if (guild.owner_id !== owner.id) return res.status(403).send('Sadece sahip yetki kaldırabilir');

        const targetUser = db.getUserByUsername(targetUsername);
        if (targetUser) {
            db.setGuildAdmin(id, targetUser.id, false);
        }

        const members = db.getGuildMembers(id);
        members.forEach(m => { if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'adminUnset', guild: id, user: targetUsername })); });
        res.send('Yönetici yetkisi kaldırıldı');
    } catch (e) {
        console.error('Unset admin error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- TRANSFER OWNERSHIP -------------------
app.post("/guild/:id/transfer", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 5 per 60s (critical action)
    if (!userRateLimit(req, res, username, 'transferOwnership', 5)) return;

    try {
        const owner = db.getUserByUsername(username);
        if (!owner) return res.status(401).send("No");

        const id = req.params.id;
        const { newOwner: newOwnerUsername } = req.body;

        const guild = db.getGuildById(id);
        if (!guild) return res.status(404).send("Sunucu bulunamadı");
        if (!db.isGuildMember(id, owner.id)) return res.status(403).send("Üye değilsin");
        if (guild.owner_id !== owner.id) return res.status(403).send("İzin yok");

        const newOwner = db.getUserByUsername(newOwnerUsername);
        if (!newOwner) return res.status(404).send("Kullanıcı bulunamadı");
        if (!db.isGuildMember(id, newOwner.id)) return res.status(400).send("Kullanıcı sunucunun üyesi değil");

        db.updateGuildOwner(id, newOwner.id);
        db.setGuildAdmin(id, newOwner.id, false);
        db.setGuildAdmin(id, owner.id, true);

        res.send("Sahiplik aktarıldı");
    } catch (e) {
        console.error('Transfer ownership error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- MESSAGES CHUNK -------------------
app.get("/messages/:gid/:channel", (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 100 per 60s
    if (!rateLimit(req, res, 'getMessages', 100)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const { gid, channel } = req.params;

        const guild = db.getGuildById(gid);
        if (!guild || !db.isGuildMember(gid, user.id)) {
            return res.status(403).send("Access denied");
        }

        const textChannel = db.getChannel(gid, channel);
        const voiceChannel = db.getVoiceChannelByName(gid, channel);
        const channelObj = textChannel || voiceChannel;

        const isOwner = guild.owner_id === user.id;
        const isAdmin = db.getIsGuildAdmin(gid, user.id);
        if (channelObj && channelObj.read_enabled === 0 && !isOwner && !isAdmin) {
            return res.status(403).send('Access denied');
        }

        const offset = parseInt(req.query.offset || 0);
        const limit = parseInt(req.query.limit || 50);

        const messages = db.getMessages(gid, channel, limit, offset);
        const dec = messages.map(m => {
            if (m.message_type === 'system') {
                return {
                    id: m.id,
                    type: 'system',
                    msgType: 'system',
                    text: m.text || '',
                    ts: m.timestamp,
                    from: null,
                    photo: null,
                    replyTo: null,
                    replyPreview: null,
                    avatar: 'default.png'
                };
            }
            const authorUser = m.from_user_id ? db.getUserById(m.from_user_id) : null;
            return {
                id: m.id,
                from: authorUser ? authorUser.username : 'unknown',
                ts: m.timestamp,
                text: m.enc && m.iv ? decrypt(m.enc, m.iv) : (m.text || ''),
                photo: m.photo || null,
                replyTo: m.reply_to || null,
                replyPreview: m.reply_from ? { from: m.reply_from, text: m.reply_text } : null,
                avatar: authorUser ? authorUser.avatar : "default.png"
            };
        });
        res.json(dec);
    } catch (e) {
        console.error('Get messages error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- EDIT MESSAGE -------------------
app.post('/messages/:gid/:channel/edit', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 50 per 60s
    if (!userRateLimit(req, res, username, 'editMessage', 50)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const { gid, channel } = req.params;
        const { id, text } = req.body;

        const guild = db.getGuildById(gid);
        if (!guild || !db.isGuildMember(gid, user.id)) {
            return res.status(403).send("Access denied");
        }

        const msg = db.getMessage(id);
        if (!msg || msg.guild_id !== gid || msg.channel_name !== channel) return res.status(404).send('Mesaj bulunamadı');

        const isOwnerEdit = guild.owner_id === user.id;
        const isAdminEdit = db.getIsGuildAdmin(gid, user.id);
        const msgAuthor = msg.user_id ? db.getUserById(msg.user_id) : null;
        if (msgAuthor && msgAuthor.username !== username && !isOwnerEdit && !isAdminEdit) return res.status(403).send('İzin yok');

        const enc = encrypt(text);
        db.updateMessage(id, enc.enc, enc.iv);

        const members = db.getGuildMembers(gid);
        members.forEach(m => {
            if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'editMessage', id, channel, guild: gid, from: username }));
        });
        res.send('Mesaj düzenlendi');
    } catch (e) {
        console.error('Edit message error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- DELETE MESSAGE -------------------
app.post('/messages/:gid/:channel/delete', (req, res) => {
    let username;
    try { username = jwt.verify(req.headers.authorization, SECRET).username; } catch { return res.status(401).send("No"); }

    // Rate limit: 50 per 60s
    if (!userRateLimit(req, res, username, 'deleteMessage', 50)) return;

    try {
        const user = db.getUserByUsername(username);
        if (!user) return res.status(401).send("No");

        const { gid, channel } = req.params;
        const { id } = req.body;

        const guild = db.getGuildById(gid);
        if (!guild || !db.isGuildMember(gid, user.id)) {
            return res.status(403).send("Access denied");
        }

        const msg = db.getMessage(id);
        if (!msg || msg.guild_id !== gid || msg.channel_name !== channel) return res.status(404).send('Mesaj bulunamadı');

        const isOwnerDel = guild.owner_id === user.id;
        const isAdminDel = db.getIsGuildAdmin(gid, user.id);
        const msgAuthor = msg.user_id ? db.getUserById(msg.user_id) : null;
        if (msgAuthor && msgAuthor.username !== username && !isOwnerDel && !isAdminDel) return res.status(403).send('İzin yok');

        if (msg.photo) {
            const photoPath = path.join(PHOTOS_DIR, msg.photo);
            if (fs.existsSync(photoPath)) {
                fs.unlinkSync(photoPath);
            }
        }

        db.deleteMessage(id);

        const members = db.getGuildMembers(gid);
        members.forEach(m => {
            if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'deleteMessage', id, channel, guild: gid }));
        });
        res.send('Mesaj silindi');
    } catch (e) {
        console.error('Delete message error:', e);
        res.status(500).send('Bir hata oluştu');
    }
});

// ------------------- WEBSOCKET -------------------
wss.on("connection", (ws, req) => {
    try {
        const params = new URLSearchParams(req.url.split("?")[1]);
        const token = params.get("token");
        const guild = params.get("guild");
        let username;
        try { username = jwt.verify(token, SECRET).username; } catch { ws.close(); return; }

        const user = db.getUserByUsername(username);
        if (!user) { ws.close(); return; }

        const guildObj = db.getGuildById(guild);
        // Security: Verify user is member of the guild they're connecting to
        if (!guildObj || !db.isGuildMember(guild, user.id)) {
            ws.send(JSON.stringify({ type: "error", message: "Access denied" }));
            ws.close();
            return;
        }

        // Ping/pong keepalive
        ws.isAlive = true;
        ws.on('pong', () => { ws.isAlive = true; });

        // Register this websocket as the current connection for the user
        // Only broadcast an "online" presence to other users when there was
        // no previous active connection for this username. This avoids noisy
        // presence broadcasts when the client opens a new WS (e.g. switching
        // guilds) while the user remains effectively online.
        const prevWs = onlineWS[username];
        onlineWS[username] = ws;

        // NOTE: previously this server aggressively removed any voice presence
        // for the connecting user across all guilds here. That behavior caused
        // users to be removed from voice member lists when they simply opened a
        // new websocket (for example switching guilds in the UI). Voice cleanup
        // is already handled on socket close below, so avoid removing presence
        // here to prevent false "user left" broadcasts.

        // Send current user their own online status (always)
        ws.send(JSON.stringify({ type: "presence", user: username, status: "online" }));

        // Only notify other users if there was no existing connection for this
        // username (i.e., the user transitioned from offline -> online).
        if (!prevWs) {
            notifySharedUsers(user.id, { type: "presence", user: username, status: "online" });
        }
        ws.on("message", raw => {
            try {
                const msg = JSON.parse(raw);

                // Ping/pong keepalive - respond to client pings
                if (msg.type === 'ping') {
                    try { ws.send(JSON.stringify({ type: 'pong' })); } catch (e) { }
                    return;
                }

                // typing indicator
                if (msg.type === "typing") {
                    const key = `${guild}:${msg.channel}`;
                    if (!typingUsers[key]) typingUsers[key] = new Set();
                    typingUsers[key].add(username);

                    // Broadcast typing status
                    const typingList = Array.from(typingUsers[key]);
                    const members = db.getGuildMembers(guild);
                    members.forEach(m => {
                        if (onlineWS[m.username]) {
                            onlineWS[m.username].send(JSON.stringify({
                                type: "typing",
                                guild: guild,
                                channel: msg.channel,
                                users: typingList
                            }));
                        }
                    });
                }

                // typing stopped
                if (msg.type === "typingStopped") {
                    const key = `${guild}:${msg.channel}`;
                    if (typingUsers[key]) {
                        typingUsers[key].delete(username);

                        // Broadcast updated typing status
                        const typingList = Array.from(typingUsers[key]);
                        const members = db.getGuildMembers(guild);
                        members.forEach(m => {
                            if (onlineWS[m.username]) {
                                onlineWS[m.username].send(JSON.stringify({
                                    type: "typing",
                                    guild: guild,
                                    channel: msg.channel,
                                    users: typingList
                                }));
                            }
                        });
                    }
                }

                // send message
                if (msg.type === "message") {
                    // per-user message rate limiting: max 80 messages per 60s, block 30s
                    try {
                        const now = Date.now();
                        let mr = messageRateMap.get(username) || { timestamps: [], blockedUntil: 0 };
                        if (mr.blockedUntil && now < mr.blockedUntil) {
                            try { ws.send(JSON.stringify({ type: 'error', message: 'Rate limited: messages' })); } catch (e) { }
                            return;
                        }
                        // prune older than 60s
                        mr.timestamps = mr.timestamps.filter(t => now - t <= 60 * 1000);
                        if (mr.timestamps.length >= 80) {
                            mr.blockedUntil = now + 30 * 1000; // block 30s
                            messageRateMap.set(username, mr);
                            try { ws.send(JSON.stringify({ type: 'error', message: 'Too many messages; temporarily rate limited' })); } catch (e) { }
                            return;
                        }
                        mr.timestamps.push(now);
                        messageRateMap.set(username, mr);
                    } catch (e) { /* don't block on rate limiter failure */ }

                    // Check send permission for this channel
                    const textChannel = db.getChannel(guild, msg.channel);
                    const voiceChannel = db.getVoiceChannelByName(guild, msg.channel);
                    const channelObj = textChannel || voiceChannel;
                    const isOwnerMsg = guildObj.owner_id === user.id;
                    const isAdminMsg = db.getIsGuildAdmin(guild, user.id);
                    if (channelObj && channelObj.send_enabled === 0 && !isOwnerMsg && !isAdminMsg) {
                        try { ws.send(JSON.stringify({ type: 'error', message: 'Mesaj gönderimi kapalı' })); } catch (e) { }
                        return;
                    }

                    const e = encrypt(msg.text || "");
                    const ts = Date.now();
                    const newId = crypto.randomBytes(6).toString('hex');

                    let replyPreview = null;
                    if (msg.replyTo) {
                        const orig = db.getMessage(msg.replyTo);
                        if (orig) {
                            const origAuthor = orig.user_id ? db.getUserById(orig.user_id) : null;
                            try {
                                replyPreview = { from: origAuthor ? origAuthor.username : 'unknown', text: decrypt(orig.enc, orig.iv) };
                            } catch (err) {
                                replyPreview = { from: origAuthor ? origAuthor.username : 'unknown', text: "[önizleme yok]" };
                            }
                        }
                    }

                    db.createMessage(
                        newId,
                        guild,
                        msg.channel,
                        user.id,
                        'user',
                        e.enc,
                        e.iv,
                        null,
                        msg.photo || null,
                        msg.replyTo || null,
                        replyPreview ? JSON.stringify(replyPreview) : null,
                        null,
                        ts
                    );

                    const members = db.getGuildMembers(guild);
                    members.forEach(m => {
                        if (onlineWS[m.username]) {
                            onlineWS[m.username].send(JSON.stringify({
                                type: "newMessage",
                                from: username,
                                avatar: user.avatar || "default.png",
                                text: msg.text,
                                photo: msg.photo || null,
                                replyTo: msg.replyTo || null,
                                replyPreview: replyPreview,
                                channel: msg.channel,
                                guild,
                                ts: ts,
                                id: newId
                            }));
                        }
                    });
                }
                // create channel
                if (msg.type === "newChannel") {
                    const name = msg.channel;
                    const existing = db.getChannel(guild, name);
                    if (!existing) {
                        db.createChannel(guild, name, 0, true, true);
                        const members = db.getGuildMembers(guild);
                        members.forEach(m => {
                            if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: "newChannel", channel: name }));
                        });
                    }
                }
                // join voice channel
                if (msg.type === "joinVoice") {
                    const vcId = msg.voiceChannelId;
                    const vc = db.getVoiceChannelById(vcId);
                    if (vc && vc.guild_id === guild) {
                        if (!voiceUsers[vcId]) voiceUsers[vcId] = [];
                        if (!voiceUsers[vcId].includes(username)) {
                            // enforce channel visibility and maxMembers
                            const isOwnerJoin = guildObj.owner_id === user.id;
                            const isAdminJoin = db.getIsGuildAdmin(guild, user.id);
                            if (vc.read_enabled === 0 && !isOwnerJoin && !isAdminJoin) {
                                try { ws.send(JSON.stringify({ type: 'error', message: 'Bu ses kanalı görünür değil' })); } catch (e) { }
                                return;
                            }
                            if (vc.speak_enabled === 0 && !isOwnerJoin && !isAdminJoin) {
                                try { ws.send(JSON.stringify({ type: 'error', message: 'Bu kanalda konuşma izni yok' })); } catch (e) { }
                                return;
                            }
                            if (vc.max_members && vc.max_members > 0 && voiceUsers[vcId].length >= vc.max_members && !isOwnerJoin && !isAdminJoin) {
                                try { ws.send(JSON.stringify({ type: 'error', message: 'Kanal kişi sınırına ulaştı' })); } catch (е) { }
                                return;
                            }
                            voiceUsers[vcId].push(username);
                            // Send the current voice channel state back to the joining socket
                            try {
                                ws.send(JSON.stringify({ type: 'voiceState', voiceChannelId: vcId, users: voiceUsers[vcId] }));
                            } catch (e) { /* ignore send errors */ }

                            // Broadcast to other members that a new user joined
                            const members = db.getGuildMembers(guild);
                            members.forEach(m => {
                                if (onlineWS[m.username] && m.username !== username) {
                                    onlineWS[m.username].send(JSON.stringify({
                                        type: "voiceUserJoined",
                                        user: username,
                                        voiceChannelId: vcId,
                                        voiceChannelName: msg.voiceChannelName
                                    }));
                                }
                            });
                        }
                    }
                }
                // leave voice channel
                if (msg.type === "leaveVoice") {
                    const vcId = msg.voiceChannelId;
                    if (voiceUsers[vcId]) {
                        voiceUsers[vcId] = voiceUsers[vcId].filter(u => u !== username);
                        const members = db.getGuildMembers(guild);
                        members.forEach(m => {
                            if (onlineWS[m.username]) {
                                onlineWS[m.username].send(JSON.stringify({
                                    type: "voiceUserLeft",
                                    user: username,
                                    voiceChannelId: vcId
                                }));
                            }
                        });
                    }
                }
                // voice signaling relay (WebRTC)
                if (msg.type === 'voiceSignal') {
                    const to = msg.to;
                    const vcId = msg.voiceChannelId;
                    // Validate sender is in the voice channel
                    if (voiceUsers[vcId] && voiceUsers[vcId].includes(username)) {
                        const vc = db.getVoiceChannelById(vcId);
                        if (vc) {
                            // enforce speak permission if configured
                            const isOwnerSpeak = guildObj.owner_id === user.id;
                            const isAdminSpeak = db.getIsGuildAdmin(guild, user.id);
                            if (vc.speak_enabled === 0 && !isOwnerSpeak && !isAdminSpeak) {
                                try { ws.send(JSON.stringify({ type: 'error', message: 'Konuşma yetkiniz yok' })); } catch (e) { }
                                return;
                            }
                            if (to) {
                                // ensure recipient is also in same voice channel to prevent relaying to outsiders
                                if (voiceUsers[vcId].includes(to) && onlineWS[to]) {
                                    onlineWS[to].send(JSON.stringify({ type: 'voiceSignal', from: username, data: msg.data }));
                                }
                            } else {
                                // broadcast to all other users in the same voice channel
                                voiceUsers[vcId].forEach(u => {
                                    if (u !== username && onlineWS[u]) {
                                        onlineWS[u].send(JSON.stringify({ type: 'voiceSignal', from: username, data: msg.data }));
                                    }
                                });
                            }
                        }
                    }
                }
                // voice mute/deafen broadcast
                if (msg.type === 'voiceMute') {
                    const vcId = msg.voiceChannelId;
                    const muted = !!msg.muted;
                    if (voiceUsers[vcId] && voiceUsers[vcId].includes(username)) {
                        // broadcast mute status to members
                        voiceUsers[vcId].forEach(u => {
                            if (onlineWS[u]) onlineWS[u].send(JSON.stringify({ type: 'voiceMute', user: username, voiceChannelId: vcId, muted }));
                        });
                    }
                }
                if (msg.type === 'voiceDeafen') {
                    const vcId = msg.voiceChannelId;
                    const deaf = !!msg.deaf;
                    if (voiceUsers[vcId] && voiceUsers[vcId].includes(username)) {
                        voiceUsers[vcId].forEach(u => {
                            if (onlineWS[u]) onlineWS[u].send(JSON.stringify({ type: 'voiceDeafen', user: username, voiceChannelId: vcId, deaf }));
                        });
                    }
                }
                // voice ready/announce (notify members this user is ready to negotiate)
                if (msg.type === 'voiceReady') {
                    const vcId = msg.voiceChannelId;
                    if (voiceUsers[vcId] && voiceUsers[vcId].includes(username)) {
                        voiceUsers[vcId].forEach(u => {
                            if (onlineWS[u]) onlineWS[u].send(JSON.stringify({ type: 'voiceReady', user: username, voiceChannelId: vcId }));
                        });
                    }
                }
                // kick from voice (owner only)
                if (msg.type === 'kickFromVoice') {
                    const target = msg.user;
                    const vcId = msg.voiceChannelId;
                    if (!target) return;
                    if (guildObj.owner_id !== user.id) {
                        // only owner can kick
                        return;
                    }
                    if (voiceUsers[vcId] && voiceUsers[vcId].includes(target)) {
                        voiceUsers[vcId] = voiceUsers[vcId].filter(u => u !== target);
                        // notify all members
                        const members = db.getGuildMembers(guild);
                        members.forEach(m => {
                            if (onlineWS[m.username]) onlineWS[m.username].send(JSON.stringify({ type: 'voiceUserLeft', user: target, voiceChannelId: vcId }));
                        });
                        // notify the kicked user specifically
                        if (onlineWS[target]) {
                            onlineWS[target].send(JSON.stringify({ type: 'kickedFromVoice', voiceChannelId: vcId, by: username }));
                        }
                    }
                }
            } catch (e) {
                console.error('WebSocket message error:', e);
            }
        });
        ws.on("close", () => {
            try {
                // Only perform cleanup if this websocket is still the current connection
                if (onlineWS[username] !== ws) {
                    // A newer connection has already replaced this one; skip cleanup
                    return;
                }
                delete onlineWS[username];

                // Remove user from typing state in all channels
                Object.keys(typingUsers).forEach(key => {
                    const [guildId, channel] = key.split(':');
                    if (guildId === guild && typingUsers[key]) {
                        typingUsers[key].delete(username);

                        // Broadcast updated typing status
                        const typingList = Array.from(typingUsers[key]);
                        const members = db.getGuildMembers(guild);
                        members.forEach(m => {
                            if (onlineWS[m.username]) {
                                onlineWS[m.username].send(JSON.stringify({
                                    type: "typing",
                                    channel: channel,
                                    users: typingList
                                }));
                            }
                        });
                    }
                });

                // Remove user from all voice channels they were in and notify
                Object.keys(voiceUsers).forEach(vcId => {
                    if (voiceUsers[vcId] && voiceUsers[vcId].includes(username)) {
                        voiceUsers[vcId] = voiceUsers[vcId].filter(u => u !== username);

                        // Get the voice channel to find its guild
                        const vc = db.getVoiceChannelById(vcId);
                        if (vc) {
                            const vcGuildId = vc.guild_id;
                            const members = db.getGuildMembers(vcGuildId);
                            members.forEach(m => {
                                if (onlineWS[m.username]) {
                                    onlineWS[m.username].send(JSON.stringify({
                                        type: 'voiceUserLeft',
                                        user: username,
                                        voiceChannelId: vcId
                                    }));
                                }
                            });
                        }
                    }
                });


                // Notify only users who share a guild with this user that they went offline
                notifySharedUsers(user.id, { type: "presence", user: username, status: "offline" });
            } catch (e) {
                console.error('WebSocket close error:', e);
            }
        });
    } catch (e) {
        console.error('WebSocket connection error:', e);
    }
});

app.get('/favicon.png', (req, res) => {
    res.sendFile(path.join(__dirname, 'favicon.png'));
})

// Global error handler - must be last middleware
// Catches any unhandled errors and prevents exposing details to clients
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    // Never expose internal error details to users
    res.status(500).send('Bir hata oluştu');
});

server.listen(3000, () => console.log("Server çalışıyor → localhost:3000"));

(async function () {
    try {
        const listener = await ngrok.forward({ addr: "https://localhost:3000", authtoken: process.env.NGROK_AUTHTOKEN });
        console.log(`Ngrok established at: ${listener.url()}`);
    } catch (e) { console.log(e); }
})();