import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_FILE = path.join(__dirname, 'database.db');

// Initialize database connection
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL'); // Better performance for concurrent access
db.pragma('foreign_keys = ON'); // Enable foreign key constraints

// ==================== SCHEMA CREATION ====================

function initializeDatabase() {
    // Users table
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password TEXT NOT NULL,
            avatar TEXT DEFAULT 'default.png',
            bio TEXT DEFAULT '',
            created_at INTEGER DEFAULT (strftime('%s', 'now'))
        );
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    `);

    // Guilds table
    db.exec(`
        CREATE TABLE IF NOT EXISTS guilds (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            icon TEXT DEFAULT 'default.png',
            system_channel_id TEXT,
            invite_code TEXT UNIQUE,
            is_private INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_guilds_invite_code ON guilds(invite_code);
    `);

    // Guild members (many-to-many)
    db.exec(`
        CREATE TABLE IF NOT EXISTS guild_members (
            guild_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            joined_at INTEGER DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (guild_id, user_id),
            FOREIGN KEY (guild_id) REFERENCES guilds(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_guild_members_user ON guild_members(user_id);
    `);

    // Banned users
    db.exec(`
        CREATE TABLE IF NOT EXISTS banned_users (
            guild_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            banned_at INTEGER DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (guild_id, user_id),
            FOREIGN KEY (guild_id) REFERENCES guilds(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    `);

    // Text channels
    db.exec(`
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id TEXT NOT NULL,
            name TEXT NOT NULL,
            position INTEGER DEFAULT 0,
            send_enabled INTEGER DEFAULT 1,
            read_enabled INTEGER DEFAULT 1,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE (guild_id, name),
            FOREIGN KEY (guild_id) REFERENCES guilds(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_channels_guild ON channels(guild_id);
    `);

    // Voice channels
    db.exec(`
        CREATE TABLE IF NOT EXISTS voice_channels (
            id TEXT PRIMARY KEY,
            guild_id TEXT NOT NULL,
            name TEXT NOT NULL,
            read_enabled INTEGER DEFAULT 1,
            speak_enabled INTEGER DEFAULT 1,
            max_members INTEGER,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (guild_id) REFERENCES guilds(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_voice_channels_guild ON voice_channels(guild_id);
    `);

    // Messages
    db.exec(`
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            guild_id TEXT NOT NULL,
            channel_name TEXT NOT NULL,
            from_user_id TEXT,
            message_type TEXT CHECK(message_type IN ('user', 'system')) DEFAULT 'user',
            enc TEXT,
            iv TEXT,
            text TEXT,
            photo TEXT,
            reply_to TEXT,
            reply_from TEXT,
            reply_text TEXT,
            edited INTEGER DEFAULT 0,
            timestamp INTEGER NOT NULL,
            FOREIGN KEY (guild_id) REFERENCES guilds(id) ON DELETE CASCADE,
            FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_guild_channel ON messages(guild_id, channel_name);
        CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
    `);

    console.log('✅ Database schema initialized');
}

// Initialize on module load
initializeDatabase();

// ==================== PREPARED STATEMENTS ====================
// All queries use parameterized statements to prevent SQL injection

const stmts = {
    // ===== USER QUERIES =====
    getUserById: db.prepare('SELECT * FROM users WHERE id = ?'),
    getUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
    insertUser: db.prepare('INSERT INTO users (id, username, password, avatar, bio) VALUES (?, ?, ?, ?, ?)'),
    updateUserPassword: db.prepare('UPDATE users SET password = ? WHERE id = ?'),
    updateUserAvatar: db.prepare('UPDATE users SET avatar = ? WHERE id = ?'),
    updateUserBio: db.prepare('UPDATE users SET bio = ? WHERE id = ?'),
    updateUsername: db.prepare('UPDATE users SET username = ? WHERE id = ?'),
    deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),

    // ===== GUILD QUERIES =====
    getGuildById: db.prepare('SELECT * FROM guilds WHERE id = ?'),
    getGuildByInviteCode: db.prepare('SELECT * FROM guilds WHERE invite_code = ?'),
    insertGuild: db.prepare('INSERT INTO guilds (id, name, owner_id, icon, system_channel_id, invite_code, is_private) VALUES (?, ?, ?, ?, ?, ?, ?)'),
    updateGuildName: db.prepare('UPDATE guilds SET name = ? WHERE id = ?'),
    updateGuildIcon: db.prepare('UPDATE guilds SET icon = ? WHERE id = ?'),
    updateGuildOwner: db.prepare('UPDATE guilds SET owner_id = ? WHERE id = ?'),
    updateGuildInviteCode: db.prepare('UPDATE guilds SET invite_code = ? WHERE id = ?'),
    updateGuildPrivate: db.prepare('UPDATE guilds SET is_private = ? WHERE id = ?'),
    updateGuildSystemChannel: db.prepare('UPDATE guilds SET system_channel_id = ? WHERE id = ?'),
    deleteGuild: db.prepare('DELETE FROM guilds WHERE id = ?'),

    // ===== GUILD MEMBER QUERIES =====
    getGuildMembers: db.prepare(`
        SELECT u.id, u.username, u.avatar, u.bio, gm.is_admin 
        FROM users u 
        JOIN guild_members gm ON u.id = gm.user_id 
        WHERE gm.guild_id = ?
    `),
    getUserGuilds: db.prepare(`
        SELECT g.id, g.name, g.icon 
        FROM guilds g 
        JOIN guild_members gm ON g.id = gm.guild_id 
        WHERE gm.user_id = ?
    `),
    isGuildMember: db.prepare('SELECT 1 FROM guild_members WHERE guild_id = ? AND user_id = ?'),
    isGuildAdmin: db.prepare('SELECT is_admin FROM guild_members WHERE guild_id = ? AND user_id = ?'),
    insertGuildMember: db.prepare('INSERT INTO guild_members (guild_id, user_id, is_admin) VALUES (?, ?, ?)'),
    removeGuildMember: db.prepare('DELETE FROM guild_members WHERE guild_id = ? AND user_id = ?'),
    setGuildAdmin: db.prepare('UPDATE guild_members SET is_admin = ? WHERE guild_id = ? AND user_id = ?'),
    getGuildAdmins: db.prepare('SELECT user_id FROM guild_members WHERE guild_id = ? AND is_admin = 1'),

    // ===== BAN QUERIES =====
    isBanned: db.prepare('SELECT 1 FROM banned_users WHERE guild_id = ? AND user_id = ?'),
    banUser: db.prepare('INSERT OR IGNORE INTO banned_users (guild_id, user_id) VALUES (?, ?)'),
    unbanUser: db.prepare('DELETE FROM banned_users WHERE guild_id = ? AND user_id = ?'),
    getBannedUsers: db.prepare('SELECT user_id FROM banned_users WHERE guild_id = ?'),

    // ===== CHANNEL QUERIES =====
    getGuildChannels: db.prepare('SELECT name, send_enabled, read_enabled FROM channels WHERE guild_id = ? ORDER BY position'),
    getChannel: db.prepare('SELECT * FROM channels WHERE guild_id = ? AND name = ?'),
    insertChannel: db.prepare('INSERT INTO channels (guild_id, name, position, send_enabled, read_enabled) VALUES (?, ?, ?, ?, ?)'),
    deleteChannel: db.prepare('DELETE FROM channels WHERE guild_id = ? AND name = ?'),
    updateChannelName: db.prepare('UPDATE channels SET name = ? WHERE guild_id = ? AND name = ?'),
    updateChannelSettings: db.prepare('UPDATE channels SET send_enabled = ?, read_enabled = ? WHERE guild_id = ? AND name = ?'),
    // Individual channel setting updates
    updateChannelSendEnabled: db.prepare('UPDATE channels SET send_enabled = ? WHERE guild_id = ? AND name = ?'),
    updateChannelReadEnabled: db.prepare('UPDATE channels SET read_enabled = ? WHERE guild_id = ? AND name = ?'),

    // ===== VOICE CHANNEL QUERIES =====
    getGuildVoiceChannels: db.prepare('SELECT id, name, read_enabled, speak_enabled, max_members FROM voice_channels WHERE guild_id = ?'),
    getVoiceChannel: db.prepare('SELECT * FROM voice_channels WHERE id = ?'),
    getVoiceChannelByName: db.prepare('SELECT * FROM voice_channels WHERE guild_id = ? AND name = ?'),
    insertVoiceChannel: db.prepare('INSERT INTO voice_channels (id, guild_id, name, read_enabled, speak_enabled, max_members) VALUES (?, ?, ?, ?, ?, ?)'),
    deleteVoiceChannel: db.prepare('DELETE FROM voice_channels WHERE guild_id = ? AND name = ?'),
    updateVoiceChannelSettings: db.prepare('UPDATE voice_channels SET read_enabled = ?, speak_enabled = ?, max_members = ? WHERE guild_id = ? AND name = ?'),
    // Individual voice channel setting updates (by id)
    updateVoiceChannelReadEnabled: db.prepare('UPDATE voice_channels SET read_enabled = ? WHERE id = ?'),
    updateVoiceChannelSpeakEnabled: db.prepare('UPDATE voice_channels SET speak_enabled = ? WHERE id = ?'),
    updateVoiceChannelMaxMembers: db.prepare('UPDATE voice_channels SET max_members = ? WHERE id = ?'),

    // ===== MESSAGE QUERIES =====
    getMessages: db.prepare('SELECT * FROM messages WHERE guild_id = ? AND channel_name = ? ORDER BY timestamp ASC LIMIT ? OFFSET ?'),
    getMessage: db.prepare('SELECT * FROM messages WHERE id = ?'),
    insertMessage: db.prepare(`
        INSERT INTO messages (id, guild_id, channel_name, from_user_id, message_type, enc, iv, text, photo, reply_to, reply_from, reply_text, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `),
    updateMessage: db.prepare('UPDATE messages SET enc = ?, iv = ?, edited = 1 WHERE id = ?'),
    deleteMessage: db.prepare('DELETE FROM messages WHERE id = ?'),
    deleteChannelMessages: db.prepare('DELETE FROM messages WHERE guild_id = ? AND channel_name = ?'),
    updateMessageChannelName: db.prepare('UPDATE messages SET channel_name = ? WHERE guild_id = ? AND channel_name = ?'),
    getPhotoGuild: db.prepare('SELECT guild_id FROM messages WHERE photo = ? LIMIT 1'),

    // Old message cleanup
    getOldMessagesWithPhotos: db.prepare('SELECT id, photo FROM messages WHERE timestamp < ? AND photo IS NOT NULL'),
    deleteOldMessages: db.prepare('DELETE FROM messages WHERE timestamp < ?'),
};

// ==================== HELPER FUNCTIONS ====================

// User helpers
export function getUserById(userId) {
    return stmts.getUserById.get(userId);
}

export function getUserByUsername(username) {
    return stmts.getUserByUsername.get(username);
}

export function createUser(id, username, hashedPassword, avatar = 'default.png', bio = '') {
    return stmts.insertUser.run(id, username, hashedPassword, avatar, bio);
}

export function updateUserPassword(userId, hashedPassword) {
    return stmts.updateUserPassword.run(hashedPassword, userId);
}

export function updateUserAvatar(userId, avatar) {
    return stmts.updateUserAvatar.run(avatar, userId);
}

export function updateUserBio(userId, bio) {
    return stmts.updateUserBio.run(bio, userId);
}

export function updateUsername(userId, newUsername) {
    return stmts.updateUsername.run(newUsername, userId);
}

// Guild helpers
export function getGuildById(guildId) {
    return stmts.getGuildById.get(guildId);
}

export function getGuildByInviteCode(code) {
    return stmts.getGuildByInviteCode.get(code);
}

export function createGuild(id, name, ownerId, icon = 'default.png', systemChannelId = null, inviteCode = null, isPrivate = 0) {
    return stmts.insertGuild.run(id, name, ownerId, icon, systemChannelId, inviteCode, isPrivate);
}

export function updateGuildIcon(guildId, icon) {
    return stmts.updateGuildIcon.run(icon, guildId);
}

export function updateGuildInviteCode(guildId, code) {
    return stmts.updateGuildInviteCode.run(code, guildId);
}

export function updateGuildPrivate(guildId, isPrivate) {
    return stmts.updateGuildPrivate.run(isPrivate ? 1 : 0, guildId);
}

export function updateGuildSystemChannel(guildId, channelId) {
    return stmts.updateGuildSystemChannel.run(channelId, guildId);
}

export function updateGuildOwner(guildId, newOwnerId) {
    return stmts.updateGuildOwner.run(newOwnerId, guildId);
}

export function deleteGuild(guildId) {
    return stmts.deleteGuild.run(guildId);
}

// Guild member helpers
export function getGuildMembers(guildId) {
    return stmts.getGuildMembers.all(guildId);
}

export function getUserGuilds(userId) {
    return stmts.getUserGuilds.all(userId);
}

export function isGuildMember(guildId, userId) {
    return stmts.isGuildMember.get(guildId, userId) !== undefined;
}

export function getIsGuildAdmin(guildId, userId) {
    const result = stmts.isGuildAdmin.get(guildId, userId);
    return result ? result.is_admin === 1 : false;
}

export function addGuildMember(guildId, userId, isAdmin = false) {
    return stmts.insertGuildMember.run(guildId, userId, isAdmin ? 1 : 0);
}

export function removeGuildMember(guildId, userId) {
    return stmts.removeGuildMember.run(guildId, userId);
}

export function setGuildAdmin(guildId, userId, isAdmin) {
    return stmts.setGuildAdmin.run(isAdmin ? 1 : 0, guildId, userId);
}

export function getGuildAdmins(guildId) {
    return stmts.getGuildAdmins.all(guildId).map(row => row.user_id);
}

// Ban helpers
export function isBanned(guildId, userId) {
    return stmts.isBanned.get(guildId, userId) !== undefined;
}

export function banUser(guildId, userId) {
    return stmts.banUser.run(guildId, userId);
}

export function unbanUser(guildId, userId) {
    return stmts.unbanUser.run(guildId, userId);
}

export function getBannedUsers(guildId) {
    return stmts.getBannedUsers.all(guildId).map(row => row.user_id);
}

// Channel helpers
export function getGuildChannels(guildId) {
    return stmts.getGuildChannels.all(guildId);
}

export function getChannel(guildId, channelName) {
    return stmts.getChannel.get(guildId, channelName);
}

export function createChannel(guildId, channelName, position = 0, sendEnabled = true, readEnabled = true) {
    return stmts.insertChannel.run(guildId, channelName, position, sendEnabled ? 1 : 0, readEnabled ? 1 : 0);
}

export function deleteChannel(guildId, channelName) {
    return stmts.deleteChannel.run(guildId, channelName);
}

export function renameChannel(guildId, oldName, newName) {
    return stmts.updateChannelName.run(newName, guildId, oldName);
}

export function updateChannelSettings(guildId, channelName, sendEnabled, readEnabled) {
    return stmts.updateChannelSettings.run(sendEnabled ? 1 : 0, readEnabled ? 1 : 0, guildId, channelName);
}

// Individual channel setting updates
export function updateChannelSendEnabled(guildId, channelName, sendEnabled) {
    return stmts.updateChannelSendEnabled.run(sendEnabled ? 1 : 0, guildId, channelName);
}

export function updateChannelReadEnabled(guildId, channelName, readEnabled) {
    return stmts.updateChannelReadEnabled.run(readEnabled ? 1 : 0, guildId, channelName);
}

// Voice channel helpers
export function getGuildVoiceChannels(guildId) {
    return stmts.getGuildVoiceChannels.all(guildId);
}

export function getVoiceChannel(voiceChannelId) {
    return stmts.getVoiceChannel.get(voiceChannelId);
}

export function getVoiceChannelByName(guildId, channelName) {
    return stmts.getVoiceChannelByName.get(guildId, channelName);
}

export function createVoiceChannel(id, guildId, name, readEnabled = true, speakEnabled = true, maxMembers = null) {
    return stmts.insertVoiceChannel.run(id, guildId, name, readEnabled ? 1 : 0, speakEnabled ? 1 : 0, maxMembers);
}

export function deleteVoiceChannel(guildId, channelName) {
    return stmts.deleteVoiceChannel.run(guildId, channelName);
}

export function updateVoiceChannelSettings(guildId, channelName, readEnabled, speakEnabled, maxMembers) {
    return stmts.updateVoiceChannelSettings.run(
        readEnabled ? 1 : 0,
        speakEnabled ? 1 : 0,
        maxMembers,
        guildId,
        channelName
    );
}

// Individual voice channel setting updates (by id)
export function updateVoiceChannelReadEnabled(voiceChannelId, readEnabled) {
    return stmts.updateVoiceChannelReadEnabled.run(readEnabled ? 1 : 0, voiceChannelId);
}

export function updateVoiceChannelSpeakEnabled(voiceChannelId, speakEnabled) {
    return stmts.updateVoiceChannelSpeakEnabled.run(speakEnabled ? 1 : 0, voiceChannelId);
}

export function updateVoiceChannelMaxMembers(voiceChannelId, maxMembers) {
    return stmts.updateVoiceChannelMaxMembers.run(maxMembers, voiceChannelId);
}

// Alias for getVoiceChannel (used in index.js)
export function getVoiceChannelById(voiceChannelId) {
    return stmts.getVoiceChannel.get(voiceChannelId);
}

// Message helpers
export function getMessages(guildId, channelName, limit = 50, offset = 0) {
    return stmts.getMessages.all(guildId, channelName, limit, offset);
}

export function getMessage(messageId) {
    return stmts.getMessage.get(messageId);
}

export function createMessage(id, guildId, channelName, fromUserId, messageType, enc, iv, text, photo, replyTo, replyFrom, replyText, timestamp) {
    return stmts.insertMessage.run(
        id, guildId, channelName, fromUserId, messageType,
        enc, iv, text, photo, replyTo, replyFrom, replyText, timestamp
    );
}

export function updateMessage(messageId, enc, iv) {
    return stmts.updateMessage.run(enc, iv, messageId);
}

export function deleteMessage(messageId) {
    return stmts.deleteMessage.run(messageId);
}

export function deleteChannelMessages(guildId, channelName) {
    return stmts.deleteChannelMessages.run(guildId, channelName);
}

export function updateMessageChannelName(guildId, oldChannelName, newChannelName) {
    return stmts.updateMessageChannelName.run(newChannelName, guildId, oldChannelName);
}

export function getPhotoGuild(photoFilename) {
    const result = stmts.getPhotoGuild.get(photoFilename);
    return result ? result.guild_id : null;
}

// Old message cleanup helpers
export function getOldMessagesWithPhotos(beforeTimestamp) {
    return stmts.getOldMessagesWithPhotos.all(beforeTimestamp);
}

export function deleteOldMessages(beforeTimestamp) {
    return stmts.deleteOldMessages.run(beforeTimestamp);
}

// Transaction helpers
export function transaction(fn) {
    return db.transaction(fn);
}

// Check if two users share at least one guild
export function sharesGuild(userIdA, userIdB) {
    const guildsA = stmts.getUserGuilds.all(userIdA).map(g => g.id);
    const guildsB = stmts.getUserGuilds.all(userIdB).map(g => g.id);
    return guildsA.some(gid => guildsB.includes(gid));
}

// Export database instance for custom queries if needed
export default db;
