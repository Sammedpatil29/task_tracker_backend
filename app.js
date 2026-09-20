import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Sequelize, DataTypes, Op } from 'sequelize';
import 'dotenv/config';
import { sendOtpEmail, sendPasswordResetOtpEmail } from './emailService.js';
import multer from 'multer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* =========================================================================
   1. HARDENED SECURITY CONFIGURATION & HEADERS
========================================================================= */

// Disable fingerprinting
app.disable('x-powered-by');

// Security Response Headers (Defense in Depth / Helmet equivalent)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY'); // Anti-Clickjacking
  res.setHeader('X-Content-Type-Options', 'nosniff'); // Anti-MIME Sniffing
  res.setHeader('X-XSS-Protection', '1; mode=block'); // Anti-XSS Filter
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Strict Payload Limits (Anti-DoS / Buffer Overflow)
app.use(express.json({ limit: '25kb' }));
app.use(express.urlencoded({ extended: false, limit: '25kb' }));

// CORS Whitelisting
const defaultMobileOrigins = [
  'https://localhost',
  'http://localhost',
  'capacitor://localhost',
  'ionic://localhost',
  'http://localhost:4200',
  'http://127.0.0.1:4200',
  'http://localhost:8100',
  'http://127.0.0.1:8100'
];

const rawOrigins = process.env.ALLOWED_ORIGINS || '';
const customOrigins = rawOrigins.split(',').map(o => o.trim()).filter(Boolean);
const allowedOrigins = Array.from(new Set([...defaultMobileOrigins, ...customOrigins]));

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (e.g. mobile apps native HTTP/curl/Postman) or matched origins
    if (!origin) {
      return callback(null, true);
    }
    // Allow whitelisted origins, mobile app schemes (capacitor://, ionic://), and localhost/127.0.0.1 on any port
    if (
      allowedOrigins.includes(origin) ||
      origin.startsWith('capacitor://') ||
      origin.startsWith('ionic://') ||
      /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)
    ) {
      return callback(null, true);
    }
    return callback(new Error(`CORS Policy: Request origin '${origin}' is blocked by security rules`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-ota-secret', 'x-forwarded-proto']
}));

// Serve OTA Updates (Bundles & Manifests)
const otaPublicDir = path.join(__dirname, 'public', 'ota');
const otaBundlesDir = path.join(otaPublicDir, 'bundles');
if (!fs.existsSync(otaBundlesDir)) {
  fs.mkdirSync(otaBundlesDir, { recursive: true });
}
app.use('/ota', express.static(otaPublicDir));

// Configure multer storage for direct OTA uploads
const otaStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, otaBundlesDir);
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});
const otaUpload = multer({
  storage: otaStorage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// Direct OTA Bundle Upload Endpoint (Called by publish-ota CLI script)
app.post('/api/ota/upload-bundle', otaUpload.single('file'), async (req, res) => {
  try {
    const secret = req.headers['x-ota-secret'] || req.headers.authorization?.replace(/^Bearer\s+/i, '');
    const validSecret = process.env.OTA_SECRET_KEY || 'discipline-tracker-ota-secret-key-2026';

    if (!secret || secret !== validSecret) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized: Invalid or missing OTA secret key.'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No bundle file uploaded.'
      });
    }

    const {
      appId = 'com.discipline.tasktracker',
      channel = '__base__',
      runtime = '__default__',
      version,
      manifest: rawManifest,
      forceImmediate
    } = req.body;

    let parsedManifest = {};
    if (rawManifest) {
      try {
        parsedManifest = typeof rawManifest === 'string' ? JSON.parse(rawManifest) : rawManifest;
      } catch (e) {
        parsedManifest = {};
      }
    }

    const relVersion = version || parsedManifest.version || '1.0.0';
    const bundleFileName = req.file.filename;

    const manifestDir = path.join(otaPublicDir, 'manifests', appId, channel, runtime);
    fs.mkdirSync(manifestDir, { recursive: true });

    let hostUrl = process.env.OTA_CDN_URL;
    if (!hostUrl) {
      const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').replace(/:$/, '');
      const host = req.get('host') || 'discipline-tracker-backend-xckgge-ddd24d-203-57-85-153.sslip.io';
      hostUrl = `${proto}://${host}/ota`;
    }

    if (!hostUrl.includes('localhost') && !hostUrl.includes('127.0.0.1')) {
      hostUrl = hostUrl.replace(/^http:\/\//i, 'https://');
    }

    let bundleUrl = (parsedManifest.url && typeof parsedManifest.url === 'string' && parsedManifest.url.startsWith('http'))
      ? parsedManifest.url
      : `${hostUrl}/bundles/${bundleFileName}`;

    if (!bundleUrl.includes('localhost') && !bundleUrl.includes('127.0.0.1')) {
      bundleUrl = bundleUrl.replace(/^http:\/\//i, 'https://');
    }

    const finalManifest = {
      version: relVersion,
      url: bundleUrl,
      sha256: parsedManifest.sha256 || '',
      size: req.file.size,
      releaseId: parsedManifest.releaseId || `${appId}-${relVersion}-${Date.now().toString(36)}`,
      strategy: 'zip',
      forceImmediate: forceImmediate === 'true' || forceImmediate === true || parsedManifest.forceImmediate === true
    };

    // 1. Channel / runtime manifest
    const manifestFilePath = path.join(manifestDir, 'manifest.json');
    fs.writeFileSync(manifestFilePath, JSON.stringify(finalManifest, null, 2), 'utf-8');

    // 2. Convenience top-level manifests
    const rootManifestDir = path.join(otaPublicDir, 'manifests', appId);
    fs.mkdirSync(rootManifestDir, { recursive: true });
    fs.writeFileSync(path.join(rootManifestDir, 'manifest.json'), JSON.stringify(finalManifest, null, 2), 'utf-8');
    fs.writeFileSync(path.join(otaPublicDir, 'manifest.json'), JSON.stringify(finalManifest, null, 2), 'utf-8');

    console.log(`🚀 [OTA] Direct upload successful: bundle v${relVersion} for ${appId}`);

    return res.json({
      success: true,
      message: `Bundle ${bundleFileName} uploaded and manifest v${relVersion} published directly to server.`,
      version: relVersion,
      bundleUrl: bundleUrl,
      manifestUrl: `${hostUrl}/manifests/${appId}/${channel}/${runtime}/manifest.json`
    });

  } catch (error) {
    console.error('OTA Upload Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to upload OTA bundle',
      error: error.message
    });
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'b8d7a1e4c9f3028b5e6172a8c3d94e015f6a7b8c9d0e1f2a3b4c5d6e7f8091a2';

/* =========================================================================
   2. IN-MEMORY RATE LIMITING (Anti-Brute Force & Anti-DoS)
========================================================================= */

const rateLimitStore = new Map();

// Periodic cleanup of stale rate-limit memory (every 10 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now > record.resetTime) {
      rateLimitStore.delete(key);
    }
  }
}, 10 * 60 * 1000);

const createRateLimiter = (options = { windowMs: 15 * 60 * 1000, max: 100, message: 'Too many requests' }) => {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const key = `${req.baseUrl || req.path}_${ip}`;
    const now = Date.now();

    let record = rateLimitStore.get(key);

    if (!record || now > record.resetTime) {
      record = { count: 1, resetTime: now + options.windowMs };
      rateLimitStore.set(key, record);
      return next();
    }

    record.count++;
    if (record.count > options.max) {
      const retryAfter = Math.ceil((record.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: options.message,
        retryAfterSeconds: retryAfter
      });
    }

    next();
  };
};

// Rate Limiters
const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 15, // Max 15 attempts
  message: 'Security Alert: Too many login/registration attempts. Please try again in 15 minutes.'
});

const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 min
  max: 180, // Max 180 requests/min
  message: 'Too many API requests. Please slow down.'
});

app.use('/api/', apiLimiter);

/* =========================================================================
   3. INPUT SANITIZATION & VALIDATION HELPERS
========================================================================= */

const sanitizeText = (input, maxLength = 100) => {
  if (typeof input !== 'string') return '';
  return input
    .replace(/[<>]/g, '') // Strip script injection chars
    .trim()
    .slice(0, maxLength);
};

const isValidEmail = (email) => {
  if (typeof email !== 'string') return false;
  const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return re.test(email.trim()) && email.length <= 120;
};

const isValidDate = (dateStr) => {
  if (typeof dateStr !== 'string') return false;
  return /^\d{4}-\d{2}-\d{2}$/.test(dateStr);
};

/* =========================================================================
   4. DATABASE (POSTGRESQL / NEON)
========================================================================= */

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});

/* =========================================================================
   5. MODELS
========================================================================= */

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING(100), allowNull: false },
  email: { type: DataTypes.STRING(120), unique: true, allowNull: false },
  password: { type: DataTypes.STRING(255), allowNull: false },
  emoji: { type: DataTypes.STRING(20), defaultValue: '🌱' },
  hydrationEnabled: { type: DataTypes.BOOLEAN, defaultValue: true },
  hydrationSoundEnabled: { type: DataTypes.BOOLEAN, defaultValue: true },
  hydrationIntervalMinutes: { type: DataTypes.INTEGER, defaultValue: 30 },
  premiumUntil: { type: DataTypes.DATE, allowNull: true },
  lastAdWatchedAt: { type: DataTypes.DATE, allowNull: true }
});

const Task = sequelize.define('Task', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING(120), allowNull: false },
  weeklyTarget: { type: DataTypes.INTEGER, defaultValue: 7 },
  enabled: { type: DataTypes.BOOLEAN, defaultValue: true }
});

const Completion = sequelize.define('Completion', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  date: { type: DataTypes.DATEONLY, allowNull: false },
  completed: { type: DataTypes.BOOLEAN, defaultValue: false }
}, {
  indexes: [
    { unique: true, fields: ['UserId', 'TaskId', 'date'] }
  ]
});

const Achievement = sequelize.define('Achievement', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  badgeKey: { type: DataTypes.STRING(60), allowNull: false },
  unlockedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, {
  indexes: [
    { unique: true, fields: ['UserId', 'badgeKey'] }
  ]
});

const ProductivityCategory = sequelize.define('ProductivityCategory', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING(80), allowNull: false },
  targetHours: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 2.0 },
  emoji: { type: DataTypes.STRING(20), defaultValue: '⚡' },
  color: { type: DataTypes.STRING(20), defaultValue: '#10b981' }
});

const ActivityLog = sequelize.define('ActivityLog', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  title: { type: DataTypes.STRING(120), allowNull: false },
  date: { type: DataTypes.DATEONLY, allowNull: false },
  startTime: { type: DataTypes.STRING(10), allowNull: false }, // "HH:MM"
  endTime: { type: DataTypes.STRING(10), allowNull: false },   // "HH:MM"
  durationMinutes: { type: DataTypes.INTEGER, allowNull: false },
  ProductivityCategoryId: { type: DataTypes.INTEGER, allowNull: true }
}, {
  indexes: [
    { fields: ['UserId', 'date'] }
  ]
});

// Diet Goal - one per user, stores daily calorie + macro targets
const DietGoal = sequelize.define('DietGoal', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  dailyCalories: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 2000 },
  proteinG: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 150 },  // grams
  carbsG: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 200 },    // grams
  fatG: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 65 },       // grams
  fiberG: { type: DataTypes.FLOAT, allowNull: true, defaultValue: 30 },      // grams
  waterMl: { type: DataTypes.FLOAT, allowNull: true, defaultValue: 2500 }    // ml
});

// Meal Log - daily food entries with calorie and macro breakdown
const MealLog = sequelize.define('MealLog', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING(150), allowNull: false },  // food/meal name
  date: { type: DataTypes.DATEONLY, allowNull: false },
  mealType: { type: DataTypes.STRING(30), allowNull: false, defaultValue: 'Meal' }, // Breakfast, Lunch, Dinner, Snack
  calories: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 0 },
  proteinG: { type: DataTypes.FLOAT, allowNull: true, defaultValue: 0 },
  carbsG: { type: DataTypes.FLOAT, allowNull: true, defaultValue: 0 },
  fatG: { type: DataTypes.FLOAT, allowNull: true, defaultValue: 0 },
  fiberG: { type: DataTypes.FLOAT, allowNull: true, defaultValue: 0 },
  notes: { type: DataTypes.STRING(300), allowNull: true }
}, {
  indexes: [
    { fields: ['UserId', 'date'] }
  ]
});

/* =========================================================================
   6. RELATIONS
========================================================================= */

User.hasMany(Task, { onDelete: 'CASCADE' });
Task.belongsTo(User);

User.hasMany(Completion, { onDelete: 'CASCADE' });
Completion.belongsTo(User);

Task.hasMany(Completion, { onDelete: 'CASCADE' });
Completion.belongsTo(Task);

User.hasMany(Achievement, { onDelete: 'CASCADE' });
Achievement.belongsTo(User);

User.hasMany(ProductivityCategory, { foreignKey: 'UserId', onDelete: 'CASCADE' });
ProductivityCategory.belongsTo(User, { foreignKey: 'UserId' });

User.hasMany(ActivityLog, { foreignKey: 'UserId', onDelete: 'CASCADE' });
ActivityLog.belongsTo(User, { foreignKey: 'UserId' });

ProductivityCategory.hasMany(ActivityLog, { foreignKey: 'ProductivityCategoryId', onDelete: 'SET NULL' });
ActivityLog.belongsTo(ProductivityCategory, { foreignKey: 'ProductivityCategoryId' });

User.hasOne(DietGoal, { foreignKey: 'UserId', onDelete: 'CASCADE' });
DietGoal.belongsTo(User, { foreignKey: 'UserId' });

User.hasMany(MealLog, { foreignKey: 'UserId', onDelete: 'CASCADE' });
MealLog.belongsTo(User, { foreignKey: 'UserId' });

// Water Log - daily water intake in ml
const WaterLog = sequelize.define('WaterLog', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  date: { type: DataTypes.DATEONLY, allowNull: false },
  amountMl: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 0 }
}, {
  indexes: [
    { unique: true, fields: ['UserId', 'date'] }
  ]
});

User.hasMany(WaterLog, { foreignKey: 'UserId', onDelete: 'CASCADE' });
WaterLog.belongsTo(User, { foreignKey: 'UserId' });

/* =========================================================================
   7. SECURE AUTHENTICATION MIDDLEWARE
========================================================================= */

const auth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access Denied: Missing or malformed authorization token' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;

    // Verify user still exists in database
    const user = await User.findByPk(decoded.id, { attributes: ['id', 'email'] });
    if (!user) {
      return res.status(401).json({ error: 'User account no longer exists or has been deactivated' });
    }

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Security Warning: Invalid authentication token' });
  }
};

/* =========================================================================
   8. OTP STORES (In-Memory with 10-minute TTL and 5-attempt brute force shield)
========================================================================= */

const otpStore = new Map();
const passwordResetStore = new Map();

// Periodic cleanup of expired OTP & Password Reset records
setInterval(() => {
  const now = Date.now();
  for (const [email, record] of otpStore.entries()) {
    if (now > record.expiresAt) {
      otpStore.delete(email);
    }
  }
  for (const [email, record] of passwordResetStore.entries()) {
    if (now > record.expiresAt) {
      passwordResetStore.delete(email);
    }
  }
}, 5 * 60 * 1000);

/* =========================================================================
   9. AUTH & EMAIL OTP ROUTES
========================================================================= */

// STEP A: Forgot Password - Request Reset Code
app.post('/auth/forgot-password', authLimiter, async (req, res) => {
  try {
    let { email } = req.body;
    email = typeof email === 'string' ? email.toLowerCase().trim() : '';

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      // Return ambiguous response to avoid account enumeration
      return res.json({
        success: true,
        message: 'If an account exists with this email address, a password reset code has been sent.'
      });
    }

    // Rate limit cooldown (45 seconds)
    const existingReset = passwordResetStore.get(email);
    if (existingReset && Date.now() - existingReset.lastSentAt < 45 * 1000) {
      const waitSec = Math.ceil((45 * 1000 - (Date.now() - existingReset.lastSentAt)) / 1000);
      return res.status(429).json({
        error: `Please wait ${waitSec} seconds before requesting another reset code.`
      });
    }

    const otp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    passwordResetStore.set(email, {
      otp,
      email,
      name: user.name,
      expiresAt,
      attempts: 0,
      lastSentAt: Date.now()
    });

    await sendPasswordResetOtpEmail({
      toEmail: email,
      name: user.name,
      otp
    });

    res.json({
      success: true,
      message: `A password reset code has been sent to ${email}.`,
      expiresInSeconds: 600
    });

  } catch (err) {
    console.error('Forgot Password Error:', err);
    res.status(500).json({ error: 'Failed to process password reset request. Please try again.' });
  }
});

// STEP B: Reset Password with OTP Verification
app.post('/auth/reset-password', authLimiter, async (req, res) => {
  try {
    let { email, otp, newPassword } = req.body;
    email = typeof email === 'string' ? email.toLowerCase().trim() : '';
    otp = typeof otp === 'string' ? otp.trim() : '';

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }

    if (!otp || otp.length !== 6) {
      return res.status(400).json({ error: 'Please enter the 6-digit verification code' });
    }

    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }

    const resetRecord = passwordResetStore.get(email);
    if (!resetRecord) {
      return res.status(400).json({
        error: 'Reset code not found or expired. Please request a new code.'
      });
    }

    if (Date.now() > resetRecord.expiresAt) {
      passwordResetStore.delete(email);
      return res.status(400).json({
        error: 'Reset code has expired. Please request a new code.'
      });
    }

    if (resetRecord.attempts >= 5) {
      passwordResetStore.delete(email);
      return res.status(429).json({
        error: 'Too many incorrect attempts. Please request a new reset code.'
      });
    }

    if (resetRecord.otp !== otp) {
      resetRecord.attempts++;
      const remaining = 5 - resetRecord.attempts;
      return res.status(400).json({
        error: `Incorrect verification code. ${remaining} attempt(s) remaining.`
      });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      passwordResetStore.delete(email);
      return res.status(404).json({ error: 'User account not found' });
    }

    // Hash new password & save
    const hash = await bcrypt.hash(newPassword, 11);
    user.password = hash;
    await user.save();

    // Delete used reset record
    passwordResetStore.delete(email);

    res.json({
      success: true,
      message: 'Password reset successful! You can now sign in with your new password. 🎉'
    });

  } catch (err) {
    console.error('Reset Password Error:', err);
    res.status(500).json({ error: 'Failed to reset password. Please try again.' });
  }
});

// STEP 1: Send Verification OTP to Email
app.post('/auth/send-otp', authLimiter, async (req, res) => {
  try {
    let { name, email, password } = req.body;

    name = sanitizeText(name, 60);
    email = typeof email === 'string' ? email.toLowerCase().trim() : '';

    if (!name || name.length < 2) {
      return res.status(400).json({ error: 'Full name must be at least 2 characters' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if email already registered
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email address already exists' });
    }

    // Check resend rate limit (45 seconds cooldown)
    const existingOtp = otpStore.get(email);
    if (existingOtp && Date.now() - existingOtp.lastSentAt < 45 * 1000) {
      const waitSec = Math.ceil((45 * 1000 - (Date.now() - existingOtp.lastSentAt)) / 1000);
      return res.status(429).json({
        error: `Please wait ${waitSec} seconds before requesting another verification code.`
      });
    }

    // Generate secure 6-digit OTP
    const otp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    otpStore.set(email, {
      otp,
      name,
      email,
      expiresAt,
      attempts: 0,
      lastSentAt: Date.now()
    });

    // Send email using nodemailer
    await sendOtpEmail({
      toEmail: email,
      name,
      otp
    });

    res.json({
      success: true,
      message: `A 6-digit verification code has been sent to ${email}.`,
      expiresInSeconds: 600
    });

  } catch (err) {
    console.error('Send OTP Error:', err);
    res.status(500).json({ error: 'Failed to send verification email. Please verify your email or try again.' });
  }
});

// STEP 2: Resend Verification OTP
app.post('/auth/resend-otp', authLimiter, async (req, res) => {
  try {
    let { email, name } = req.body;
    email = typeof email === 'string' ? email.toLowerCase().trim() : '';

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }

    const existingOtp = otpStore.get(email);
    if (existingOtp && Date.now() - existingOtp.lastSentAt < 45 * 1000) {
      const waitSec = Math.ceil((45 * 1000 - (Date.now() - existingOtp.lastSentAt)) / 1000);
      return res.status(429).json({
        error: `Please wait ${waitSec} seconds before requesting a new code.`
      });
    }

    const otp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    otpStore.set(email, {
      otp,
      name: name || existingOtp?.name || 'User',
      email,
      expiresAt,
      attempts: 0,
      lastSentAt: Date.now()
    });

    await sendOtpEmail({
      toEmail: email,
      name: name || existingOtp?.name,
      otp
    });

    res.json({
      success: true,
      message: `A new verification code was sent to ${email}.`
    });

  } catch (err) {
    console.error('Resend OTP Error:', err);
    res.status(500).json({ error: 'Failed to resend verification code' });
  }
});

// STEP 3: Verify OTP & Complete Account Registration
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    let { name, email, password, emoji, otp } = req.body;

    name = sanitizeText(name, 60);
    email = typeof email === 'string' ? email.toLowerCase().trim() : '';
    emoji = sanitizeText(emoji, 10) || '🌱';
    otp = typeof otp === 'string' ? otp.trim() : '';

    if (!name || name.length < 2) {
      return res.status(400).json({ error: 'Full name must be at least 2 characters' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    if (!otp || otp.length !== 6) {
      return res.status(400).json({ error: 'Please enter the 6-digit verification code' });
    }

    // Verify OTP Record
    const otpRecord = otpStore.get(email);
    if (!otpRecord) {
      return res.status(400).json({
        error: 'Verification code not found or expired. Please request a new code.'
      });
    }

    if (Date.now() > otpRecord.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({
        error: 'Verification code has expired. Please request a new code.'
      });
    }

    // Rate limit incorrect verification attempts
    if (otpRecord.attempts >= 5) {
      otpStore.delete(email);
      return res.status(429).json({
        error: 'Too many incorrect attempts. Please request a fresh verification code.'
      });
    }

    if (otpRecord.otp !== otp) {
      otpRecord.attempts++;
      const remaining = 5 - otpRecord.attempts;
      return res.status(400).json({
        error: `Incorrect verification code. ${remaining} attempt(s) remaining.`
      });
    }

    // Check for double registration race condition
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      otpStore.delete(email);
      return res.status(409).json({ error: 'An account with this email address already exists' });
    }

    // Hash Password & Create User
    const hash = await bcrypt.hash(password, 11);

    const user = await User.create({
      name,
      email,
      password: hash,
      emoji
    });

    // Delete used OTP
    otpStore.delete(email);

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      message: 'Account verified and created successfully! 🎉',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emoji: user.emoji
      }
    });

  } catch (err) {
    console.error('Registration Error:', err);
    res.status(500).json({ error: 'An error occurred during registration. Please try again.' });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    let { email, password } = req.body;

    email = typeof email === 'string' ? email.toLowerCase().trim() : '';

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      // Mitigate timing enumeration attack
      await bcrypt.compare(password, '$2a$11$DummyHashToPreventTimingEnumerationAttacks.XYZ');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    console.error('Login Security Error:', err);
    res.status(500).json({ error: 'An error occurred during sign in. Please try again.' });
  }
});

/* =========================================================================
   9. SECURE DASHBOARD & API ROUTES
========================================================================= */

app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: ['id', 'name', 'email', 'emoji', 'hydrationEnabled', 'hydrationSoundEnabled', 'hydrationIntervalMinutes']
    });

    if (!user) return res.status(404).json({ error: 'User not found' });

    // IDOR Protection: Strictly scoped to req.user.id
    const tasks = await Task.findAll({
      where: { UserId: user.id },
      order: [['id', 'ASC']]
    });

    const completions = await Completion.findAll({
      where: { UserId: user.id }
    });

    // Evaluate & Sync Unlocked Achievements to Database
    const completedList = completions.filter(c => c.completed);
    const activeTasks = tasks.filter(t => t.enabled !== false);

    const dateMap = new Map();
    for (const c of completedList) {
      if (!dateMap.has(c.date)) dateMap.set(c.date, new Set());
      dateMap.get(c.date).add(c.TaskId);
    }

    let maxStreak = 0;
    let curStreak = 0;
    const today = new Date();
    for (let i = 180; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      const y = d.getFullYear();
      const m = String(d.getMonth() + 1).padStart(2, '0');
      const day = String(d.getDate()).padStart(2, '0');
      const dStr = `${y}-${m}-${day}`;
      if (dateMap.has(dStr)) {
        curStreak++;
        if (curStreak > maxStreak) maxStreak = curStreak;
      } else {
        curStreak = 0;
      }
    }

    const eligibleBadges = [];
    if (completedList.length >= 1) eligibleBadges.push('first_win');
    if (maxStreak >= 3) eligibleBadges.push('streak_3');
    if (maxStreak >= 7) eligibleBadges.push('streak_7');
    if (completedList.length >= 50) eligibleBadges.push('centurion');

    if (activeTasks.length > 0) {
      for (const [_, set] of dateMap.entries()) {
        if (set.size >= activeTasks.length) {
          eligibleBadges.push('perfect_day');
          break;
        }
      }
    }

    // Persist any newly eligible achievements
    for (const badgeKey of eligibleBadges) {
      await Achievement.findOrCreate({
        where: { UserId: user.id, badgeKey },
        defaults: { unlockedAt: new Date() }
      });
    }

    const achievements = await Achievement.findAll({
      where: { UserId: user.id },
      attributes: ['badgeKey', 'unlockedAt']
    });

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emoji: user.emoji,
        hydrationEnabled: user.hydrationEnabled ?? true,
        hydrationSoundEnabled: user.hydrationSoundEnabled ?? true,
        hydrationIntervalMinutes: user.hydrationIntervalMinutes ?? 30
      },
      tasks,
      achievements: achievements.map(a => ({
        badgeKey: a.badgeKey,
        unlockedAt: a.unlockedAt
      })),
      completions: completions.map(c => ({
        taskId: c.TaskId,
        date: c.date,
        completed: c.completed
      }))
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

/* =========================================================================
   9.1 MANUAL / REAL-TIME ACHIEVEMENT UNLOCK
========================================================================= */

app.post('/api/achievements/unlock', auth, async (req, res) => {
  try {
    let { badgeKey } = req.body;
    badgeKey = sanitizeText(badgeKey, 60);
    if (!badgeKey) return res.status(400).json({ error: 'Badge key is required' });

    const [achievement, created] = await Achievement.findOrCreate({
      where: { UserId: req.user.id, badgeKey },
      defaults: { unlockedAt: new Date() }
    });

    res.json({
      success: true,
      achievement: {
        badgeKey: achievement.badgeKey,
        unlockedAt: achievement.unlockedAt
      },
      newlyUnlocked: created
    });
  } catch (err) {
    console.error('Unlock achievement error:', err);
    res.status(500).json({ error: 'Failed to record achievement' });
  }
});

/* =========================================================================
   10. UPDATE USER PROFILE (Email is protected / non-editable)
========================================================================= */

app.put('/api/user/profile', auth, async (req, res) => {
  try {
    const { name, emoji } = req.body;
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (name && typeof name === 'string') {
      const sanitizedName = sanitizeText(name, 60);
      if (sanitizedName.length >= 2) {
        user.name = sanitizedName;
      }
    }

    if (emoji && typeof emoji === 'string') {
      user.emoji = sanitizeText(emoji, 10);
    }

    await user.save();

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        emoji: user.emoji
      }
    });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

/* =========================================================================
   11. UPDATE HYDRATION PREFERENCES
========================================================================= */

app.put('/api/user/hydration', auth, async (req, res) => {
  try {
    const { enabled, soundEnabled, intervalMinutes } = req.body;
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (typeof enabled === 'boolean') {
      user.hydrationEnabled = enabled;
    }
    if (typeof soundEnabled === 'boolean') {
      user.hydrationSoundEnabled = soundEnabled;
    }
    if (typeof intervalMinutes === 'number' && intervalMinutes >= 5 && intervalMinutes <= 480) {
      user.hydrationIntervalMinutes = Math.round(intervalMinutes);
    }

    await user.save();

    res.json({
      success: true,
      hydrationSettings: {
        enabled: user.hydrationEnabled,
        soundEnabled: user.hydrationSoundEnabled,
        intervalMinutes: user.hydrationIntervalMinutes
      }
    });
  } catch (err) {
    console.error('Update hydration error:', err);
    res.status(500).json({ error: 'Failed to update hydration settings' });
  }
});

/* =========================================================================
   11.1 PREMIUM & REWARDED AD ROUTES (1-Ad-Per-Day Access System)
========================================================================= */

app.get('/api/user/premium-status', auth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: ['id', 'name', 'email', 'premiumUntil', 'lastAdWatchedAt']
    });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const now = new Date();
    const premiumUntil = user.premiumUntil ? new Date(user.premiumUntil) : null;
    const isPremium = premiumUntil !== null && premiumUntil > now;
    const remainingMs = isPremium ? Math.max(0, premiumUntil.getTime() - now.getTime()) : 0;
    const remainingHours = Math.floor(remainingMs / (1000 * 60 * 60));
    const remainingMinutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));

    res.json({
      success: true,
      isPremium,
      premiumUntil: premiumUntil ? premiumUntil.toISOString() : null,
      lastAdWatchedAt: user.lastAdWatchedAt ? user.lastAdWatchedAt.toISOString() : null,
      remainingHours,
      remainingMinutes,
      remainingFormatted: isPremium ? `${remainingHours}h ${remainingMinutes}m` : 'Expired'
    });
  } catch (err) {
    console.error('Get premium status error:', err);
    res.status(500).json({ error: 'Failed to retrieve premium status' });
  }
});

app.post('/api/user/claim-ad-reward', auth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const now = new Date();
    const oneDayMs = 24 * 60 * 60 * 1000;

    let baseTime = now;
    if (user.premiumUntil) {
      const currentExpiry = new Date(user.premiumUntil);
      if (currentExpiry > now) {
        baseTime = currentExpiry;
      }
    }

    const newExpiry = new Date(baseTime.getTime() + oneDayMs);
    user.premiumUntil = newExpiry;
    user.lastAdWatchedAt = now;
    await user.save();

    const remainingMs = Math.max(0, newExpiry.getTime() - now.getTime());
    const remainingHours = Math.floor(remainingMs / (1000 * 60 * 60));
    const remainingMinutes = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));

    res.json({
      success: true,
      message: '1-Day Premium access unlocked successfully! 🎉',
      isPremium: true,
      premiumUntil: newExpiry.toISOString(),
      lastAdWatchedAt: now.toISOString(),
      remainingHours,
      remainingMinutes,
      remainingFormatted: `${remainingHours}h ${remainingMinutes}m`
    });
  } catch (err) {
    console.error('Claim ad reward error:', err);
    res.status(500).json({ error: 'Failed to claim ad reward' });
  }
});

/* =========================================================================
   12. CREATE TASK
========================================================================= */

app.post('/api/tasks', auth, async (req, res) => {
  try {
    let { name, weeklyTarget } = req.body;
    name = sanitizeText(name, 80);

    if (!name || name.length < 1) {
      return res.status(400).json({ error: 'Task name is required' });
    }

    const target = Number(weeklyTarget);
    const validTarget = (!isNaN(target) && target >= 1 && target <= 7) ? Math.round(target) : 7;

    const task = await Task.create({
      name,
      weeklyTarget: validTarget,
      UserId: req.user.id
    });

    res.status(201).json(task);
  } catch (err) {
    console.error('Create task error:', err);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

/* =========================================================================
   13. ENABLE / DISABLE TASK (IDOR Protected)
========================================================================= */

app.patch('/api/tasks/:id/toggle', auth, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id, 10);
    if (isNaN(taskId)) return res.status(400).json({ error: 'Invalid task ID' });

    const task = await Task.findOne({
      where: { id: taskId, UserId: req.user.id }
    });

    if (!task) return res.status(404).json({ error: 'Task not found or access denied' });

    task.enabled = !task.enabled;
    await task.save();

    res.json(task);
  } catch (err) {
    console.error('Toggle task error:', err);
    res.status(500).json({ error: 'Failed to toggle task' });
  }
});

/* =========================================================================
   14. DELETE TASK (IDOR Protected with Cascade Delete)
========================================================================= */

app.delete('/api/tasks/:id', auth, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id, 10);
    if (isNaN(taskId)) return res.status(400).json({ error: 'Invalid task ID' });

    const task = await Task.findOne({
      where: { id: taskId, UserId: req.user.id }
    });

    if (!task) return res.status(404).json({ error: 'Task not found or access denied' });

    // Remove associated completions
    await Completion.destroy({
      where: { TaskId: task.id, UserId: req.user.id }
    });

    // Remove task
    await task.destroy();

    res.json({ success: true, message: 'Task deleted successfully', id: taskId });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

/* =========================================================================
   15. COMPLETION (SELECT / DESELECT)
========================================================================= */

app.post('/api/completions', auth, async (req, res) => {
  try {
    let { taskId, date, completed } = req.body;

    taskId = parseInt(taskId, 10);
    if (isNaN(taskId)) return res.status(400).json({ error: 'Invalid task ID' });

    if (!isValidDate(date)) {
      return res.status(400).json({ error: 'Invalid date format (must be YYYY-MM-DD)' });
    }

    const isCompletedBool = Boolean(completed);

    const task = await Task.findOne({
      where: { id: taskId, UserId: req.user.id }
    });

    if (!task || !task.enabled) {
      return res.status(403).json({ error: 'Task disabled or access denied' });
    }

    const [entry, created] = await Completion.findOrCreate({
      where: {
        UserId: req.user.id,
        TaskId: taskId,
        date
      },
      defaults: { completed: isCompletedBool }
    });

    if (!created && entry.completed !== isCompletedBool) {
      entry.completed = isCompletedBool;
      await entry.save();
    }

    res.json({
      success: true,
      completion: { taskId, date, completed: isCompletedBool }
    });

  } catch (err) {
    console.error('Completion error:', err);
    res.status(500).json({ error: 'Failed to record completion' });
  }
});

/* =========================================================================
   16. PRODUCTIVITY TRACKER APIS (24h Goals & Overlap Protected Time Logs)
========================================================================= */

// Get user productivity categories
app.get('/api/productivity/categories', auth, async (req, res) => {
  try {
    const categories = await ProductivityCategory.findAll({
      where: { UserId: req.user.id },
      order: [['id', 'ASC']]
    });
    res.json(categories);
  } catch (err) {
    console.error('Get productivity categories error:', err);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// Bulk Save / Update productivity categories (Validates 24h total allocation)
app.post('/api/productivity/categories/bulk', auth, async (req, res) => {
  try {
    const { categories } = req.body;
    if (!Array.isArray(categories) || categories.length === 0) {
      return res.status(400).json({ error: 'At least one category is required' });
    }

    let totalHours = 0;
    const sanitizedCategories = [];

    for (const cat of categories) {
      const name = sanitizeText(cat.name, 60);
      const targetHours = parseFloat(cat.targetHours);
      const emoji = sanitizeText(cat.emoji || '⚡', 10);
      const color = sanitizeText(cat.color || '#10b981', 20);

      if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
      }
      if (isNaN(targetHours) || targetHours <= 0 || targetHours > 24) {
        return res.status(400).json({ error: `Invalid target hours for '${name}'` });
      }

      totalHours += targetHours;
      sanitizedCategories.push({
        name,
        targetHours: Math.round(targetHours * 10) / 10,
        emoji,
        color,
        UserId: req.user.id
      });
    }

    // Round total to 1 decimal place
    totalHours = Math.round(totalHours * 10) / 10;
    if (Math.abs(totalHours - 24.0) > 0.05) {
      return res.status(400).json({
        error: `Category goals must total exactly 24.0 hours (current total: ${totalHours} hrs)`
      });
    }

    // Remove old categories and recreate clean set
    await ProductivityCategory.destroy({ where: { UserId: req.user.id } });
    const created = await ProductivityCategory.bulkCreate(sanitizedCategories);

    res.json({
      success: true,
      message: 'Productivity categories and 24h goals saved successfully! 🎯',
      categories: created
    });
  } catch (err) {
    console.error('Save productivity categories error:', err);
    res.status(500).json({ error: 'Failed to save productivity categories' });
  }
});

// Helper to convert "HH:MM" to minutes from midnight
const timeToMinutes = (timeStr) => {
  if (!timeStr || typeof timeStr !== 'string') return -1;
  const parts = timeStr.trim().split(':');
  if (parts.length !== 2) return -1;
  const h = parseInt(parts[0], 10);
  const m = parseInt(parts[1], 10);
  if (isNaN(h) || isNaN(m) || h < 0 || h > 23 || m < 0 || m > 59) return -1;
  return h * 60 + m;
};

// Get activity logs for a specific date or date range
app.get('/api/productivity/logs', auth, async (req, res) => {
  try {
    const { date, startDate, endDate } = req.query;

    let whereClause = { UserId: req.user.id };

    if (startDate && endDate && isValidDate(startDate) && isValidDate(endDate)) {
      whereClause.date = { [Op.between]: [startDate, endDate] };
    } else if (date && isValidDate(date)) {
      whereClause.date = date;
    } else {
      return res.status(400).json({ error: 'Valid date or startDate & endDate range is required (YYYY-MM-DD)' });
    }

    const logs = await ActivityLog.findAll({
      where: whereClause,
      include: [{ model: ProductivityCategory, attributes: ['id', 'name', 'emoji', 'color', 'targetHours'] }],
      order: [['date', 'ASC'], ['startTime', 'ASC']]
    });

    res.json(logs);
  } catch (err) {
    console.error('Get activity logs error:', err);
    res.status(500).json({ error: 'Failed to fetch activity logs' });
  }
});

// Add activity log with STRICT NON-OVERLAPPING TIME validation
app.post('/api/productivity/logs', auth, async (req, res) => {
  try {
    let { title, date, startTime, endTime, categoryId } = req.body;

    title = sanitizeText(title, 120);
    if (!title) {
      return res.status(400).json({ error: 'Activity description/title is required' });
    }

    if (!isValidDate(date)) {
      return res.status(400).json({ error: 'Valid date format required (YYYY-MM-DD)' });
    }

    const startMin = timeToMinutes(startTime);
    const endMin = timeToMinutes(endTime);

    if (startMin === -1 || endMin === -1) {
      return res.status(400).json({ error: 'Start time and End time must be in HH:MM format' });
    }

    if (endMin <= startMin) {
      return res.status(400).json({ error: 'End time must be after Start time' });
    }

    const durationMinutes = endMin - startMin;

    // Verify Category exists & belongs to user (or allow null)
    let category = null;
    if (categoryId) {
      category = await ProductivityCategory.findOne({
        where: { id: categoryId, UserId: req.user.id }
      });
      if (!category) {
        return res.status(400).json({ error: 'Selected category not found' });
      }
    }

    // Check for ANY overlapping time slots on this date
    const existingLogs = await ActivityLog.findAll({
      where: { UserId: req.user.id, date }
    });

    for (const existing of existingLogs) {
      const exStart = timeToMinutes(existing.startTime);
      const exEnd = timeToMinutes(existing.endTime);

      // Overlap condition: (StartA < EndB) and (EndA > StartB)
      if (startMin < exEnd && endMin > exStart) {
        return res.status(409).json({
          error: `Time conflict: '${startTime} - ${endTime}' overlaps with existing activity '${existing.title}' (${existing.startTime} - ${existing.endTime})`
        });
      }
    }

    const newLog = await ActivityLog.create({
      title,
      date,
      startTime,
      endTime,
      durationMinutes,
      ProductivityCategoryId: category ? category.id : null,
      UserId: req.user.id
    });

    const fullLog = await ActivityLog.findByPk(newLog.id, {
      include: [{ model: ProductivityCategory, attributes: ['id', 'name', 'emoji', 'color', 'targetHours'] }]
    });

    res.status(201).json({
      success: true,
      log: fullLog
    });

  } catch (err) {
    console.error('Create activity log error:', err);
    res.status(500).json({ error: 'Failed to create activity log' });
  }
});

// Delete an activity log
app.delete('/api/productivity/logs/:id', auth, async (req, res) => {
  try {
    const logId = parseInt(req.params.id, 10);
    if (isNaN(logId)) return res.status(400).json({ error: 'Invalid log ID' });

    const log = await ActivityLog.findOne({
      where: { id: logId, UserId: req.user.id }
    });

    if (!log) {
      return res.status(404).json({ error: 'Activity log not found or access denied' });
    }

    await log.destroy();
    res.json({ success: true, message: 'Activity log deleted successfully', id: logId });
  } catch (err) {
    console.error('Delete activity log error:', err);
    res.status(500).json({ error: 'Failed to delete activity log' });
  }
});

/* =========================================================================
   16-B. DIET TRACKER API
========================================================================= */

// GET /api/diet/goal - get user's current diet goal
app.get('/api/diet/goal', auth, async (req, res) => {
  try {
    let goal = await DietGoal.findOne({ where: { UserId: req.user.id } });
    if (!goal) {
      // Return default without saving
      return res.json({
        dailyCalories: 2000,
        proteinG: 150,
        carbsG: 200,
        fatG: 65,
        fiberG: 30,
        waterMl: 2500,
        isDefault: true
      });
    }
    res.json(goal);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch diet goal' });
  }
});

// POST /api/diet/goal - create or update user's diet goal
app.post('/api/diet/goal', auth, async (req, res) => {
  try {
    const { dailyCalories, proteinG, carbsG, fatG, fiberG, waterMl } = req.body;

    if (!dailyCalories || dailyCalories < 500 || dailyCalories > 10000) {
      return res.status(400).json({ error: 'Daily calories must be between 500 and 10000' });
    }

    const [goal, created] = await DietGoal.findOrCreate({
      where: { UserId: req.user.id },
      defaults: {
        UserId: req.user.id,
        dailyCalories: Math.round(dailyCalories),
        proteinG: parseFloat(proteinG) || 150,
        carbsG: parseFloat(carbsG) || 200,
        fatG: parseFloat(fatG) || 65,
        fiberG: parseFloat(fiberG) || 30,
        waterMl: parseFloat(waterMl) || 2500
      }
    });

    if (!created) {
      await goal.update({
        dailyCalories: Math.round(dailyCalories),
        proteinG: parseFloat(proteinG) || 150,
        carbsG: parseFloat(carbsG) || 200,
        fatG: parseFloat(fatG) || 65,
        fiberG: fiberG != null ? parseFloat(fiberG) : 30,
        waterMl: waterMl != null ? parseFloat(waterMl) : 2500
      });
    }

    res.json(goal);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save diet goal' });
  }
});

// GET /api/diet/logs?date=YYYY-MM-DD - get all meal logs for a specific date
app.get('/api/diet/logs', auth, async (req, res) => {
  try {
    const { date, startDate, endDate } = req.query;

    let whereClause = { UserId: req.user.id };

    if (date) {
      whereClause.date = date;
    } else if (startDate && endDate) {
      whereClause.date = { [Op.between]: [startDate, endDate] };
    } else {
      return res.status(400).json({ error: 'date or startDate+endDate required' });
    }

    const logs = await MealLog.findAll({
      where: whereClause,
      order: [['createdAt', 'ASC']]
    });

    res.json(logs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch meal logs' });
  }
});

// POST /api/diet/logs - add a meal log entry
app.post('/api/diet/logs', auth, async (req, res) => {
  try {
    const { name, date, mealType, calories, proteinG, carbsG, fatG, fiberG, notes } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Meal name is required' });
    }
    if (!date) {
      return res.status(400).json({ error: 'Date is required' });
    }
    if (calories == null || parseFloat(calories) < 0) {
      return res.status(400).json({ error: 'Valid calories are required' });
    }

    const validMealTypes = ['Breakfast', 'Lunch', 'Dinner', 'Snack', 'Pre-Workout', 'Post-Workout', 'Meal'];
    const sanitizedMealType = validMealTypes.includes(mealType) ? mealType : 'Meal';

    const log = await MealLog.create({
      UserId: req.user.id,
      name: sanitizeText(name, 150),
      date,
      mealType: sanitizedMealType,
      calories: Math.round(parseFloat(calories) * 10) / 10,
      proteinG: proteinG != null ? Math.round(parseFloat(proteinG) * 10) / 10 : 0,
      carbsG: carbsG != null ? Math.round(parseFloat(carbsG) * 10) / 10 : 0,
      fatG: fatG != null ? Math.round(parseFloat(fatG) * 10) / 10 : 0,
      fiberG: fiberG != null ? Math.round(parseFloat(fiberG) * 10) / 10 : 0,
      notes: notes ? sanitizeText(notes, 300) : null
    });

    res.status(201).json(log);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to log meal' });
  }
});

// PUT /api/diet/logs/:id - update a meal log entry
app.put('/api/diet/logs/:id', auth, async (req, res) => {
  try {
    const log = await MealLog.findOne({ where: { id: req.params.id, UserId: req.user.id } });
    if (!log) return res.status(404).json({ error: 'Meal log not found' });

    const { name, mealType, calories, proteinG, carbsG, fatG, fiberG, notes } = req.body;
    const validMealTypes = ['Breakfast', 'Lunch', 'Dinner', 'Snack', 'Pre-Workout', 'Post-Workout', 'Meal'];

    await log.update({
      name: name ? sanitizeText(name, 150) : log.name,
      mealType: validMealTypes.includes(mealType) ? mealType : log.mealType,
      calories: calories != null ? Math.round(parseFloat(calories) * 10) / 10 : log.calories,
      proteinG: proteinG != null ? Math.round(parseFloat(proteinG) * 10) / 10 : log.proteinG,
      carbsG: carbsG != null ? Math.round(parseFloat(carbsG) * 10) / 10 : log.carbsG,
      fatG: fatG != null ? Math.round(parseFloat(fatG) * 10) / 10 : log.fatG,
      fiberG: fiberG != null ? Math.round(parseFloat(fiberG) * 10) / 10 : log.fiberG,
      notes: notes !== undefined ? (notes ? sanitizeText(notes, 300) : null) : log.notes
    });

    res.json(log);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update meal log' });
  }
});

// DELETE /api/diet/logs/:id - delete a meal log entry
app.delete('/api/diet/logs/:id', auth, async (req, res) => {
  try {
    const log = await MealLog.findOne({ where: { id: req.params.id, UserId: req.user.id } });
    if (!log) return res.status(404).json({ error: 'Meal log not found' });

    await log.destroy();
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete meal log' });
  }
});

// GET /api/diet/summary?startDate=X&endDate=Y - range summary for analytics
app.get('/api/diet/summary', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'startDate and endDate required' });
    }

    const [goal, logs] = await Promise.all([
      DietGoal.findOne({ where: { UserId: req.user.id } }),
      MealLog.findAll({
        where: { UserId: req.user.id, date: { [Op.between]: [startDate, endDate] } },
        order: [['date', 'ASC'], ['createdAt', 'ASC']]
      })
    ]);

    // Group logs by date
    const byDate = {};
    for (const log of logs) {
      if (!byDate[log.date]) byDate[log.date] = [];
      byDate[log.date].push(log);
    }

    res.json({ goal: goal || null, byDate });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch diet summary' });
  }
});

// GET /api/diet/water?date=YYYY-MM-DD - get water intake for a specific date
app.get('/api/diet/water', auth, async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ error: 'Date is required' });

    const log = await WaterLog.findOne({ where: { UserId: req.user.id, date } });
    res.json({ date, amountMl: log ? log.amountMl : 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch water log' });
  }
});

// POST /api/diet/water - log or adjust water intake
app.post('/api/diet/water', auth, async (req, res) => {
  try {
    const { date, amountMl, delta } = req.body;
    if (!date) return res.status(400).json({ error: 'Date is required' });

    let [log, created] = await WaterLog.findOrCreate({
      where: { UserId: req.user.id, date },
      defaults: { UserId: req.user.id, date, amountMl: 0 }
    });

    let newAmount = log.amountMl;
    if (delta !== undefined) {
      newAmount = Math.max(0, Math.round(log.amountMl + parseFloat(delta)));
    } else if (amountMl !== undefined) {
      newAmount = Math.max(0, Math.round(parseFloat(amountMl)));
    }

    await log.update({ amountMl: newAmount });
    res.json({ date, amountMl: log.amountMl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update water log' });
  }
});

/* =========================================================================
   16. FALLBACK 404 & GLOBAL ERROR HANDLER
========================================================================= */

app.use((req, res) => {
  res.status(404).json({ error: 'Resource not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled Exception:', err);
  res.status(500).json({ error: 'A secure server error occurred' });
});



/* =========================================================================
   17. SERVER INITIALIZATION
========================================================================= */

const PORT = process.env.PORT || 3000;

sequelize.sync({ alter: true }).then(() => {
  console.log('✅ PostgreSQL Security & Models Synchronized');
  app.listen(PORT, () =>
    console.log(`🔒 Secure API running on http://localhost:${PORT}`)
  );
}).catch(err => {
  console.error('❌ Database Connection Security Failure:', err);
});
