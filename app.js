import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Sequelize, DataTypes } from 'sequelize';
import 'dotenv/config';
import { sendOtpEmail, sendPasswordResetOtpEmail } from './emailService.js';

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
const rawOrigins = process.env.ALLOWED_ORIGINS || 'http://localhost:4200,http://127.0.0.1:4200';
const allowedOrigins = rawOrigins.split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (e.g. mobile apps/curl in dev) or matched origins
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS Policy: Request origin is blocked by security rules'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

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
  hydrationIntervalMinutes: { type: DataTypes.INTEGER, defaultValue: 30 }
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

/* =========================================================================
   6. RELATIONS
========================================================================= */

User.hasMany(Task, { onDelete: 'CASCADE' });
Task.belongsTo(User);

User.hasMany(Completion, { onDelete: 'CASCADE' });
Completion.belongsTo(User);

Task.hasMany(Completion, { onDelete: 'CASCADE' });
Completion.belongsTo(Task);

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
