import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Sequelize, DataTypes } from 'sequelize';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json());

/* =========================
   DATABASE (NEON POSTGRES)
========================= */

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false
});

/* =========================
   MODELS
========================= */

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: DataTypes.STRING,
  email: { type: DataTypes.STRING, unique: true },
  password: DataTypes.STRING,
  emoji: DataTypes.STRING
});

const Task = sequelize.define('Task', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: DataTypes.STRING,
  weeklyTarget: DataTypes.INTEGER,
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

/* =========================
   RELATIONS
========================= */

User.hasMany(Task);
Task.belongsTo(User);

User.hasMany(Completion);
Completion.belongsTo(User);

Task.hasMany(Completion);
Completion.belongsTo(Task);

/* =========================
   AUTH MIDDLEWARE
========================= */

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    req.user = jwt.verify(token, 'SECRET_KEY');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

/* =========================
   AUTH ROUTES
========================= */

app.post('/auth/register', async (req, res) => {
  const { name, email, password, emoji } = req.body;

  const hash = await bcrypt.hash(password, 10);
//   const emoji = ['😀','😎','🔥','💪','🚀'][Math.floor(Math.random() * 5)];

  const user = await User.create({
    name, email, password: hash, emoji
  });

  const token = jwt.sign({ id: user.id }, 'SECRET_KEY');

  res.json({ token });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid login' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid login' });

  const token = jwt.sign({ id: user.id }, 'SECRET_KEY');
  res.json({ token });
});

/* =========================
   FETCH ALL DATA (Angular)
========================= */

app.get('/api/dashboard', auth, async (req, res) => {
  const user = await User.findByPk(req.user.id);
  const tasks = await Task.findAll({ where: { UserId: user.id } });
  const completions = await Completion.findAll({ where: { UserId: user.id } });

  res.json({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      emoji: user.emoji
    },
    tasks,
    completions: completions.map(c => ({
      taskId: c.TaskId,
      date: c.date,
      completed: c.completed
    }))
  });
});

/* =========================
   CREATE TASK
========================= */

app.post('/api/tasks', auth, async (req, res) => {
  const { name, weeklyTarget } = req.body;

  const task = await Task.create({
    name,
    weeklyTarget,
    UserId: req.user.id
  });

  res.json(task);
});

/* =========================
   ENABLE / DISABLE TASK
========================= */

app.patch('/api/tasks/:id/toggle', auth, async (req, res) => {
  const task = await Task.findOne({
    where: { id: req.params.id, UserId: req.user.id }
  });

  if (!task) return res.status(404).json({ error: 'Task not found' });

  task.enabled = !task.enabled;
  await task.save();

  res.json(task);
});

/* =========================
   COMPLETION (SELECT / DESELECT)
========================= */

app.post('/api/completions', auth, async (req, res) => {
  try {
    const { taskId, date, completed } = req.body;

    const task = await Task.findOne({
      where: { id: taskId, UserId: req.user.id }
    });

    if (!task || !task.enabled) {
      return res.status(403).json({ error: 'Task disabled or not found' });
    }

    const [entry, created] = await Completion.findOrCreate({
      where: {
        UserId: req.user.id,
        TaskId: taskId,
        date
      },
      defaults: { completed }
    });

    if (!created && entry.completed !== completed) {
      entry.completed = completed;
      await entry.save();
    }

    res.json({
      success: true,
      completion: { taskId, date, completed }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Completion error' });
  }
});

/* =========================
   SERVER
========================= */

sequelize.sync().then(() => {
  console.log('✅ DB Ready');
  app.listen(3000, () =>
    console.log('🚀 API running on http://localhost:3000')
  );
});
