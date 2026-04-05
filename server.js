// ─── StudyHub Pro – Express + Firebase Admin Backend ──────────────────────────
// All Firebase credentials stay here on the server. The frontend never sees them.
// ────────────────────────────────────────────────────────────────────────────────

require('dotenv').config();
const express    = require('express');
const admin      = require('firebase-admin');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const path       = require('path');

// ─── Firebase Admin Init ──────────────────────────────────────────────────────
admin.initializeApp({
  credential: admin.credential.cert({
    projectId:   process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey:  (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
  }),
});
const db = admin.firestore();

// ─── Express Setup ────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
  .split(',').map(o => o.trim());

app.use(cors({ origin: allowedOrigins, credentials: true }));

// Helmet with relaxed CSP so PDF.js / Bootstrap CDN still work from the served HTML
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net",
                   "https://cdnjs.cloudflare.com", "https://www.gstatic.com"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net",
                   "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", "data:", "blob:"],
      mediaSrc:   ["'self'", "blob:"],
      workerSrc:  ["'self'", "blob:", "https://cdnjs.cloudflare.com"],
    },
  },
}));

app.use(express.json({ limit: '20mb' }));  // large for base64 chunk uploads
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 min
  max: 20,
  message: { error: 'Too many requests, please try again later.' },
});
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,   // 1 min
  max: 120,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/auth', authLimiter);
app.use('/api',      apiLimiter);

// ─── Helpers ──────────────────────────────────────────────────────────────────
const SALT_ROUNDS = 10;

async function hashPw(plain)        { return bcrypt.hash(plain, SALT_ROUNDS); }
async function checkPw(plain, hash) {
  // Support legacy plaintext passwords (migrate on first login)
  if (!hash.startsWith('$2')) return plain === hash;
  return bcrypt.compare(plain, hash);
}

function colRef(name)       { return db.collection(name); }
function docRef(col, id)    { return db.collection(col).doc(id); }

async function getAll(col) {
  const snap = await colRef(col).get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function getWhere(col, ...wheres) {
  let q = colRef(col);
  for (const [field, op, val] of wheres) q = q.where(field, op, val);
  const snap = await q.get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function getDoc(col, id) {
  const snap = await docRef(col, id).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}

async function addDoc(col, data) {
  const ref = await colRef(col).add({ ...data, _createdAt: admin.firestore.FieldValue.serverTimestamp() });
  return ref.id;
}

async function setDoc(col, id, data) {
  await docRef(col, id).set(data, { merge: true });
}

async function updateDoc(col, id, data) {
  await docRef(col, id).update(data);
}

async function deleteDoc(col, id) {
  await docRef(col, id).delete();
}

// Strip sensitive fields before sending user to frontend
function safeUser(u) {
  const { password, firebaseUid, ...safe } = u;
  return safe;
}

// ─── Middleware: verify session (simple userId header approach) ───────────────
// We use a lightweight signed token: base64(userId):base64(HMAC)
// For production you can swap this for express-session + Redis or JWT.
const crypto = require('crypto');
const SECRET = process.env.SESSION_SECRET || 'changeme_please';

function signToken(userId) {
  const payload = Buffer.from(userId).toString('base64');
  const sig     = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  if (sig !== expected) return null;
  return Buffer.from(payload, 'base64').toString('utf8'); // userId
}

async function requireAuth(req, res, next) {
  const token  = req.headers['x-session-token'];
  const userId = verifyToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  const user = await getDoc('users', userId);
  if (!user || user.banned) return res.status(403).json({ error: 'Forbidden' });
  req.user = user;
  next();
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, async () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
    next();
  });
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

    const users = await getWhere('users', ['username', '==', username]);
    if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = users[0];
    if (user.banned) return res.status(403).json({ error: 'Account banned' });

    const ok = await checkPw(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Migrate plaintext password to bcrypt hash on first login
    if (!user.password.startsWith('$2')) {
      const hashed = await hashPw(password);
      await updateDoc('users', user.id, { password: hashed });
    }

    const token = signToken(user.id);
    res.json({ token, user: safeUser(user) });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, phone } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 4) return res.status(400).json({ error: 'Min 4 characters' });

    const existing = await getWhere('users', ['username', '==', username]);
    if (existing.length) return res.status(409).json({ error: 'Username taken' });

    const hashed = await hashPw(password);
    const id = await addDoc('users', {
      username,
      password: hashed,
      role: 'student',
      phone: phone || null,
      banned: false,
      blockedMaterials: false,
      blockedTests: false,
    });

    const user = await getDoc('users', id);
    const token = signToken(id);
    res.json({ token, user: safeUser(user) });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
    if (newPassword.length < 4) return res.status(400).json({ error: 'Min 4 characters' });

    const ok = await checkPw(currentPassword, req.user.password);
    if (!ok) return res.status(401).json({ error: 'Current password incorrect' });

    const hashed = await hashPw(newPassword);
    await updateDoc('users', req.user.id, { password: hashed });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/admin-set-password  (admin sets a student's password)
app.post('/api/auth/admin-set-password', requireAdmin, async (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword || newPassword.length < 4)
      return res.status(400).json({ error: 'Invalid request' });
    const hashed = await hashPw(newPassword);
    await updateDoc('users', userId, { password: hashed });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── GENERIC FIRESTORE CRUD ROUTES ───────────────────────────────────────────
// These mirror your original window._all / _get / _add / _upd / _del helpers
// but run on the server with Admin SDK (no API key exposed).

// GET /api/collection/:col  — get all docs
app.get('/api/collection/:col', requireAuth, async (req, res) => {
  try {
    const data = await getAll(req.params.col);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/collection/:col/:id  — get one doc
app.get('/api/collection/:col/:id', requireAuth, async (req, res) => {
  try {
    const data = await getDoc(req.params.col, req.params.id);
    if (!data) return res.status(404).json({ error: 'Not found' });
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/collection/:col/query  — query with where clauses
// Body: { where: [["field","==","val"], ...] }
app.post('/api/collection/:col/query', requireAuth, async (req, res) => {
  try {
    const wheres = req.body.where || [];
    const data   = await getWhere(req.params.col, ...wheres);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/collection/:col  — add doc (admin only for sensitive collections)
const ADMIN_ONLY_WRITE = ['users', 'branches', 'semesters', 'subjects', 'tests', 'materials', 'syllabus', 'fileChunks'];

app.post('/api/collection/:col', requireAuth, async (req, res) => {
  try {
    const col = req.params.col;
    // Students can write to results (submit tests)
    if (ADMIN_ONLY_WRITE.includes(col) && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admins only' });
    }
    const id = await addDoc(col, req.body);
    res.json({ id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/collection/:col/:id  — update doc
app.patch('/api/collection/:col/:id', requireAuth, async (req, res) => {
  try {
    const col = req.params.col;
    const id  = req.params.id;
    // Students can only update their own user doc (but not role/banned)
    if (req.user.role !== 'admin') {
      if (col !== 'users' || id !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      // Strip fields students must not self-modify
      const { role, banned, blockedMaterials, blockedTests, password, ...safe } = req.body;
      await updateDoc(col, id, safe);
      return res.json({ ok: true });
    }
    await updateDoc(col, id, req.body);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/collection/:col/:id  — delete doc (admin only)
app.delete('/api/collection/:col/:id', requireAdmin, async (req, res) => {
  try {
    await deleteDoc(req.params.col, req.params.id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── SEED / BOOTSTRAP ─────────────────────────────────────────────────────────
app.post('/api/admin/seed', async (req, res) => {
  try {
    // Only run if no admin exists yet (safe to call on startup)
    const admins = await getWhere('users', ['role', '==', 'admin']);
    if (!admins.length) {
      const hashed = await hashPw('admin123');
      await addDoc('users', { username: 'admin', password: hashed, role: 'admin', phone: null, banned: false });
    }
    const brs = await getAll('branches');
    if (!brs.length) {
      await addDoc('branches', { name: 'Computer Science' });
      await addDoc('branches', { name: 'Civil Engineering' });
    }
    const sms = await getAll('semesters');
    if (!sms.length) {
      await addDoc('semesters', { name: 'Semester 3' });
      await addDoc('semesters', { name: 'Semester 4' });
      await addDoc('semesters', { name: 'Semester 5' });
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Serve frontend for all other routes ─────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`✅ StudyHub Pro running at http://localhost:${PORT}`);
  // Auto-seed on startup
  try {
    const r = await fetch(`http://localhost:${PORT}/api/admin/seed`, { method: 'POST' });
    const j = await r.json();
    if (j.ok) console.log('✅ Default data seeded');
  } catch (_) {}
});
