import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const app = express();

// --- middleware ---
app.use(helmet());
app.use(cors({ origin: true, credentials: true })); // adjust origin in production
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// --- demo user (replace with real DB user lookup) ---
const DEMO_USER = {
  id: 'u_demo_1',
  username: 'demo',
  name: 'Demo User',
  // hash at startup for the demo password: "Password123!"
  passwordHash: bcrypt.hashSync('Password123!', 10)
};

// --- helpers ---
function createToken(payload) {
  const expMin = parseInt(process.env.JWT_EXP_MIN || '15', 10);
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: `${expMin}m` });
}

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// --- routes ---
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  // Replace with DB lookup
  const user = username === DEMO_USER.username ? DEMO_USER : null;
  if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials.' });

  const token = createToken({ sub: user.id, username: user.username, name: user.name });
  return res.json({
    token,
    user: { id: user.id, username: user.username, name: user.name }
  });
});

// Optional: protected test route
app.get('/api/me', auth, (req, res) => {
  res.json({ user: req.user });
});

// --- start ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
});
