const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-session-secret-immediately';
const OWNER_EMAIL = (process.env.OWNER_EMAIL || 'owner@timing.local').toLowerCase();
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || 'ChangeMe123!';
const OWNER_NAME = process.env.OWNER_NAME || 'Dainyel Rooi';

const baseDir = __dirname;
const dataDir = path.join(baseDir, 'data');
const usersFile = path.join(dataDir, 'users.json');
const attemptsFile = path.join(dataDir, 'login-attempts.json');
const requestsFile = path.join(dataDir, 'access-requests.json');
const assessmentFile = path.join(baseDir, 'assessment.html');

function ensureJson(filePath, fallback) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(fallback, null, 2), 'utf8');
  }
}

function readJson(filePath, fallback) {
  ensureJson(filePath, fallback);
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    return fallback;
  }
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

async function ensureOwnerAccount() {
  const users = readJson(usersFile, []);
  const existing = users.find(u => u.email === OWNER_EMAIL);
  if (existing) return;
  const passwordHash = await bcrypt.hash(OWNER_PASSWORD, 10);
  users.push({
    id: crypto.randomUUID(),
    name: OWNER_NAME,
    email: OWNER_EMAIL,
    passwordHash,
    role: 'admin',
    approved: true,
    createdAt: new Date().toISOString(),
    lastLoginAt: null
  });
  writeJson(usersFile, users);
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
}

function addAttempt(entry) {
  const attempts = readJson(attemptsFile, []);
  attempts.unshift({ id: crypto.randomUUID(), ...entry });
  writeJson(attemptsFile, attempts.slice(0, 2000));
}

function addRequest(entry) {
  const requests = readJson(requestsFile, []);
  requests.unshift({ id: crypto.randomUUID(), ...entry });
  writeJson(requestsFile, requests.slice(0, 1000));
}

function authRequired(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function adminRequired(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 8
  }
}));
app.use('/public', express.static(path.join(baseDir, 'public')));

function layout(title, body, extraHead = '') {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <link rel="stylesheet" href="/public/styles.css" />
  ${extraHead}
</head>
<body>
  ${body}
</body>
</html>`;
}

function escapeHtml(value = '') {
  return value.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/app');
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/app');
  const msg = req.query.msg ? `<div class="notice">${escapeHtml(req.query.msg)}</div>` : '';
  res.send(layout('Login | Timing Secure Tool', `
    <main class="auth-shell">
      <section class="card auth-card">
        <div class="brand-row">
          <div>
            <div class="eyebrow">Protected Access</div>
            <h1>Timing Language & Safety Matrix</h1>
            <p class="muted">Login is required before the assessment can be opened. All login attempts and access requests are logged for the owner.</p>
          </div>
        </div>
        ${msg}
        <form method="post" action="/login" class="stack-md">
          <label>Email address</label>
          <input name="email" type="email" required placeholder="name@company.com" />
          <label>Password</label>
          <input name="password" type="password" required placeholder="Your password" />
          <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <div class="divider"></div>
        <div class="stack-sm">
          <h2>Request access</h2>
          <p class="muted">No account yet? Submit a request first. The owner can then approve access and create your login.</p>
          <form method="post" action="/request-access" class="stack-md">
            <label>Full name</label>
            <input name="name" type="text" required placeholder="Your name" />
            <label>Company / department</label>
            <input name="company" type="text" required placeholder="Timing / client / department" />
            <label>Email address</label>
            <input name="email" type="email" required placeholder="name@company.com" />
            <label>Reason for access</label>
            <textarea name="reason" rows="4" required placeholder="Why do you need access?"></textarea>
            <button type="submit" class="btn btn-secondary">Send access request</button>
          </form>
        </div>
      </section>
    </main>
  `));
});

app.post('/login', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  const password = req.body.password || '';
  const users = readJson(usersFile, []);
  const user = users.find(u => u.email === email);
  const baseLog = {
    timestamp: new Date().toISOString(),
    email,
    ip: getClientIp(req),
    userAgent: req.headers['user-agent'] || '',
  };

  if (!user) {
    addAttempt({ ...baseLog, status: 'failed', reason: 'unknown-user' });
    return res.redirect('/login?msg=' + encodeURIComponent('Access denied. Unknown account.'));
  }

  if (!user.approved) {
    addAttempt({ ...baseLog, status: 'failed', reason: 'not-approved', userId: user.id });
    return res.redirect('/login?msg=' + encodeURIComponent('Access not approved yet. Please contact the owner.'));
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    addAttempt({ ...baseLog, status: 'failed', reason: 'wrong-password', userId: user.id });
    return res.redirect('/login?msg=' + encodeURIComponent('Access denied. Incorrect password.'));
  }

  user.lastLoginAt = new Date().toISOString();
  writeJson(usersFile, users);
  req.session.user = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  };
  addAttempt({ ...baseLog, status: 'success', reason: 'login-success', userId: user.id });
  res.redirect('/app');
});

app.post('/request-access', (req, res) => {
  const payload = {
    timestamp: new Date().toISOString(),
    name: (req.body.name || '').trim(),
    company: (req.body.company || '').trim(),
    email: (req.body.email || '').toLowerCase().trim(),
    reason: (req.body.reason || '').trim(),
    ip: getClientIp(req),
    userAgent: req.headers['user-agent'] || '',
    status: 'pending'
  };

  addRequest(payload);
  res.redirect('/login?msg=' + encodeURIComponent('Access request sent. The owner can review it in the admin dashboard.'));
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login?msg=' + encodeURIComponent('You have been logged out.')));
});

app.get('/app', authRequired, (req, res) => {
  const adminLink = req.session.user.role === 'admin'
    ? '<a class="nav-link" href="/admin">Admin dashboard</a>'
    : '';

  res.send(layout('Assessment | Timing Secure Tool', `
    <header class="topbar">
      <div>
        <strong>Timing Secure Tool</strong>
        <span class="muted">Logged in as ${escapeHtml(req.session.user.name)} (${escapeHtml(req.session.user.email)})</span>
      </div>
      <nav class="topbar-actions">
        ${adminLink}
        <form method="post" action="/logout">
          <button class="btn btn-ghost" type="submit">Logout</button>
        </form>
      </nav>
    </header>
    <main class="app-frame-shell">
      <iframe title="Timing Assessment" src="/assessment-file" class="app-frame"></iframe>
    </main>
  `));
});

app.get('/assessment-file', authRequired, (req, res) => {
  res.sendFile(assessmentFile);
});

app.get('/admin', adminRequired, (req, res) => {
  res.send(layout('Admin | Timing Secure Tool', `
    <header class="topbar">
      <div>
        <strong>Admin dashboard</strong>
        <span class="muted">Review access requests, users and login attempts.</span>
      </div>
      <nav class="topbar-actions">
        <a class="nav-link" href="/app">Open assessment</a>
        <form method="post" action="/logout">
          <button class="btn btn-ghost" type="submit">Logout</button>
        </form>
      </nav>
    </header>
    <main class="admin-grid">
      <section class="card">
        <h2>Create approved user</h2>
        <form id="createUserForm" class="stack-md">
          <label>Name</label>
          <input name="name" type="text" required />
          <label>Email</label>
          <input name="email" type="email" required />
          <label>Temporary password</label>
          <input name="password" type="text" required />
          <label>Role</label>
          <select name="role">
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
          <button class="btn btn-primary" type="submit">Create user</button>
        </form>
      </section>

      <section class="card">
        <h2>Access requests</h2>
        <div id="requestsContainer" class="table-wrap"></div>
      </section>

      <section class="card wide">
        <h2>Recent login attempts</h2>
        <div id="attemptsContainer" class="table-wrap"></div>
      </section>

      <section class="card wide">
        <h2>Approved users</h2>
        <div id="usersContainer" class="table-wrap"></div>
      </section>
    </main>
    <script src="/public/admin.js"></script>
  `));
});

app.get('/api/admin/data', adminRequired, (req, res) => {
  const users = readJson(usersFile, []).map(({ passwordHash, ...rest }) => rest);
  const attempts = readJson(attemptsFile, []);
  const requests = readJson(requestsFile, []);
  res.json({ users, attempts, requests });
});

app.post('/api/admin/users', adminRequired, async (req, res) => {
  const users = readJson(usersFile, []);
  const email = (req.body.email || '').toLowerCase().trim();
  if (!email || !req.body.password || !req.body.name) {
    return res.status(400).json({ error: 'Name, email and password are required.' });
  }
  if (users.some(u => u.email === email)) {
    return res.status(400).json({ error: 'User already exists.' });
  }

  const passwordHash = await bcrypt.hash(req.body.password, 10);
  const user = {
    id: crypto.randomUUID(),
    name: req.body.name.trim(),
    email,
    passwordHash,
    role: req.body.role === 'admin' ? 'admin' : 'user',
    approved: true,
    createdAt: new Date().toISOString(),
    lastLoginAt: null
  };
  users.push(user);
  writeJson(usersFile, users);
  res.json({ ok: true });
});

app.post('/api/admin/requests/:id/status', adminRequired, (req, res) => {
  const requests = readJson(requestsFile, []);
  const target = requests.find(r => r.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'Request not found.' });
  target.status = req.body.status === 'approved' ? 'approved' : 'denied';
  target.reviewedAt = new Date().toISOString();
  target.reviewedBy = req.session.user.email;
  writeJson(requestsFile, requests);
  res.json({ ok: true });
});

app.listen(PORT, async () => {
  ensureJson(usersFile, []);
  ensureJson(attemptsFile, []);
  ensureJson(requestsFile, []);
  await ensureOwnerAccount();
  console.log(`Timing Secure Tool running on http://localhost:${PORT}`);
  console.log(`Owner login: ${OWNER_EMAIL}`);
});
