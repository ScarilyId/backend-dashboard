// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const csvStringify = require('csv-stringify');
const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.JWT_SECRET || "supersecret";

// Middleware
app.use(cors());
app.use(express.json());

// Data dummy (sebagai in-memory store)
let users = [
  { id: 1, name: 'Admin', role: 'admin', username: 'admin', password: bcrypt.hashSync('admin123', 10) },
  { id: 2, name: 'User', role: 'user', username: 'user', password: bcrypt.hashSync('user123', 10) }
];

// Middleware untuk verifikasi token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Middleware untuk otorisasi berdasarkan role
function authorizeRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

/* 1. Authentication & MFA (opsional)
   Endpoint login yang juga dapat diperluas untuk MFA */
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && bcrypt.compareSync(password, user.password)) {
    // Jika ingin menambahkan MFA, lakukan verifikasi tambahan di sini
    const token = jwt.sign({ id: user.id, role: user.role }, secretKey, { expiresIn: '1h' });
    return res.json({ message: "Login successful", token });
  }
  res.status(401).json({ message: "Invalid credentials" });
});

/* 2. CRUD untuk Users (Admin Only) */
// Get all users (dengan opsi filter misalnya berdasarkan role)
app.get('/users', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const { role } = req.query;
  let filtered = users;
  if (role) {
    filtered = users.filter(u => u.role === role);
  }
  res.json(filtered.map(u => ({ id: u.id, name: u.name, username: u.username, role: u.role })));
});

// Buat user baru
app.post('/users', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const { name, username, password, role } = req.body;
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: "Username already exists" });
  }
  const newUser = { 
    id: users.length + 1, 
    name, 
    username, 
    password: bcrypt.hashSync(password, 10), 
    role 
  };
  users.push(newUser);
  res.json({ message: "User added", user: { id: newUser.id, name, username, role } });
});

// Update user
app.put('/users/:id', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const userId = parseInt(req.params.id);
  const { name, role } = req.body;
  let user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ message: "User not found" });
  user.name = name || user.name;
  user.role = role || user.role;
  res.json({ message: "User updated", user: { id: user.id, name: user.name, role: user.role, username: user.username } });
});

// Hapus user
app.delete('/users/:id', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const userId = parseInt(req.params.id);
  users = users.filter(u => u.id !== userId);
  res.json({ message: "User deleted" });
});

/* 3. Statistik Real-Time (dummy data) */
app.get('/stats', authenticateToken, (req, res) => {
  const stats = {
    totalUsers: users.length,
    activeSessions: Math.floor(Math.random() * 100),
    sales: Math.floor(Math.random() * 1000)
  };
  res.json(stats);
});

/* 4. Export Data ke CSV */
app.get('/users/export', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const data = users.map(u => ({ id: u.id, name: u.name, username: u.username, role: u.role }));
  csvStringify(data, { header: true }, (err, output) => {
    if (err) return res.status(500).json({ message: "Export error" });
    res.attachment('users.csv');
    res.send(output);
  });
});

/* 5. Integrasi API Eksternal (contoh dummy weather) */
app.get('/weather', (req, res) => {
  res.json({ location: "Jakarta", temperature: "32°C", condition: "Sunny" });
});

/* 6. Laporan Otomatis (dummy report) */
app.get('/reports', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const report = {
    reportDate: new Date(),
    summary: "Ini adalah laporan dummy.",
    data: { users: users.length, sales: 500, notifications: 5 }
  };
  res.json(report);
});

/* 7. Kalender & Scheduling (dummy events) */
app.get('/calendar', authenticateToken, (req, res) => {
  const events = [
    { id: 1, title: "Meeting", date: "2025-04-01" },
    { id: 2, title: "Maintenance", date: "2025-04-05" }
  ];
  res.json(events);
});

/* 8. Chat / Live Support (dummy chat) */
app.get('/chat', authenticateToken, (req, res) => {
  const messages = [
    { id: 1, sender: "Support", message: "Halo, ada yang bisa dibantu?" },
    { id: 2, sender: "User", message: "Saya butuh bantuan dengan akun saya." }
  ];
  res.json(messages);
});

/* 9. Payment Gateway Integration (dummy data) */
app.get('/payments', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const payments = [
    { id: 1, user: "User", amount: 100, status: "Completed" },
    { id: 2, user: "Alice", amount: 250, status: "Pending" }
  ];
  res.json(payments);
});

/* 10. Social Media Feed Integration (dummy feed) */
app.get('/social', (req, res) => {
  const posts = [
    { id: 1, platform: "Twitter", content: "Ini adalah tweet contoh", date: "2025-03-14" },
    { id: 2, platform: "Instagram", content: "Post terbaru telah diupload", date: "2025-03-15" }
  ];
  res.json(posts);
});

/* 11. Public Endpoint untuk Dashboard (tidak perlu autentikasi)
   Mengembalikan data user terbatas untuk tampilan publik */
app.get('/public/users', (req, res) => {
  res.json(users.map(u => ({ name: u.name, role: u.role })));
});

/* 12. Log Middleware untuk monitoring & audit trail */
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Mulai server
app.listen(port, () => console.log(`Server running on port ${port}`));
