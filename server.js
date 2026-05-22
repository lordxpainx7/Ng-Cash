const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_KEY = process.env.ADMIN_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_MASTER_PASSWORD = process.env.ADMIN_MASTER_PASSWORD || 'LordNG2026Secure!';

// ==================== SEGURANÇA ====================

// Helmet - Proteção de headers HTTP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS - Restrito
const corsOptions = {
  origin: function (origin, callback) {
    // Permitir origens do Render e localhost
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5000',
      'https://ngcash.onrender.com',
      'https://ngcash-admin.onrender.com',
      undefined // Para requisições sem origin (Postman, etc)
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️ CORS bloqueado para origem: ${origin}`);
      callback(new Error('Origem não permitida pelo CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'admin-key'],
  credentials: true,
  maxAge: 86400 // 24 horas
};

app.use(cors(corsOptions));

// Rate Limiting - Proteção contra DDoS e brute force
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 requisições por IP
  message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // máximo 10 tentativas de login
  message: { error: 'Muitas tentativas de login. Tente novamente em 15 minutos.' },
  skipSuccessfulRequests: true // Reset após login bem-sucedido
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Limite de requisições ADM excedido.' }
});

const pixLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 5, // máximo 5 PIX por minuto
  message: { error: 'Limite de PIX excedido. Aguarde 1 minuto.' }
});

// Aplicar limitadores
app.use('/api/', generalLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/admin', adminLimiter);
app.use('/api/pix', pixLimiter);

// Body parser com limite de tamanho
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Servir arquivos estáticos
app.use(express.static(path.join(__dirname), {
  dotfiles: 'deny',
  index: false,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

// ==================== BANCO DE DADOS SEGURO ====================
const db = new Database('ngcash.db', {
  verbose: process.env.NODE_ENV === 'development' ? console.log : null,
  fileMustExist: false,
  timeout: 5000
});

// Configurações de segurança do banco
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');
db.pragma('cache_size = -2000'); // 2MB cache
db.pragma('synchronous = NORMAL');

// Criar tabelas com constraints e índices
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK(length(name) >= 3),
    email TEXT UNIQUE NOT NULL CHECK(email LIKE '%@%.%'),
    cpf TEXT UNIQUE NOT NULL CHECK(length(cpf) = 11),
    username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3),
    password TEXT NOT NULL CHECK(length(password) >= 60),
    balance REAL NOT NULL DEFAULT 500.00 CHECK(balance >= 0),
    cofrinho REAL NOT NULL DEFAULT 0 CHECK(cofrinho >= 0),
    card_number TEXT,
    card_cvv TEXT,
    card_expiry TEXT DEFAULT '09/29',
    skin TEXT DEFAULT 'default',
    avatar TEXT DEFAULT '👾',
    last_login DATETIME,
    login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER,
    to_user_id INTEGER,
    type TEXT NOT NULL CHECK(type IN ('pix', 'cofrinho_in', 'cofrinho_out', 'admin_adjustment', 'deposit', 'withdraw')),
    amount REAL NOT NULL CHECK(amount != 0),
    description TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    read INTEGER DEFAULT 0 CHECK(read IN (0, 1)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_action TEXT NOT NULL,
    target_user_id INTEGER,
    details TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS blacklisted_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    expired_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Índices para performance e segurança
  CREATE INDEX IF NOT EXISTS idx_transactions_users ON transactions(from_user_id, to_user_id);
  CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read);
  CREATE INDEX IF NOT EXISTS idx_blacklisted_tokens ON blacklisted_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_users_login ON users(email, username, cpf);
`);

// Limpar tokens expirados periodicamente
setInterval(() => {
  db.prepare('DELETE FROM blacklisted_tokens WHERE expired_at < ?').run(new Date().toISOString());
}, 3600000); // A cada hora

// ==================== FUNÇÕES DE SEGURANÇA ====================

// Gerar hash SHA-256 para tokens
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Validar inputs contra injeção
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  // Remover caracteres perigosos e limitar tamanho
  return input
    .replace(/[<>{}()]/g, '')
    .replace(/script/gi, '')
    .slice(0, 200);
}

// Validar CPF
function validateCPF(cpf) {
  cpf = cpf.replace(/[^\d]/g, '');
  if (cpf.length !== 11) return false;
  
  // Verificar se todos os dígitos são iguais
  if (/^(\d)\1+$/.test(cpf)) return false;
  
  // Validar dígitos verificadores
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += parseInt(cpf.charAt(i)) * (10 - i);
  let rev = 11 - (sum % 11);
  if (rev === 10 || rev === 11) rev = 0;
  if (rev !== parseInt(cpf.charAt(9))) return false;
  
  sum = 0;
  for (let i = 0; i < 10; i++) sum += parseInt(cpf.charAt(i)) * (11 - i);
  rev = 11 - (sum % 11);
  if (rev === 10 || rev === 11) rev = 0;
  if (rev !== parseInt(cpf.charAt(10))) return false;
  
  return true;
}

// Verificar se conta está bloqueada
function isAccountLocked(user) {
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return true;
  }
  return false;
}

// Incrementar tentativas de login
function incrementLoginAttempts(userId) {
  const user = db.prepare('SELECT login_attempts FROM users WHERE id = ?').get(userId);
  const attempts = (user.login_attempts || 0) + 1;
  
  if (attempts >= 5) {
    // Bloquear por 30 minutos
    const lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    db.prepare('UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?').run(attempts, lockedUntil, userId);
  } else {
    db.prepare('UPDATE users SET login_attempts = ? WHERE id = ?').run(attempts, userId);
  }
}

// Resetar tentativas de login
function resetLoginAttempts(userId) {
  db.prepare('UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?')
    .run(new Date().toISOString(), userId);
}

// Gerar cartão virtual
function generateCardNumber() {
  return '5182' + Array.from({length: 12}, () => Math.floor(Math.random() * 10)).join('');
}

function generateCVV() {
  return String(Math.floor(Math.random() * 900) + 100);
}

// Registrar log administrativo
function logAdminAction(action, targetUserId = null, details = '', req = null) {
  db.prepare('INSERT INTO admin_logs (admin_action, target_user_id, details, ip_address) VALUES (?, ?, ?, ?)')
    .run(action, targetUserId, details, req?.ip || 'system');
}

// ==================== MIDDLEWARES ====================

// Autenticação JWT com blacklist
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  // Verificar blacklist
  const tokenHash = hashToken(token);
  const blacklisted = db.prepare('SELECT id FROM blacklisted_tokens WHERE token_hash = ? AND expired_at > ?')
    .get(tokenHash, new Date().toISOString());
  
  if (blacklisted) {
    return res.status(401).json({ error: 'Token revogado. Faça login novamente.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Verificar se usuário ainda existe e não está bloqueado
    const user = db.prepare('SELECT id, locked_until FROM users WHERE id = ?').get(decoded.id);
    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }
    
    if (isAccountLocked(user)) {
      return res.status(423).json({ error: 'Conta bloqueada temporariamente. Tente novamente mais tarde.' });
    }
    
    req.user = decoded;
    req.token = token;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado. Faça login novamente.' });
    }
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// Autenticação Admin
const authenticateAdmin = (req, res, next) => {
  const adminKey = req.headers['admin-key'];
  
  if (!adminKey || adminKey !== ADMIN_KEY) {
    logAdminAction('TENTATIVA_ACESSO_NAO_AUTORIZADO', null, 'Chave ADM inválida', req);
    return res.status(403).json({ error: 'Acesso não autorizado. Este incidente será registrado.' });
  }
  
  next();
};

// Validar dados de entrada
const validateUserInput = (req, res, next) => {
  const { name, email, cpf, username, password } = req.body;
  
  // Validar campos obrigatórios apenas se estiverem presentes
  if (name !== undefined && (typeof name !== 'string' || name.length < 3)) {
    return res.status(400).json({ error: 'Nome deve ter pelo menos 3 caracteres' });
  }
  
  if (email !== undefined && !email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    return res.status(400).json({ error: 'Email inválido' });
  }
  
  if (cpf !== undefined && !validateCPF(cpf)) {
    return res.status(400).json({ error: 'CPF inválido' });
  }
  
  if (username !== undefined && (typeof username !== 'string' || username.length < 3 || !username.match(/^[a-zA-Z0-9_]+$/))) {
    return res.status(400).json({ error: 'Username deve ter pelo menos 3 caracteres e conter apenas letras, números e underscore' });
  }
  
  if (password !== undefined && password.length < 6) {
    return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
  }
  
  next();
};

// ==================== ROTAS PÚBLICAS ====================

// Redirecionamento
app.get('/', (req, res) => {
  res.redirect('/app.html');
});

app.get('/admin', (req, res) => {
  res.redirect('/adm');
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'online', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Registro de novo usuário
app.post('/api/register', validateUserInput, async (req, res) => {
  try {
    const { name, email, cpf, username, password } = req.body;
    
    // Sanitizar inputs
    const sanitizedName = sanitizeInput(name);
    const sanitizedEmail = sanitizeInput(email).toLowerCase();
    const sanitizedUsername = sanitizeInput(username).toLowerCase();
    
    // Verificar se já existe
    const existingUser = db.prepare(
      'SELECT id FROM users WHERE email = ? OR cpf = ? OR username = ?'
    ).get(sanitizedEmail, cpf, sanitizedUsername);
    
    if (existingUser) {
      return res.status(409).json({ error: 'Email, CPF ou usuário já cadastrado' });
    }
    
    // Hash da senha com salt
    const hashedPassword = await bcrypt.hash(password, 12);
    const cardNumber = generateCardNumber();
    const cvv = generateCVV();
    
    const result = db.prepare(`
      INSERT INTO users (name, email, cpf, username, password, card_number, card_cvv, card_expiry, balance)
      VALUES (?, ?, ?, ?, ?, ?, ?, '09/29', 500.00)
    `).run(sanitizedName, sanitizedEmail, cpf, sanitizedUsername, hashedPassword, cardNumber, cvv);
    
    const token = jwt.sign(
      { id: result.lastInsertRowid, username: sanitizedUsername, name: sanitizedName },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    logAdminAction('NOVO_USUARIO', result.lastInsertRowid, `Usuário ${sanitizedUsername} criado`, req);
    
    res.status(201).json({ 
      token, 
      user: { 
        id: result.lastInsertRowid, 
        name: sanitizedName, 
        username: sanitizedUsername, 
        email: sanitizedEmail, 
        cpf,
        balance: 500.00,
        cofrinho: 0,
        cardNumber,
        cvv,
        expiry: '09/29'
      } 
    });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ error: 'Erro interno ao criar conta' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { login, password } = req.body;
    
    if (!login || !password) {
      return res.status(400).json({ error: 'Login e senha são obrigatórios' });
    }
    
    const sanitizedLogin = sanitizeInput(login);
    
    const user = db.prepare(
      'SELECT * FROM users WHERE email = ? OR cpf = ? OR username = ?'
    ).get(sanitizedLogin, sanitizedLogin, sanitizedLogin);
    
    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }
    
    // Verificar bloqueio
    if (isAccountLocked(user)) {
      const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      return res.status(423).json({ 
        error: `Conta bloqueada. Tente novamente em ${minutesLeft} minutos.` 
      });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      incrementLoginAttempts(user.id);
      logAdminAction('LOGIN_FALHO', user.id, 'Senha incorreta', req);
      return res.status(401).json({ error: 'Senha incorreta' });
    }
    
    // Resetar tentativas e atualizar último login
    resetLoginAttempts(user.id);
    
    const token = jwt.sign(
      { id: user.id, username: user.username, name: user.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    logAdminAction('LOGIN_SUCESSO', user.id, `Usuário ${user.username} logado`, req);
    
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email,
        cpf: user.cpf,
        balance: user.balance,
        cofrinho: user.cofrinho,
        cardNumber: user.card_number,
        cvv: user.card_cvv,
        expiry: user.card_expiry,
        skin: user.skin,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno ao realizar login' });
  }
});

// Biometria simulada (com segurança adicional)
app.post('/api/biometry', async (req, res) => {
  try {
    const { login } = req.body;
    
    if (!login) {
      return res.status(400).json({ error: 'Identificação necessária' });
    }
    
    const sanitizedLogin = sanitizeInput(login);
    
    const user = db.prepare(
      'SELECT * FROM users WHERE email = ? OR cpf = ? OR username = ?'
    ).get(sanitizedLogin, sanitizedLogin, sanitizedLogin);
    
    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }
    
    if (isAccountLocked(user)) {
      return res.status(423).json({ error: 'Conta bloqueada. Use senha para desbloquear.' });
    }
    
    // Biometria simula verificação bem-sucedida
    resetLoginAttempts(user.id);
    
    const token = jwt.sign(
      { id: user.id, username: user.username, name: user.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    logAdminAction('LOGIN_BIOMETRIA', user.id, 'Login por biometria', req);
    
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email,
        cpf: user.cpf,
        balance: user.balance,
        cofrinho: user.cofrinho,
        cardNumber: user.card_number,
        cvv: user.card_cvv,
        expiry: user.card_expiry,
        skin: user.skin,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Erro na biometria:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Logout (revogar token)
app.post('/api/logout', authenticateToken, (req, res) => {
  const tokenHash = hashToken(req.token);
  const decoded = jwt.decode(req.token);
  
  db.prepare('INSERT INTO blacklisted_tokens (token_hash, expired_at) VALUES (?, ?)')
    .run(tokenHash, new Date(decoded.exp * 1000).toISOString());
  
  res.json({ success: true, message: 'Logout realizado com sucesso' });
});

// ==================== ROTAS PROTEGIDAS (USUÁRIO) ====================

// Perfil do usuário
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const user = db.prepare(
      'SELECT id, name, email, cpf, username, balance, cofrinho, card_number, card_cvv, card_expiry, skin, avatar, created_at FROM users WHERE id = ?'
    ).get(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    // Últimas transações (limitar a 50 para performance)
    const transactions = db.prepare(`
      SELECT t.*, 
             u1.name as from_name, u1.username as from_username,
             u2.name as to_name, u2.username as to_username
      FROM transactions t
      LEFT JOIN users u1 ON t.from_user_id = u1.id
      LEFT JOIN users u2 ON t.to_user_id = u2.id
      WHERE t.from_user_id = ? OR t.to_user_id = ?
      ORDER BY t.created_at DESC
      LIMIT 50
    `).all(user.id, user.id);
    
    // Notificações não lidas
    const notifications = db.prepare(
      'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
    ).all(user.id);
    
    res.json({ 
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        cpf: user.cpf,
        username: user.username,
        balance: user.balance,
        cofrinho: user.cofrinho,
        cardNumber: user.card_number,
        cvv: user.card_cvv,
        expiry: user.card_expiry,
        skin: user.skin,
        avatar: user.avatar,
        created_at: user.created_at
      },
      transactions,
      notifications 
    });
  } catch (error) {
    console.error('Erro ao buscar perfil:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Enviar PIX (com proteção adicional)
app.post('/api/pix', authenticateToken, async (req, res) => {
  const dbTransaction = db.transaction(() => {
    const { amount, recipientKey, description } = req.body;
    const fromUserId = req.user.id;
    
    // Validações
    if (!amount || amount <= 0) {
      throw new Error('Valor inválido');
    }
    
    if (amount > 10000) {
      throw new Error('Limite máximo de R$ 10.000,00 por transação');
    }
    
    if (!recipientKey) {
      throw new Error('Destinatário não informado');
    }
    
    // Buscar remetente com lock para evitar race condition
    const sender = db.prepare('SELECT * FROM users WHERE id = ?').get(fromUserId);
    
    if (!sender) {
      throw new Error('Usuário não encontrado');
    }
    
    if (sender.balance < amount) {
      throw new Error('Saldo insuficiente');
    }
    
    // Buscar destinatário
    const recipient = db.prepare(
      'SELECT * FROM users WHERE (id = ? OR email = ? OR cpf = ? OR username = ?) AND id != ?'
    ).get(recipientKey, recipientKey, recipientKey, recipientKey, fromUserId);
    
    if (!recipient) {
      throw new Error('Destinatário não encontrado');
    }
    
    // Atualizar saldos atomicamente
    db.prepare('UPDATE users SET balance = balance - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND balance >= ?')
      .run(amount, fromUserId, amount);
    
    db.prepare('UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(amount, recipient.id);
    
    // Registrar transação
    const sanitizedDesc = sanitizeInput(description || 'Pix enviado');
    db.prepare(`
      INSERT INTO transactions (from_user_id, to_user_id, type, amount, description, ip_address, user_agent)
      VALUES (?, ?, 'pix', ?, ?, ?, ?)
    `).run(fromUserId, recipient.id, amount, sanitizedDesc, req.ip, req.headers['user-agent']);
    
    // Notificações
    db.prepare('INSERT INTO notifications (user_id, message) VALUES (?, ?)')
      .run(recipient.id, `💰 Você recebeu R$ ${amount.toFixed(2)} de @${sender.username}`);
    
    db.prepare('INSERT INTO notifications (user_id, message) VALUES (?, ?)')
      .run(fromUserId, `✅ Pix de R$ ${amount.toFixed(2)} enviado para @${recipient.username}`);
    
    logAdminAction('PIX_ENVIADO', fromUserId, `R$ ${amount} para usuário ${recipient.id}`, req);
    
    const updatedSender = db.prepare('SELECT balance FROM users WHERE id = ?').get(fromUserId);
    
    return {
      success: true,
      message: `Pix de R$ ${amount.toFixed(2)} enviado para @${recipient.username}`,
      newBalance: updatedSender.balance
    };
  });
  
  try {
    const result = dbTransaction();
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Guardar no cofrinho
app.post('/api/cofrinho/guardar', authenticateToken, (req, res) => {
  const dbTransaction = db.transaction(() => {
    const { amount } = req.body;
    const userId = req.user.id;
    
    if (!amount || amount <= 0) {
      throw new Error('Valor inválido');
    }
    
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    
    if (user.balance < amount) {
      throw new Error('Saldo insuficiente');
    }
    
    db.prepare('UPDATE users SET balance = balance - ?, cofrinho = cofrinho + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND balance >= ?')
      .run(amount, amount, userId, amount);
    
    db.prepare('INSERT INTO transactions (from_user_id, to_user_id, type, amount, description, ip_address) VALUES (?, NULL, ?, ?, ?, ?)')
      .run(userId, 'cofrinho_in', amount, 'Guardado no cofrinho', req.ip);
    
    db.prepare('INSERT INTO notifications (user_id, message) VALUES (?, ?)')
      .run(userId, `🐷 R$ ${amount.toFixed(2)} guardado no cofrinho! Rendendo 100% CDI`);
    
    const updatedUser = db.prepare('SELECT balance, cofrinho FROM users WHERE id = ?').get(userId);
    
    return { success: true, balance: updatedUser.balance, cofrinho: updatedUser.cofrinho };
  });
  
  try {
    const result = dbTransaction();
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Resgatar do cofrinho
app.post('/api/cofrinho/resgatar', authenticateToken, (req, res) => {
  const dbTransaction = db.transaction(() => {
    const { amount } = req.body;
    const userId = req.user.id;
    
    if (!amount || amount <= 0) {
      throw new Error('Valor inválido');
    }
    
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    
    if (user.cofrinho < amount) {
      throw new Error('Saldo do cofrinho insuficiente');
    }
    
    db.prepare('UPDATE users SET balance = balance + ?, cofrinho = cofrinho - ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND cofrinho >= ?')
      .run(amount, amount, userId, amount);
    
    db.prepare('INSERT INTO transactions (from_user_id, to_user_id, type, amount, description, ip_address) VALUES (?, NULL, ?, ?, ?, ?)')
      .run(userId, 'cofrinho_out', amount, 'Resgatado do cofrinho', req.ip);
    
    db.prepare('INSERT INTO notifications (user_id, message) VALUES (?, ?)')
      .run(userId, `💰 R$ ${amount.toFixed(2)} resgatado do cofrinho!`);
    
    const updatedUser = db.prepare('SELECT balance, cofrinho FROM users WHERE id = ?').get(userId);
    
    return { success: true, balance: updatedUser.balance, cofrinho: updatedUser.cofrinho };
  });
  
  try {
    const result = dbTransaction();
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Atualizar perfil
app.put('/api/profile', authenticateToken, (req, res) => {
  try {
    const { skin, avatar } = req.body;
    const userId = req.user.id;
    
    if (skin && !['default', 'dark', 'neon', 'gold', 'ocean'].includes(skin)) {
      return res.status(400).json({ error: 'Skin inválida' });
    }
    
    if (avatar && avatar.length > 2) {
      return res.status(400).json({ error: 'Avatar inválido' });
    }
    
    if (skin) db.prepare('UPDATE users SET skin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(skin, userId);
    if (avatar) db.prepare('UPDATE users SET avatar = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(avatar, userId);
    
    const user = db.prepare('SELECT skin, avatar FROM users WHERE id = ?').get(userId);
    res.json({ success: true, skin: user.skin, avatar: user.avatar });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Notificações
app.get('/api/notifications', authenticateToken, (req, res) => {
  const notifications = db.prepare(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
  ).all(req.user.id);
  res.json(notifications);
});

app.put('/api/notifications/:id/read', authenticateToken, (req, res) => {
  const result = db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?')
    .run(req.params.id, req.user.id);
  
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Notificação não encontrada' });
  }
  
  res.json({ success: true });
});

// ==================== ROTAS ADMIN ====================

// Listar usuários
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
  try {
    const users = db.prepare(
      'SELECT id, name, email, cpf, username, balance, cofrinho, card_number, skin, avatar, created_at, last_login FROM users ORDER BY id DESC LIMIT 100'
    ).all();
    
    logAdminAction('LISTAR_USUARIOS', null, `Listou ${users.length} usuários`, req);
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// Criar usuário
app.post('/api/admin/users', authenticateAdmin, validateUserInput, async (req, res) => {
  try {
    const { name, email, cpf, username, password } = req.body;
    
    const existingUser = db.prepare(
      'SELECT id FROM users WHERE email = ? OR cpf = ? OR username = ?'
    ).get(email, cpf, username);
    
    if (existingUser) {
      return res.status(409).json({ error: 'Email, CPF ou usuário já cadastrado' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    const cardNumber = generateCardNumber();
    const cvv = generateCVV();
    
    const result = db.prepare(`
      INSERT INTO users (name, email, cpf, username, password, card_number, card_cvv, card_expiry, balance)
      VALUES (?, ?, ?, ?, ?, ?, ?, '09/29', 500.00)
    `).run(name, email, cpf, username, hashedPassword, cardNumber, cvv);
    
    logAdminAction('CRIAR_USUARIO', result.lastInsertRowid, `Admin criou usuário ${username}`, req);
    
    res.status(201).json({ success: true, message: 'Usuário criado com sucesso', userId: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

// Atualizar usuário
app.put('/api/admin/users/:id', authenticateAdmin, validateUserInput, async (req, res) => {
  try {
    const { name, email, cpf, username, password } = req.body;
    const userId = req.params.id;
    
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 12);
      db.prepare('UPDATE users SET name = ?, email = ?, cpf = ?, username = ?, password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
        .run(name, email, cpf, username, hashedPassword, userId);
    } else {
      db.prepare('UPDATE users SET name = ?, email = ?, cpf = ?, username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
        .run(name, email, cpf, username, userId);
    }
    
    logAdminAction('EDITAR_USUARIO', userId, `Dados atualizados`, req);
    
    res.json({ success: true, message: 'Usuário atualizado' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// Ajustar saldo
app.put('/api/admin/users/:id/balance', authenticateAdmin, (req, res) => {
  const dbTransaction = db.transaction(() => {
    const { amount, type } = req.body;
    const userId = req.params.id;
    
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      throw new Error('Usuário não encontrado');
    }
    
    let newBalance;
    let transactionType = 'admin_adjustment';
    
    switch (type) {
      case 'add':
        newBalance = user.balance + parseFloat(amount);
        break;
      case 'subtract':
        newBalance = user.balance - parseFloat(amount);
        if (newBalance < 0) {
          throw new Error('Saldo não pode ficar negativo');
        }
        break;
      case 'set':
        newBalance = parseFloat(amount);
        if (newBalance < 0) {
          throw new Error('Saldo não pode ser negativo');
        }
        break;
      default:
        throw new Error('Tipo de operação inválido');
    }
    
    db.prepare('UPDATE users SET balance = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(newBalance, userId);
    
    db.prepare('INSERT INTO transactions (from_user_id, to_user_id, type, amount, description, ip_address) VALUES (?, ?, ?, ?, ?, ?)')
      .run(0, userId, transactionType, parseFloat(amount), 'Ajuste de saldo pelo administrador', req.ip);
    
    db.prepare('INSERT INTO notifications (user_id, message) VALUES (?, ?)')
      .run(userId, `🔧 Seu saldo foi ajustado em R$ ${Math.abs(parseFloat(amount)).toFixed(2)}`);
    
    logAdminAction('AJUSTAR_SALDO', userId, `Saldo alterado de R$ ${user.balance} para R$ ${newBalance}`, req);
    
    return { success: true, newBalance };
  });
  
  try {
    const result = dbTransaction();
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Deletar usuário
app.delete('/api/admin/users/:id', authenticateAdmin, (req, res) => {
  const dbTransaction = db.transaction(() => {
    const userId = req.params.id;
    
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      throw new Error('Usuário não encontrado');
    }
    
    db.prepare('DELETE FROM notifications WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM transactions WHERE from_user_id = ? OR to_user_id = ?').run(userId, userId);
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    
    logAdminAction('DELETAR_USUARIO', userId, `Usuário ${user.username} deletado`, req);
    
    return { success: true, message: 'Usuário removido permanentemente' };
  });
  
  try {
    const result = dbTransaction();
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Estatísticas
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
  try {
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
    const totalBalance = db.prepare('SELECT SUM(balance) as total FROM users').get();
    const totalCofrinho = db.prepare('SELECT SUM(cofrinho) as total FROM users').get();
    const totalTransactions = db.prepare('SELECT COUNT(*) as count FROM transactions').get();
    const recentLogs = db.prepare('SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT 10').all();
    
    logAdminAction('VER_STATS', null, 'Visualizou estatísticas', req);
    
    res.json({
      totalUsers: totalUsers.count,
      totalBalance: totalBalance.total || 0,
      totalCofrinho: totalCofrinho.total || 0,
      totalTransactions: totalTransactions.count,
      recentLogs
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// Servir app ADM
app.get('/adm', (req, res) => {
  res.sendFile(path.join(__dirname, 'adm.html'));
});

// ==================== TRATAMENTO DE ERROS ====================

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// Erro global
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload muito grande' });
  }
  
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// ==================== INICIAR SERVIDOR ====================
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('🔒 NG.CASH - Servidor Seguro');
  console.log(`🚀 Rodando na porta ${PORT}`);
  console.log(`📱 App Usuário: http://localhost:${PORT}/app.html`);
  console.log(`🔐 Painel ADM: http://localhost:${PORT}/adm`);
  console.log(`🛡️ Chave ADM: ${ADMIN_KEY}`);
  console.log(`🔑 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM recebido. Fechando servidor...');
  server.close(() => {
    db.close();
    console.log('Servidor fechado.');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT recebido. Fechando servidor...');
  server.close(() => {
    db.close();
    console.log('Servidor fechado.');
    process.exit(0);
  });
});
