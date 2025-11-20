// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'troque-esta-chave-para-producao';
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || '10', 10);

// middlewares básicos
app.use(cors());
app.use(bodyParser.json());

// --- inicializa DB ---
async function runInitSql() {
  try {
    const sql = fs.readFileSync(path.join(__dirname, 'init.sql')).toString();
    await db.query(sql);
    console.log('init.sql executado com sucesso (criação de tabelas).');
  } catch (err) {
    console.error('Erro ao executar init.sql:', err);
  }
}

// --- utilidades ---
function normalizePhone(phone) {
  if (!phone) return phone;
  return phone.toString().replace(/\D/g, '');
}

async function logAudit(userId, action, tableName = null, oldData = null, newData = null) {
  try {
    await db.query(
      `INSERT INTO audit_logs (user_id, action, table_name, old_data, new_data) VALUES ($1,$2,$3,$4,$5)`,
      [userId || null, action, tableName, oldData ? JSON.stringify(oldData) : null, newData ? JSON.stringify(newData) : null]
    );
  } catch (err) {
    console.error('Erro ao gravar audit log:', err);
  }
}

// ==================================================================
// 1. ROTAS PÚBLICAS (Não passam pelo Auth Middleware)
// ==================================================================

// Rota de status simples
app.get('/', (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV || 'development' });
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { telefone, password } = req.body;
    if (!telefone || !password) return res.status(400).json({ error: 'Telefone e senha são obrigatórios' });

    const normalizedPhone = normalizePhone(telefone);
    const { rows } = await db.query('SELECT * FROM users WHERE telefone = $1', [normalizedPhone]);
    if (rows.length === 0) return res.status(401).json({ error: 'Credenciais inválidas' });

    const user = rows[0];
    if (!user.password_hash) return res.status(401).json({ error: 'Usuário sem senha. Contate o admin.' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Credenciais inválidas' });

    // atualizar last_seen e status online
    await db.query('UPDATE users SET status = $1, last_seen = now() WHERE id = $2', ['online', user.id]);
    await logAudit(user.id, 'login', 'users', null, { id: user.id });

    const token = jwt.sign({ id: user.id, role: user.role, setor_id: user.setor_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: { id: user.id, nome: user.nome, telefone: user.telefone, role: user.role, setor_id: user.setor_id } });
  } catch (err) {
    console.error('POST /auth/login erro', err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Cadastro Externo
app.post('/auth/register', async (req, res) => {
  try {
    const { nome, telefone, password, setor_id } = req.body;
    if (!telefone || !password) return res.status(400).json({ error: 'Telefone e senha são obrigatórios' });

    const normalizedPhone = normalizePhone(telefone);
    // checar telefone duplicado
    const { rows: exists } = await db.query('SELECT id FROM users WHERE telefone = $1', [normalizedPhone]);
    if (exists.length > 0) return res.status(400).json({ error: 'Telefone já cadastrado' });

    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const { rows } = await db.query(
      `INSERT INTO users (nome, telefone, password_hash, setor_id, role, status) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, nome, telefone, role, status`,
      [nome || null, normalizedPhone, password_hash, setor_id || null, 'user', 'pendente']
    );

    const newUser = rows[0];
    await logAudit(newUser.id, 'create_user_register', 'users', null, newUser);

    res.status(201).json({ message: 'Usuário criado. Aguarda aprovação admin.', user: newUser });
  } catch (err) {
    console.error('POST /auth/register erro', err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// Confirmar leitura (Pode receber token opcionalmente dentro da lógica, mas a rota em si é aberta para evitar loop de bloqueio)
app.post('/compliance/confirm', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Token ausente' });
    const token = authHeader.split(' ')[1];
    const payload = jwt.verify(token, JWT_SECRET);
    const userId = payload.id;

    const { compliance_msg_id } = req.body;
    if (!compliance_msg_id) return res.status(400).json({ error: 'compliance_msg_id é obrigatório' });

    await db.query(
      `INSERT INTO user_reads (user_id, compliance_msg_id) VALUES ($1,$2)
       ON CONFLICT (user_id, compliance_msg_id) DO NOTHING`,
      [userId, compliance_msg_id]
    );

    await logAudit(userId, 'confirm_compliance', 'user_reads', null, { user_id: userId, compliance_msg_id });
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /compliance/confirm erro', err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});


// ==================================================================
// 2. MIDDLEWARES DE SEGURANÇA (Barreira)
// ==================================================================

// Auth Middleware
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Token ausente' });

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await db.query('SELECT id, nome, telefone, role, setor_id, status, last_seen FROM users WHERE id = $1', [payload.id]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuário não encontrado' });
    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// Compliance Middleware
async function complianceMiddleware(req, res, next) {
  const user = req.user;
  if (!user) return res.status(401).json({ error: 'Usuário não autenticado' });

  // Admin pode pular verificação se necessário, ou mantemos para todos
  // if (user.role === 'admin') return next(); 

  try {
    const { rows: obrigatorias } = await db.query('SELECT id FROM compliance_msgs WHERE obrigatoria = true');
    if (!obrigatorias || obrigatorias.length === 0) return next();

    const { rows: notRead } = await db.query(
      `SELECT id FROM compliance_msgs cm
       WHERE cm.obrigatoria = true
       AND NOT EXISTS (
         SELECT 1 FROM user_reads ur WHERE ur.user_id = $1 AND ur.compliance_msg_id = cm.id
       )`,
      [user.id]
    );

    if (notRead.length > 0) {
      return res.status(403).json({
        error: 'Você possui mensagens obrigatórias pendentes de leitura.',
        compliance_pending: true
      });
    }
    next();
  } catch (err) {
    console.error('Erro complianceMiddleware:', err);
    res.status(500).json({ error: 'Erro no servidor (compliance check)' });
  }
}

// APLICAR OS MIDDLEWARES DAQUI PARA BAIXO
app.use(authMiddleware);
app.use(complianceMiddleware);


// ==================================================================
// 3. ROTAS PROTEGIDAS (Exigem Login)
// ==================================================================

// Admin helper
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado: admin' });
  next();
}

// --- Admin ---
app.post('/admin/approve', requireAdmin, async (req, res) => {
  try {
    const { user_id, approve, motivo } = req.body;
    if (!user_id || typeof approve === 'undefined') return res.status(400).json({ error: 'user_id e approve são obrigatórios' });

    const { rows: oldRows } = await db.query('SELECT * FROM users WHERE id = $1', [user_id]);
    if (oldRows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });

    const newStatus = approve ? 'offline' : 'rejected';
    await db.query('UPDATE users SET status = $1 WHERE id = $2', [newStatus, user_id]);
    await logAudit(req.user.id, approve ? 'approve_user' : 'reject_user', 'users', oldRows[0], { status: newStatus, motivo: motivo || null });

    res.json({ ok: true, status: newStatus });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.post('/admin/reset-password', requireAdmin, async (req, res) => {
  try {
    const { user_id, new_password } = req.body;
    if (!user_id || !new_password) return res.status(400).json({ error: 'user_id e new_password são obrigatórios' });

    const { rows: oldRows } = await db.query('SELECT id, nome, telefone FROM users WHERE id = $1', [user_id]);
    if (oldRows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });

    const newHash = await bcrypt.hash(new_password, SALT_ROUNDS);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user_id]);
    await logAudit(req.user.id, 'reset_password', 'users', oldRows[0], { id: user_id });

    res.json({ ok: true, message: 'Senha resetada pelo admin.' });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.post('/compliance', requireAdmin, async (req, res) => {
  try {
    const { texto, obrigatoria } = req.body;
    if (!texto) return res.status(400).json({ error: 'texto é obrigatório' });
    const { rows } = await db.query('INSERT INTO compliance_msgs (texto, obrigatoria) VALUES ($1,$2) RETURNING *', [texto, !!obrigatoria]);
    await logAudit(req.user.id, 'create_compliance_msg', 'compliance_msgs', null, rows[0]);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.get('/users', requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.query('SELECT id, nome, telefone, setor_id, role, status, last_seen, created_at FROM users ORDER BY id DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// --- Rotas Comuns Protegidas ---
app.get('/compliance', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM compliance_msgs ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.get('/biolinks', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM biolinks ORDER BY id DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.post('/biolinks', async (req, res) => {
  try {
    const user = req.user;
    const { titulo, items } = req.body;
    const { rows: setorRows } = await db.query('SELECT permissoes_json FROM setores WHERE id = $1', [user.setor_id]);
    const permissoes = setorRows[0] ? setorRows[0].permissoes_json : {};
    if (!(permissoes && permissoes.biolink && permissoes.biolink === 'write')) {
      return res.status(403).json({ error: 'Seu setor não tem permissão para criar biolinks' });
    }
    const { rows } = await db.query(
      'INSERT INTO biolinks (titulo, items) VALUES ($1,$2) RETURNING *',
      [titulo || null, items ? JSON.stringify(items) : '[]']
    );
    await logAudit(user.id, 'create_biolink', 'biolinks', null, rows[0]);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.put('/biolinks/:id', async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    const { titulo, items } = req.body;
    const { rows: oldRows } = await db.query('SELECT * FROM biolinks WHERE id = $1', [id]);
    if (oldRows.length === 0) return res.status(404).json({ error: 'Biolink não encontrado' });

    const { rows: setorRows } = await db.query('SELECT permissoes_json FROM setores WHERE id = $1', [user.setor_id]);
    const permissoes = setorRows[0] ? setorRows[0].permissoes_json : {};
    if (!(permissoes && permissoes.biolink && (permissoes.biolink === 'write' || permissoes.biolink === 'edit'))) {
      return res.status(403).json({ error: 'Seu setor não tem permissão para editar biolinks' });
    }

    const { rows } = await db.query(
      'UPDATE biolinks SET titulo = $1, items = $2, updated_at = now() WHERE id = $3 RETURNING *',
      [titulo || oldRows[0].titulo, items ? JSON.stringify(items) : oldRows[0].items, id]
    );
    await logAudit(user.id, 'update_biolink', 'biolinks', oldRows[0], rows[0]);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.delete('/biolinks/:id', async (req, res) => {
  try {
    const user = req.user;
    const id = req.params.id;
    const { rows: oldRows } = await db.query('SELECT * FROM biolinks WHERE id = $1', [id]);
    if (oldRows.length === 0) return res.status(404).json({ error: 'Biolink não encontrado' });

    if (user.role !== 'admin') {
      const { rows: setorRows } = await db.query('SELECT permissoes_json FROM setores WHERE id = $1', [user.setor_id]);
      const permissoes = setorRows[0] ? setorRows[0].permissoes_json : {};
      if (!(permissoes && permissoes.biolink && permissoes.biolink === 'write')) {
        return res.status(403).json({ error: 'Seu setor não tem permissão para deletar biolinks' });
      }
    }
    await db.query('DELETE FROM biolinks WHERE id = $1', [id]);
    await logAudit(user.id, 'delete_biolink', 'biolinks', oldRows[0], null);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.post('/biolinks/:id/click', async (req, res) => {
    // Nota: Se você quiser que cliques sejam PUBLICOS (sem login), mova esta rota para a seção 1 (antes do authMiddleware).
    // Por enquanto, deixei protegida.
  try {
    const id = req.params.id;
    const { rows: oldRows } = await db.query('SELECT * FROM biolinks WHERE id = $1', [id]);
    if (oldRows.length === 0) return res.status(404).json({ error: 'Biolink não encontrado' });

    const { rows } = await db.query('UPDATE biolinks SET cliques_count = cliques_count + 1 WHERE id = $1 RETURNING cliques_count', [id]);
    await logAudit(req.user.id, 'click_biolink', 'biolinks', { id, cliques_count: oldRows[0].cliques_count }, { cliques_count: rows[0].cliques_count });
    res.json({ ok: true, cliques_count: rows[0].cliques_count });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.get('/me', async (req, res) => {
  try {
    const user = req.user;
    res.json({ id: user.id, nome: user.nome, telefone: user.telefone, role: user.role, setor_id: user.setor_id });
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.put('/me', async (req, res) => {
  try {
    const user = req.user;
    const { nome } = req.body;
    const { rows: oldRows } = await db.query('SELECT id, nome FROM users WHERE id = $1', [user.id]);
    const { rows } = await db.query('UPDATE users SET nome = $1 WHERE id = $2 RETURNING id, nome, telefone', [nome || oldRows[0].nome, user.id]);
    await logAudit(user.id, 'update_profile', 'users', oldRows[0], rows[0]);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

// --- Start ---
(async () => {
  await runInitSql();
  app.listen(PORT, () => {
    console.log(`Server rodando na porta ${PORT}`);
  });
})();
