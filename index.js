require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'mysecretkey';

const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

// РЕГИСТРАЦИЯ
app.post('/api/register', async (req, res) => {
  const { login, password } = req.body;
  try {
    const exists = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (exists.rows.length > 0) {
      return res.json({ success: false, message: 'Пользователь уже существует' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (login, password) VALUES ($1, $2)', [login, passwordHash]);
    res.json({ success: true, login });
  } catch (err) {
    console.error('Ошибка регистрации:', err);
    res.json({ success: false, message: 'Ошибка сервера: ' + err.message });
  }
});

// ВХОД
app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (result.rows.length === 1) {
      const user = result.rows[0];
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        const token = jwt.sign({ login: user.login, id: user.id }, JWT_SECRET, { expiresIn: '7d' });
        return res.json({ success: true, login: user.login, token });
      }
    }
    res.json({ success: false, message: 'Неверный логин или пароль' });
  } catch (err) {
    res.json({ success: false, message: 'Ошибка сервера: ' + err.message });
  }
});

// Пример защищённого роутера (кабинет)
app.get('/api/cabinet', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: `Привет, ${decoded.login}!`, user: decoded });
  } catch {
    res.status(401).json({ message: 'Неверный токен' });
  }
});


// Получить профиль пользователя по токену
app.get('/api/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query(
      'SELECT login, lastname, firstname, middlename, email, role FROM users WHERE id = $1',
      [decoded.id]
    );
    if (result.rows.length === 1) {
      return res.json(result.rows[0]);
    } else {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }
  } catch (err) {
    return res.status(401).json({ message: 'Неверный токен', error: err.message });
  }
});

// Обновить профиль пользователя по токену
app.post('/api/profile', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    // Только эти поля можно обновлять пользователю (login и role — нет!)
    const { lastname, firstname, middlename, email } = req.body;
    await pool.query(
      'UPDATE users SET lastname = $1, firstname = $2, middlename = $3, email = $4 WHERE id = $5',
      [lastname || '', firstname || '', middlename || '', email || '', decoded.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(401).json({ success: false, message: 'Ошибка обновления', error: err.message });
  }
});

app.get('/api/deals', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    // Показываем только сделки, связанные с этим пользователем
    const result = await pool.query(
      `SELECT * FROM deals WHERE client_id = $1 OR responsible_id = $1 ORDER BY created_at DESC`,
      [decoded.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(401).json({ message: 'Ошибка авторизации', error: err.message });
  }
});

app.post('/api/deals', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const {
      title, budget, status, comment, reason, lawyer, contract_number, service_type,
      created_at, first_contact_at, reaction_time, nps, nps_comment
    } = req.body;
    const result = await pool.query(
      `INSERT INTO deals (title, client_id, responsible_id, budget, status, comment, reason, lawyer, contract_number, service_type, created_at, first_contact_at, reaction_time, nps, nps_comment)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING *`,
      [title, decoded.id, decoded.id, budget, status, comment, reason, lawyer, contract_number, service_type, created_at, first_contact_at, reaction_time, nps, nps_comment]
    );
    res.json({ success: true, deal: result.rows[0] });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.get('/api/deals/:id', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    jwt.verify(token, JWT_SECRET); // Можно добавить проверку прав на просмотр
    const result = await pool.query('SELECT * FROM deals WHERE id = $1', [req.params.id]);
    if (result.rows.length) res.json(result.rows[0]);
    else res.status(404).json({ message: 'Сделка не найдена' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post('/api/deals/:id', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    jwt.verify(token, JWT_SECRET); // Можно добавить проверку прав на редактирование
    const { title, budget, status, comment } = req.body;
    const result = await pool.query(
      `UPDATE deals SET title=$1, budget=$2, status=$3, comment=$4 WHERE id=$5 RETURNING *`,
      [title, budget, status, comment, req.params.id]
    );
    res.json({ success: true, deal: result.rows[0] });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.post('/api/deals/:id/stage', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Нет токена' });
  try {
    const token = auth.split(' ')[1];
    jwt.verify(token, JWT_SECRET);
    const { stage } = req.body;
    const result = await pool.query(
      `UPDATE deals SET stage = $1 WHERE id = $2 RETURNING *`,
      [stage, req.params.id]
    );
    res.json({ success: true, deal: result.rows[0] });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

app.listen(3001, () => console.log('Backend started on port 3001'));