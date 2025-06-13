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


app.listen(3001, () => console.log('Backend started on port 3001'));