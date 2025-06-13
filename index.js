const express = require('express');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(require('cors')());

const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

app.get('/api/status', async (req, res) => {
  const result = await pool.query('SELECT NOW()');
  res.json({ status: 'ok', time: result.rows[0].now });
});

app.listen(3001, () => console.log('Backend started on port 3001'));
