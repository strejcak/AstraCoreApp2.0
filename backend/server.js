const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = 5001;
const jwtSecret = 'tajnyklic';

// Middleware pro zpracování JSON
app.use(express.json());

// Nastavení připojení k databázi
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Testování připojení k databázi
pool.connect((err) => {
  if (err) {
    console.error('Error connecting to the database', err);
  } else {
    console.log('Connected to the PostgreSQL database');
  }
});

// Middleware pro ověření JWT tokenu
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied, no token provided' });

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Endpoint pro registraci uživatele
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *',
      [username, hashedPassword]
    );

    res.status(201).json({ message: 'User registered successfully', user: result.rows[0] });
  } catch (err) {
    console.error('Error registering user', err);
    res.status(500).json({ message: 'Failed to register user' });
  }
});

// Endpoint pro přihlášení uživatele a generování JWT tokenu
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, jwtSecret, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Error logging in', err);
    res.status(500).json({ message: 'Failed to login' });
  }
});

// Endpoint pro přidání nové faktury
app.post('/api/invoices', authenticateToken, async (req, res) => {
  const { zakazka_id, invoice_type_id, issue_date, due_date, amount, payment_method, status, description } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO invoices 
       (zakazka_id, invoice_type_id, issue_date, due_date, amount, payment_method, status, description) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [zakazka_id, invoice_type_id, issue_date, due_date, amount, payment_method, status, description]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error inserting invoice', err);
    res.status(500).json({ message: 'Failed to create invoice' });
  }
});

// Endpoint pro načítání všech faktur
app.get('/api/invoices', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM invoices');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching invoices', err);
    res.status(500).json({ message: 'Failed to fetch invoices' });
  }
});

// Endpoint pro načtení konkrétní faktury podle ID
app.get('/api/invoices/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM invoices WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      res.status(404).json({ message: 'Invoice not found' });
    } else {
      res.json(result.rows[0]);
    }
  } catch (err) {
    console.error('Error fetching invoice', err);
    res.status(500).json({ message: 'Failed to fetch invoice' });
  }
});

// Endpoint pro aktualizaci faktury
app.put('/api/invoices/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { zakazka_id, invoice_type_id, issue_date, due_date, amount, payment_method, status, description } = req.body;
  try {
    const result = await pool.query(
      `UPDATE invoices 
       SET zakazka_id = $1, invoice_type_id = $2, issue_date = $3, due_date = $4, amount = $5, 
           payment_method = $6, status = $7, description = $8 
       WHERE id = $9 RETURNING *`,
      [zakazka_id, invoice_type_id, issue_date, due_date, amount, payment_method, status, description, id]
    );
    if (result.rows.length === 0) {
      res.status(404).json({ message: 'Invoice not found' });
    } else {
      res.json(result.rows[0]);
    }
  } catch (err) {
    console.error('Error updating invoice', err);
    res.status(500).json({ message: 'Failed to update invoice' });
  }
});

// Endpoint pro smazání faktury
app.delete('/api/invoices/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM invoices WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      res.status(404).json({ message: 'Invoice not found' });
    } else {
      res.json({ message: 'Invoice deleted successfully', invoice: result.rows[0] });
    }
  } catch (err) {
    console.error('Error deleting invoice', err);
    res.status(500).json({ message: 'Failed to delete invoice' });
  }
});

// Endpoint pro přidání nové zakázky
app.post('/api/zakazky', authenticateToken, async (req, res) => {
  const { nazev, adresa, cena_bez_dph, dph, cena_s_dph, stav, zisk, stavebni_denik } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO zakazky 
       (nazev, adresa, cena_bez_dph, dph, cena_s_dph, stav, zisk, stavebni_denik) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [nazev, adresa, cena_bez_dph, dph, cena_s_dph, stav, zisk, stavebni_denik]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error inserting zakazka', err);
    res.status(500).json({ message: 'Failed to create zakazka' });
  }
});

// Endpoint pro načítání všech zakázek
app.get('/api/zakazky', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM zakazky');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching zakazky', err);
    res.status(500).json({ message: 'Failed to fetch zakazky' });
  }
});

// Endpoint pro načtení konkrétní zakázky podle ID
app.get('/api/zakazky/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM zakazky WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      res.status(404).json({ message: 'Zakazka not found' });
    } else {
      res.json(result.rows[0]);
    }
  } catch (err) {
    console.error('Error fetching zakazka', err);
    res.status(500).json({ message: 'Failed to fetch zakazka' });
  }
});
// Endpoint pro aktualizaci zakázky
app.put('/api/zakazky/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { nazev, adresa, cena_bez_dph, dph, cena_s_dph, stav, zisk, stavebni_denik } = req.body;
    try {
      const result = await pool.query(
        `UPDATE zakazky 
         SET nazev = $1, adresa = $2, cena_bez_dph = $3, dph = $4, cena_s_dph = $5, 
             stav = $6, zisk = $7, stavebni_denik = $8 
         WHERE id = $9 RETURNING *`,
        [nazev, adresa, cena_bez_dph, dph, cena_s_dph, stav, zisk, stavebni_denik, id]
      );
      if (result.rows.length === 0) {
        res.status(404).json({ message: 'Zakazka not found' });
      } else {
        res.json(result.rows[0]);
      }
    } catch (err) {
      console.error('Error updating zakazka', err);
      res.status(500).json({ message: 'Failed to update zakazka' });
    }
  });
  
  // Endpoint pro smazání zakázky
  app.delete('/api/zakazky/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
      const result = await pool.query('DELETE FROM zakazky WHERE id = $1 RETURNING *', [id]);
      if (result.rows.length === 0) {
        res.status(404).json({ message: 'Zakazka not found' });
      } else {
        res.json({ message: 'Zakazka deleted successfully', zakazka: result.rows[0] });
      }
    } catch (err) {
      console.error('Error deleting zakazka', err);
      res.status(500).json({ message: 'Failed to delete zakazka' });
    }
  });
  
  // Spuštění serveru
  app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });
  