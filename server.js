const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors());

const pool = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE
});

app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  // Check if the user already exists in the database
  const checkUserSql = 'SELECT * FROM users WHERE username = ?';
  pool.query(checkUserSql, [username], (err, result) => {
    if (err) {
      console.error('Error executing SQL query:', err);
      return res.status(500).send('Error signing up');
    }

    if (result.length > 0) {
      // User already exists, send a message
      return res.status(200).send('User already available');
    } else {
      // User does not exist, hash the password and create a new user profile
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          console.error('Error hashing password:', err);
          return res.status(500).send('Error signing up');
        }

        const insertUserSql = 'INSERT INTO users (username, password) VALUES (?, ?)';
        pool.query(insertUserSql, [username, hash], (err, result) => {
          if (err) {
            console.error('Error executing SQL query:', err);
            return res.status(500).send('Error signing up');
          }
          res.status(200).send('Signup successful');
        });
      });
    }
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error getting connection from pool:', err);
      return res.status(500).send('Error logging in');
    }

    const sql = 'SELECT * FROM users WHERE username = ?';
    connection.query(sql, [username], (err, result) => {
      connection.release();
      if (err) {
        console.error('Error executing SQL query:', err);
        return res.status(500).send('Error logging in');
      }

      if (result.length > 0) {
        const storedHash = result[0].password;
        bcrypt.compare(password, storedHash, (err, isValid) => {
          if (err || !isValid) {
            return res.status(401).send('Invalid credentials');
          }
          res.status(200).send('Login successful');
        });
      } else {
        res.status(401).send('Invalid credentials');
      }
    });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
