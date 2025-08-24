// src/db.js
const { Pool } = require('pg');
require('dotenv').config();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});


// ทดสอบ connection
// ทดสอบการเชื่อมต่อ
pool.connect()
  .then(client => {
    return client.query('SELECT NOW()')
      .then(res => {
        console.log('PostgreSQL live time:', res.rows[0]);
        client.release();
      })
      .catch(err => {
        client.release();
        console.error('Query error:', err);
      });
  })
  .catch(err => console.error('Pool connect error:', err));

module.exports = pool;
