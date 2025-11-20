// db.js
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL not set. The app will fail to connect to Postgres until it is set.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // se precisar de SSL em alguns provedores:
  // ssl: { rejectUnauthorized: false }
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};
