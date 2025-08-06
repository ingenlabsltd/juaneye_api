// db.js
const mysql   = require('mysql2/promise');
const dotenv  = require('dotenv');

dotenv.config();

// Create a MySQL connection pool
const pool = mysql.createPool({
  host            : process.env.DB_HOST,
  user            : process.env.DB_USER,
  password        : process.env.DB_PASSWORD,
  database        : process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit : 10,
  queueLimit      : 0,
  timezone        : '+08:00',
  dateStrings     : true
});

pool.on('connection', (connection) => {
  connection.query("SET time_zone = '+08:00';");
});

module.exports = pool;