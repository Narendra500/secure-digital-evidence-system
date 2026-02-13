const { Pool } = require("pg");

const pool = new Pool({
  host: "localhost",
  port: 5432,
  user: "evidence_user",
  password: "evidence_pass",
  database: "evidence_db"
});

module.exports = pool;
