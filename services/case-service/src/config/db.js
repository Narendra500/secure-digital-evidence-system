import pkg from "pg";

const { Pool } = pkg;

const pool = new Pool({
  host: "localhost",
  port: 5432,
  user: "evidence_user",
  password: "evidence_pass",
  database: "evidence_db",
});

export default pool;