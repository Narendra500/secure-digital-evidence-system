CREATE SCHEMA IF NOT EXISTS integrity_schema;

CREATE TABLE IF NOT EXISTS integrity_schema.actions (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name VARCHAR(32) UNIQUE NOT NULL,
  description VARCHAR(255) NOT NULL
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'integrity_schema.integrity_status') THEN
        CREATE TYPE integrity_schema.integrity_status AS ENUM ('unchanged', 'tampered');
    END IF;
END $$;   
