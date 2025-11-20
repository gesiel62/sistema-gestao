-- init.sql
-- Cria extensões se necessário
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- tabela setores
CREATE TABLE IF NOT EXISTS setores (
  id SERIAL PRIMARY KEY,
  nome TEXT NOT NULL UNIQUE,
  permissoes_json JSONB DEFAULT '{}'::jsonb
);

-- tabela users
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  nome TEXT,
  telefone TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  setor_id INTEGER REFERENCES setores(id) ON DELETE SET NULL,
  role TEXT NOT NULL DEFAULT 'user', -- 'admin' ou 'user'
  status TEXT NOT NULL DEFAULT 'offline', -- online/offline/pendente
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- tabela biolinks
CREATE TABLE IF NOT EXISTS biolinks (
  id SERIAL PRIMARY KEY,
  titulo TEXT,
  items JSONB DEFAULT '[]'::jsonb, -- cada item: { title, url, image, required_permission }
  cliques_count BIGINT DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- tabela audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  table_name TEXT,
  old_data JSONB,
  new_data JSONB,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- tabela compliance_msgs
CREATE TABLE IF NOT EXISTS compliance_msgs (
  id SERIAL PRIMARY KEY,
  texto TEXT NOT NULL,
  obrigatoria BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- tabela user_reads (registro de quem leu mensagens obrigatórias)
CREATE TABLE IF NOT EXISTS user_reads (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  compliance_msg_id INTEGER REFERENCES compliance_msgs(id) ON DELETE CASCADE,
  read_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(user_id, compliance_msg_id)
);
