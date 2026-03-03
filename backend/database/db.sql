CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  nickname VARCHAR(20) NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  birth_date DATE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rooms (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(50) NOT NULL,
  owner_id BIGINT REFERENCES users(id) ON DELETE CASCADE, -- Si es NULL, es una sala oficial del juego
  max_users INT DEFAULT 25,
  layout JSONB DEFAULT '[]', -- Aquí guardaremos si hay paredes o huecos en el futuro
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Creamos el Lobby Principal por defecto (owner_id = NULL)
INSERT INTO rooms (id, name, owner_id) VALUES (1, 'Lobby', NULL) 
ON CONFLICT DO NOTHING;