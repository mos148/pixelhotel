CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  nickname VARCHAR(20) NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  birth_date DATE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE users 
ADD COLUMN avatar_config JSONB DEFAULT '{"shirt": 16733525}'::jsonb;

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

INSERT INTO rooms (name, owner_id, max_users) 
VALUES 
  ('La Piscina', NULL, 50),
  ('El Bar Pixel', NULL, 20),
  ('Sala de Juegos', NULL, 15);

--Sincronizamos el contador automático (secuencia) con el ID real más alto
SELECT setval('rooms_id_seq', (SELECT MAX(id) FROM rooms));

--insertamos las salas nuevas. 
INSERT INTO rooms (name, owner_id, max_users) 
VALUES 
  ('La Piscina', NULL, 50),
  ('El Bar Pixel', NULL, 20),
  ('Sala de Juegos', NULL, 15);

  -- Añadimos las columnas con un tamaño por defecto de 10x10
ALTER TABLE rooms 
ADD COLUMN width INT DEFAULT 10,
ADD COLUMN height INT DEFAULT 10;

-- distintos tamaños de salas:
UPDATE rooms SET width = 15, height = 15 WHERE id = 1; -- El Lobby Principal será grande
UPDATE rooms SET width = 20, height = 10 WHERE name = 'La Piscina'; -- Rectangular y muy larga
UPDATE rooms SET width = 8, height = 8 WHERE name = 'El Bar Pixel'; -- Pequeñita
UPDATE rooms SET width = 12, height = 12 WHERE name = 'Sala de Juegos';

-- Creamos la tabla de amistades
CREATE TABLE friendships (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    friend_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'pending', -- Puede ser 'pending' (pendiente) o 'accepted' (aceptado)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Evitamos duplicados (user_id, friend_id) y (friend_id, user_id)
    UNIQUE(user_id, friend_id)
);

--Pruebas

-- 1. Tabla del catálogo (tipos de muebles que existen)
CREATE TABLE catalog_items (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    color_hex VARCHAR(10) NOT NULL -- Temporal, hasta que usemos texturas PNG
);

-- 2. Tabla de muebles colocados en las salas
CREATE TABLE room_furnis (
    id SERIAL PRIMARY KEY,
    room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    item_id INTEGER REFERENCES catalog_items(id) ON DELETE CASCADE,
    x INTEGER NOT NULL,
    y INTEGER NOT NULL
);

-- 3. Insertamos un mueble en el catálogo (Nuestra caja marrón)
INSERT INTO catalog_items (name, color_hex) VALUES ('Caja Madera', '0x8B4513');

-- 4. Colocamos esa caja en la Sala 1 (Lobby) en la coordenada 5,5
INSERT INTO room_furnis (room_id, item_id, x, y) VALUES (1, 1, 5, 5);

--SISTEMA DE TIENDA Y MONEDA
---- 1. Añadimos la moneda a los usuarios (les damos 100000 de bienvenida por defecto)
ALTER TABLE users ADD COLUMN creditos INTEGER DEFAULT 100000;

-- 2. Añadimos el precio al catálogo
ALTER TABLE catalog_items ADD COLUMN price INTEGER DEFAULT 0;

-- Le ponemos precios a lo que ya teníamos (por ejemplo, la caja cuesta 50)
UPDATE catalog_items SET price = 50 WHERE id = 1;

-- Añadimos un par de muebles más para probar la tienda luego
INSERT INTO catalog_items (name, color_hex, price) VALUES ('Planta Retro', '0x228B22', 150);
INSERT INTO catalog_items (name, color_hex, price) VALUES ('Silla Azul', '0x0000FF', 75);

-- 3. Creamos la tabla del Inventario (Las cosas que el usuario ha comprado pero no ha puesto en sala)
-- Es importante que cada mueble sea una fila individual en esta tabla, porque el usuario puede tener 3 plantas retro iguales, y cada una es un objeto distinto que puede colocar o quitar de las salas.
CREATE TABLE inventory (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    item_id INTEGER REFERENCES catalog_items(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Añadimos las dos columnas nuevas
ALTER TABLE catalog_items ADD COLUMN sprite_name VARCHAR(50);
ALTER TABLE catalog_items ADD COLUMN is_walkable BOOLEAN DEFAULT false;

-- Actualizamos la Caja de Madera (sólida)
UPDATE catalog_items SET sprite_name = 'caja', is_walkable = false WHERE id = 1;

-- Actualizamos la Planta Retro (sólida)
UPDATE catalog_items SET sprite_name = 'planta', is_walkable = false WHERE id = 2;

-- Convertimos el item 3 en una Alfombra para probar que se puede pisar
UPDATE catalog_items SET name = 'Alfombra Roja', color_hex = '0xFF0000', sprite_name = 'alfombra', is_walkable = true WHERE id = 3;



-- 1. Crear tabla de categorías
CREATE TABLE catalog_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL
);

-- 2. Insertar algunas categorías
INSERT INTO catalog_categories (name) VALUES ('Suelos'), ('Decoración'), ('Muebles'), ('Navidad');

-- 3. Añadir columna a catalog_items para vincularla
ALTER TABLE catalog_items ADD COLUMN category_id INTEGER REFERENCES catalog_categories(id);

INSERT INTO catalog_categories (name) VALUES ('Cocina');

INSERT INTO catalog_items (name, color_hex, price, category_id, sprite_name, is_walkable) 
VALUES 
('Nevera Blanca', '0xFFFFFF', 150, 2, 'cocina/nevera', false),
('Horno Industrial', '0xFFFFFF', 200, 2, 'cocina/horno', false),
('Alfombra de Cocina', '0xFFFFFF', 50, 2, 'cocina/alfombra_cocina', true);

-- mas inserts
INSERT INTO catalog_items (name, color_hex, price, category_id, sprite_name, is_walkable)
VALUES 
('Silla de Cocina', '0xFFFFFF', 10, 2, 'cocina/silla_cocina', false),
('Mesa Cuadrada', '0xFFFFFF', 120, 2, 'cocina/mesa_cuadrada', false),
('Mesa Redonda', '0xFFFFFF', 100, 2, 'cocina/mesa_redonda', false),
('Armario de Cocina', '0xFFFFFF', 180, 2, 'cocina/armario', false),
('Cajonera de Cocina', '0xFFFFFF', 80, 2, 'cocina/cajon', false),
('Cafetera', '0xFFFFFF', 60, 2, 'cocina/cafetera', false);


ALTER TABLE room_furnis ADD COLUMN direction INTEGER DEFAULT 0;
-- 0 = Normal (mirando a la derecha)
-- 1 = Girado (mirando a la izquierda)