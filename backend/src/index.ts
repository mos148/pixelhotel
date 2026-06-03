import express from "express";
import "dotenv/config";
import { pool } from "./db.js";
import bcrypt from "bcryptjs";
import type { RegisterBody, UserPublic } from "./types/auth.js";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { requireAuth } from "./middleware/requireAuth.js";
import http from "http";
import { Server } from "socket.io";
import type { PlayerState } from "./types/player.js";
import cookie from "cookie";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import { createCanvas, loadImage } from "canvas";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const players = new Map<string, PlayerState>();
const userSocket = new Map<number, string>();
const app = express();

app.use(
  cors({
    origin: ["http://localhost:4200", "http://79.143.94.107", "http://79.143.94.107:4200", "http://pixelhotel.online", "http://www.pixelhotel.online", "http://www.pixelhotel.online:4200", "http://pixelhotel.online:4200"],
    credentials: true,
  }),
);
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "../../client")));

// Servir index.html en la raíz
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "../../client/index.html"));
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    // 1) Validaciones mínimas
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: "Faltan campos" });
    }
    if (typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ ok: false, error: "Tipos inválidos" });
    }

    // 2) Buscar usuario por email
    const result = await pool.query<{
      id: number;
      email: string;
      password_hash: string;
      nickname: string;
    }>(
      `SELECT id, email, password_hash, nickname
       FROM users
       WHERE email = $1`,
      [email],
    );

    const user = result.rows[0];
    if (!user) {
      // No revelamos si existe o no el email
      return res
        .status(401)
        .json({ ok: false, error: "Credenciales incorrectas" });
    }

    // 3) Comparar password con el hash
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res
        .status(401)
        .json({ ok: false, error: "Credenciales incorrectas" });
    }

    // 4) Crear JWT
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return res
        .status(500)
        .json({ ok: false, error: "JWT_SECRET no configurado" });
    }

    const token = jwt.sign(
      { userId: user.id }, // payload (lo mínimo)
      secret,
      { expiresIn: "7d" }, // duración del token
    );

    // 5) Guardar JWT en cookie httpOnly
    res.cookie("auth", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // en producción con HTTPS: true
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
    });

    // 6) Responder OK (sin password_hash)
    return res.json({
      ok: true,
      user: { id: user.id, email: user.email, nickname: user.nickname },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

app.post("/register", async (req, res) => {
  try {
    const body = req.body as Partial<RegisterBody>;

    // 1) Validación
    if (!body.email || !body.password || !body.nickname || !body.birth_date) {
      return res.status(400).json({ ok: false, error: "Faltan campos" });
    }
    if (typeof body.email !== "string" || typeof body.password !== "string") {
      return res.status(400).json({ ok: false, error: "Tipos inválidos" });
    }
    if (
      typeof body.nickname !== "string" ||
      typeof body.birth_date !== "string"
    ) {
      return res.status(400).json({ ok: false, error: "Tipos inválidos" });
    }
    if (body.password.length < 6) {
      return res
        .status(400)
        .json({ ok: false, error: "Password demasiado corta (min 6)" });
    }

    // 2) Hashear contraseña
    const password_hash = await bcrypt.hash(body.password, 10);

    // 3) Insert seguro (parametrizado) en PostgreSQL
    const result = await pool.query<UserPublic>(
      `INSERT INTO users (email, password_hash, nickname, birth_date)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, nickname, birth_date, created_at`,
      [body.email, password_hash, body.nickname, body.birth_date],
    );

    return res.status(201).json({ ok: true, user: result.rows[0] });
  } catch (err: any) {
    // Email duplicado (constraint UNIQUE)
    if (err?.code === "23505") {
      return res
        .status(409)
        .json({ ok: false, error: "Ese email ya está registrado" });
    }
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Logout: borrar cookie
app.post("/logout", (_req, res) => {
  res.clearCookie("auth");
  return res.json({ ok: true });
});

// Ruta para enviar solicitud de amistad o aceptarla
app.post("/friends/request", requireAuth, async (req, res) => {
  const userId = Number((req as any).userId);
  const { friendId } = req.body;

  try {
    // Primero comprobamos si ya existe una relación previa
    const check = await pool.query(
      `SELECT * FROM friendships WHERE 
            (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)`,
      [userId, friendId],
    );

    if (check.rows.length > 0) {
      return res
        .status(400)
        .json({ error: "Ya existe una solicitud o amistad con este usuario." });
    }

    // Si no existe, creamos la solicitud en estado 'pending'
    await pool.query(
      `INSERT INTO friendships (user_id, friend_id, status) VALUES ($1, $2, 'pending')`,
      [userId, friendId],
    );

    res.json({ ok: true, message: "Solicitud de amistad enviada" });
  } catch (err) {
    console.error("Error en friends/request:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Obtener lista de amigos (relaciones aceptadas)
app.get("/friends", requireAuth, async (req, res) => {
  const userId = Number((req as any).userId);
  try {
    const query = `
            SELECT u.id, u.nickname
            FROM users u
            JOIN friendships f ON (f.user_id = u.id OR f.friend_id = u.id)
            WHERE (f.user_id = $1 OR f.friend_id = $1)
            AND f.status = 'accepted'
            AND u.id != $1
        `;

    const result = await pool.query(query, [userId]);

    const amigos = result.rows.map((u: any) => ({
      id: u.id,
      nickname: u.nickname,
      online: userSocket.has(u.id),
    }));

    res.json({ ok: true, amigos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "Error" });
  }
});

//  Ver solicitudes pendientes que tengo
app.get("/friends/requests", requireAuth, async (req, res) => {
  const userId = Number((req as any).userId);
  try {
    // Buscamos solo donde tú eres el RECEPTOR (friend_id) y está pendiente
    const result = await pool.query(
      `
            SELECT f.id, u.nickname as sender_name 
            FROM friendships f
            JOIN users u ON f.user_id = u.id
            WHERE f.friend_id = $1 AND f.status = 'pending'`,
      [userId],
    );

    res.json({ ok: true, requests: result.rows });
  } catch (err) {
    console.error("ERROR EN SOLICITUDES:", err);
    res.status(500).json({ ok: false, error: "No se pudieron cargar solicitudes" });
  }
});

// Aceptar o Denegar solicitud de amistad
app.post("/friends/action", requireAuth, async (req, res) => {
  const userId = Number((req as any).userId);
  const { friendshipId, action } = req.body;

  if (action === "accepted") {
    // Aceptamos: Cambiamos estado
    await pool.query(
      "UPDATE friendships SET status = 'accepted' WHERE id = $1 AND friend_id = $2",
      [friendshipId, userId],
    );
    res.json({ success: true });
  } else {
    // DENIEGAS O RECHAZAS: Eliminamos la fila (ya no nos interesa conservarla)
    await pool.query(
      "DELETE FROM friendships WHERE id = $1 AND (friend_id = $2 OR user_id = $2)",
      [friendshipId, userId],
    );
    res.json({ success: true });
  }
});

// --- ELIMINAR AMIGO ---
app.post("/friends/remove", requireAuth, async (req, res) => {
  const userId = Number((req as any).userId);
  const { friendId } = req.body;

  try {
    // Borramos la relación
    await pool.query(
      `DELETE FROM friendships 
       WHERE (user_id = $1 AND friend_id = $2) 
          OR (user_id = $2 AND friend_id = $1)`,
      [userId, friendId],
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Error al eliminar amigo:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Ruta reutilizable para consultar el estado de relación con cualquier usuario
app.get("/users/status/:id", requireAuth, async (req, res) => {
  const myId = Number((req as any).userId);
  const targetId = Number(req.params.id);

  if (myId === targetId) return res.json({ status: "self" });

  try {
    const result = await pool.query(
      `
            SELECT status 
            FROM friendships 
            WHERE (user_id = $1 AND friend_id = $2) 
               OR (user_id = $2 AND friend_id = $1)
            LIMIT 1`,
      [myId, targetId],
    );

    if (result.rows.length > 0) {
      res.json({ status: result.rows[0].status }); // 'pending' o 'accepted'
    } else {
      res.json({ status: "none" }); // No hay relación
    }
  } catch (err) {
    res.status(500).json({ error: "Error consultando estado" });
  }
});

// Ruta protegida de ejemplo
app.get("/protected", requireAuth, (req, res) => {
  res.json({
    ok: true,
    message: "Acceso permitido",
    userId: (req as any).userId,
  });
});

// Obtener datos del usuario logueado
app.get("/me", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).userId;

    const result = await pool.query<UserPublic>(
      `SELECT id, email, nickname, birth_date, created_at, creditos, avatar_config
       FROM users
       WHERE id = $1`,
      [userId],
    );

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ ok: false, error: "Usuario no encontrado" });
    }

    return res.json({ ok: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

app.get("/users/:id/avatar", async (req, res) => {
  try {
    const userId = req.params.id;

    const result = await pool.query(
      "SELECT avatar_config FROM users WHERE id = $1",
      [userId],
    );

    if (result.rows.length === 0) {
      return res.status(404).send("Usuario no encontrado");
    }

    const config = result.rows[0].avatar_config || {
      pant: 16777215,
      shirt: 16777215,
      shoes: 16777215,
      hair: 0x8B4513,
    };

    const assetsPath = path.join(__dirname, "../assets");
    const baseImg = await loadImage(path.join(assetsPath, "base_avatar.png"));
    const shirtImg = await loadImage(path.join(assetsPath, "shirts.png"));
    const pantImg = await loadImage(path.join(assetsPath, "jeans.png"));
    const shoesImg = await loadImage(path.join(assetsPath, "shoes.png"));
    const hairImg = await loadImage(path.join(assetsPath, "hair.png"));

    // Cada imagen tiene 4x4 frames
    const frameW = baseImg.width / 4;
    const frameH = baseImg.height / 4;

    // Coordenadas para coger el muñeco mirando de frente (Columna 1, Fila 3)
    const startX = 0;
    const startY = frameH * 3;

    const canvas = createCanvas(frameW, frameH);
    const ctx = canvas.getContext("2d");

    const drawLayer = (img: any, colorValue: string | number) => {
      // Nos aseguramos de que el color sea un número antes de pasarlo a Hex
      const decimalColor = Number(colorValue);
      const hexColor = "#" + decimalColor.toString(16).padStart(6, "0");

      const layerCanvas = createCanvas(frameW, frameH);
      const layerCtx = layerCanvas.getContext("2d");

      // Recortar la capa usando startX y startY
      layerCtx.drawImage(
        img,
        startX,
        startY,
        frameW,
        frameH,
        0,
        0,
        frameW,
        frameH,
      );

      // Aplicar el tinte
      layerCtx.globalCompositeOperation = "source-in";
      layerCtx.fillStyle = hexColor;
      layerCtx.fillRect(0, 0, frameW, frameH);

      // Multiplicar por la textura original para recuperar las sombras y arrugas de la ropa
      layerCtx.globalCompositeOperation = "multiply";
      layerCtx.drawImage(
        img,
        startX,
        startY,
        frameW,
        frameH,
        0,
        0,
        frameW,
        frameH,
      );

      // Pegar esta capa ya coloreada en el lienzo principal
      ctx.drawImage(layerCanvas, 0, 0);
    };

    // Montar el avatar por orden de capas
    ctx.drawImage(
      baseImg,
      startX,
      startY,
      frameW,
      frameH,
      0,
      0,
      frameW,
      frameH,
    );

    if (config.shoes) drawLayer(shoesImg, config.shoes);
    if (config.pant) drawLayer(pantImg, config.pant);
    if (config.shirt) drawLayer(shirtImg, config.shirt);
    if (config.hair) drawLayer(hairImg, config.hair);

    const buffer = canvas.toBuffer("image/png");
    res.set("Content-Type", "image/png");
    res.set("Cache-Control", "no-store");
    res.send(buffer);
  } catch (error) {
    console.error("Error generando avatar:", error);
    res.status(500).send("Error interno generando avatar");
  }
});
function getUserFromSocket(socket: any) {
  const cookieHeader = socket.handshake.headers.cookie;
  if (!cookieHeader) return null;

  const cookies = cookie.parse(cookieHeader);
  const token = cookies.auth;
  if (!token) return null;

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET!);
    return payload as { userId: number };
  } catch {
    return null;
  }
}

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true,
  },
});
// Autenticación de socket.io usando cookie "auth" con JWT (evitamos duplicados)
io.use((socket, next) => {
  try {
    const cookieHeader = socket.handshake.headers.cookie || "";
    const cookies = cookie.parse(cookieHeader);

    const token = cookies.auth;
    if (!token) return next(new Error("No auth cookie"));

    const secret = process.env.JWT_SECRET;
    if (!secret) return next(new Error("JWT_SECRET missing"));

    const payload = jwt.verify(token, secret) as {
      userId: number;
      sv?: number;
    };
    socket.data.userId = payload.userId;

    return next();
  } catch (e) {
    return next(new Error("Unauthorized"));
  }
});

function broadcastOnlineCount() {
  io.emit("online:update", { count: io.engine.clientsCount });
}

io.on("connection", (socket) => {
  const userId = socket.data.userId as number | undefined;

  // Si no hay userId, fuera (por seguridad)
  if (!userId) {
    socket.disconnect(true);
    return;
  }

  // Si este usuario ya tenía un socket activo, lo expulsamos
  const prevSocketId = userSocket.get(userId);
  if (prevSocketId && prevSocketId !== socket.id) {
    const prev = io.sockets.sockets.get(prevSocketId);
    if (prev) {
      prev.emit("session:kicked"); // aviso al cliente viejo
      prev.disconnect(true); // lo echamos
    }
  }

  // Guardamos este socket como el activo del userId
  userSocket.set(userId, socket.id);

  console.log("user connected:", socket.id);
  broadcastOnlineCount();

  socket.on("chat:send", (payload) => {
    // Buscamos al jugador primero
    const p = players.get(socket.id);
    if (!p) return;

    io.to(`room:${p.roomId}`).emit("chat:msg", {
      text: payload?.text ?? "",
      nickname: payload?.nickname ?? "???",
      at: Date.now(),
    });
  });

  // Indicador de escritura (typing)
  socket.on("chat:typing", (isTyping) => {
    // 1. Buscamos al jugador
    const p = players.get(socket.id);
    if (!p) return;

    // 2. Enviamos solo a su sala (usando socket.to en lugar de socket.broadcast)
    socket.to(`room:${p.roomId}`).emit("player:typing", {
      socketId: socket.id,
      isTyping: !!isTyping,
    });
  });

  // Chat privado (susurros por Nickname)
  socket.on("private:message", (data) => {
    console.log(
      `DEBUG: Mensaje recibido de ${data.fromNickname} para el jugador: ${data.to}`,
    );

    const destinatarioNickname = data.to;
    let destinatarioSocketId = null;

    // Buscamos en el Map 'players' quién tiene ese nickname
    for (const [id, player] of players.entries()) {
      if (player.nickname === destinatarioNickname) {
        destinatarioSocketId = id;
        break; // Detenemos la búsqueda
      }
    }

    // Verificamos si encontramos al jugador y si sigue conectado
    if (destinatarioSocketId && io.sockets.sockets.get(destinatarioSocketId)) {
      console.log("DEBUG: ¡Destinatario encontrado! Enviando...");

      io.to(destinatarioSocketId).emit("private:message", {
        fromNickname: data.fromNickname, // Le decimos quién se lo envía
        text: data.text,
      });
    } else {
      console.log(
        "DEBUG: ERROR. No se encontró al jugador con Nickname:",
        destinatarioNickname,
      );
    }
  });

  // --- SEGUIR A UN JUGADOR ---
  socket.on("player:follow", (payload) => {
    const targetNickname = payload.targetNickname;
    let foundRoomId = null;

    // Buscamos en el mapa de jugadores a ver dónde está el jugador con ese nickname
    for (const player of players.values()) {
      if (player.nickname === targetNickname) {
        foundRoomId = player.roomId;
        break; // Lo encontramos, dejamos de buscar
      }
    }

    // Si encontramos su sala, se lo decimos al cliente para que viaje
    if (foundRoomId) {
      socket.emit("player:follow_result", { roomId: foundRoomId });
    }
  });

  // Desconexión
  socket.on("disconnect", () => {
    const existed = players.get(socket.id);
    players.delete(socket.id);

    if (existed) {
      // Avisamos solo a la sala en la que estaba
      socket
        .to(`room:${existed.roomId}`)
        .emit("player:left", { socketId: socket.id });
    }

    const userId = socket.data.userId as number | undefined;
    if (userId) {
      const current = userSocket.get(userId);
      if (current === socket.id) userSocket.delete(userId);
    }

    console.log("❌ user disconnected:", socket.id);
    broadcastOnlineCount();
  });

  socket.on("player:hello", async () => {
    const userId = socket.data.userId as number | undefined;
    if (!userId) {
      socket.disconnect(true); // seguridad
      return;
    }
    // Obtener nickname y configuración de avatar desde la BD
    const result = await pool.query(
      "SELECT nickname, avatar_config, creditos FROM users WHERE id = $1",
      [userId],
    );

    const nickname = result.rows[0]?.nickname ?? "Player";
    const shirtColor = result.rows[0]?.avatar_config?.shirt
      ? Number(result.rows[0].avatar_config.shirt)
      : 0xffffff;
    const pantColor = result.rows[0]?.avatar_config?.pant;
    const shoesColor = result.rows[0]?.avatar_config?.shoes;
    const hairColor = result.rows[0]?.avatar_config?.hair;
    const creditos = result.rows[0]?.creditos ?? 0;


    // Por defecto, todos entran a la sala 1 (Lobby)
    const roomId = 1;
    const roomStr = `room:${roomId}`;

    // Buscamos los furnis del Lobby (roomId = 1)
    const furnisResult = await pool.query(
      `SELECT rf.id, rf.x, rf.y, rf.direction, ci.name, ci.color_hex, ci.sprite_name, ci.is_walkable 
   FROM room_furnis rf JOIN catalog_items ci ON rf.item_id = ci.id WHERE rf.room_id = $1`,
      [roomId],
    );

    // Unimos el socket a la sala de Socket.io
    socket.join(roomStr);

    const spawnX = 0;
    const spawnY = 0;

    const me: PlayerState = {
      socketId: socket.id,
      nickname,
      x: spawnX,
      y: spawnY,
      roomId: roomId, // Asignamos el ID de la sala por defecto (Lobby)
      id: userId,
      shirtColor: shirtColor,
      pantColor: pantColor,
      shoesColor: shoesColor,
      hairColor: hairColor,
      creditos: creditos,
    };

    players.set(socket.id, me);

    // Filtramos para enviarle SOLO los jugadores que estén en su misma sala
    const playersInRoom = Array.from(players.values()).filter(
      (p) => p.roomId === roomId,
    );

    // Enviamos al jugador que se unió su estado inicial y el de los demás
    socket.emit("players:init", {
      me: me, //
      players: playersInRoom,
      furnis: furnisResult.rows,
    });

    // Avisamos SOLO a los de esta sala de que hemos entrado
    socket.to(roomStr).emit("player:joined", me);
  });

  // Movimiento de jugador
  socket.on("player:move", (payload) => {
    const p = players.get(socket.id);
    if (!p) return;

    const toX = Number(payload?.toX);
    const toY = Number(payload?.toY);

    if (!Number.isFinite(toX) || !Number.isFinite(toY)) return;

    // Guardamos el destino como "posición" (estado simple).
    p.x = toX;
    p.y = toY;

    // io.to() envía a todos los de la sala (incluido el que se mueve)
    io.to(`room:${p.roomId}`).emit("player:moved", {
      socketId: socket.id,
      toX: p.x,
      toY: p.y,
    });
  });

  // --- OBTENER LISTA DE SALAS (Públicas, Mis Salas y De Jugadores) ---
  socket.on("rooms:request", async () => {
    try {
      const userId = socket.data.userId;

      // 1. Públicas
      const resPublic = await pool.query(`
      SELECT id, name, max_users, width, height, NULL as owner_id, 'Sistema' as owner_name 
      FROM rooms WHERE owner_id IS NULL ORDER BY id ASC`);

      // 2. Mis Salas
      const resMine = await pool.query(
        `
      SELECT r.id, r.name, r.max_users, r.width, r.height, r.owner_id,
             COALESCE(u.nickname, 'Yo') as owner_name 
      FROM rooms r 
      LEFT JOIN users u ON r.owner_id = u.id 
      WHERE r.owner_id = $1 
      ORDER BY r.id ASC`,
        [userId],
      );

      // 3. Todas
      const resPlayers = await pool.query(`
      SELECT r.id, r.name, r.max_users, r.width, r.height, r.owner_id, u.nickname as owner_name 
      FROM rooms r 
      JOIN users u ON r.owner_id = u.id 
      WHERE r.owner_id IS NOT NULL 
      ORDER BY r.id DESC LIMIT 50`);

      // Función unificada para procesar todas las salas
      const mapWithCount = (room: any) => {
        const roomIdNum = Number(room.id);
        const count = Array.from(players.values()).filter(
          (p) => p.roomId === roomIdNum,
        ).length;

        return {
          ...room,
          id: roomIdNum,
          current_users: count,
          // Si el SQL no trajo nombre, ponemos el fallback aquí dentro
          owner_name: room.owner_name || "Sistema",
        };
      };

      // Aplicamos el map a cada lista. Ya no necesitamos hacer nada extra aquí.
      const publicRooms = resPublic.rows.map(mapWithCount);
      const myRooms = resMine.rows.map(mapWithCount);
      const playerRooms = resPlayers.rows.map(mapWithCount);

      // Enviamos los 3 grupos
      socket.emit("rooms:list", { publicRooms, myRooms, playerRooms });
    } catch (err) {
      console.error("Error obteniendo salas:", err);
    }
  });
  // --- CREAR UNA SALA NUEVA ---
  socket.on("room:create", async (payload) => {
    try {
      const userId = socket.data.userId;
      if (!userId) return;

      const { name, width, height, maxUsers } = payload;

      // Seguridad básica
      const safeWidth = Math.min(Math.max(Number(width) || 10, 4), 25);
      const safeHeight = Math.min(Math.max(Number(height) || 10, 4), 25);
      const safeMaxUsers = Math.min(Math.max(Number(maxUsers) || 15, 2), 50);
      const safeName = name ? String(name).substring(0, 30) : "Mi Sala";

      // Insertamos la sala a nombre de este usuario
      const result = await pool.query(
        `INSERT INTO rooms (name, owner_id, width, height, max_users) 
         VALUES ($1, $2, $3, $4, $5)  RETURNING id`,
        [safeName, userId, safeWidth, safeHeight, safeMaxUsers],
      );

      // Obtenemos el ID de la sala recién creada (usando RETURNING en la consulta)
      const roomId = result.rows[0].id;

      // Le decimos al cliente que todo ha ido bien
      socket.emit("room:created_success", { roomId: roomId });
    } catch (err) {
      console.error("Error creando sala:", err);
    }
  });

  // --- BORRAR SALA (solo si eres el dueño) ---
  socket.on("room:delete", async (data) => {
    console.log("DEBUG: Intento de borrado recibido:", data);
    try {
      const { roomId } = data;
      const userId = socket.data.userId;

      // Ejecuta este log para ver si la sala existe realmente
      const check = await pool.query(
        "SELECT id FROM rooms WHERE id = $1 AND owner_id = $2",
        [roomId, userId],
      );
      console.log(
        "DEBUG: ¿Se encontró la sala para borrar?",
        check.rows.length,
      );

      if (check.rows.length > 0) {
        await pool.query("DELETE FROM rooms WHERE id = $1", [roomId]);
        console.log("ÉXITO: Sala eliminada.");
        socket.emit("rooms:request");
      } else {
        console.log("ERROR: No tienes permiso o la sala no existe.");
      }
    } catch (err) {
      console.error("Error crítico borrando:", err);
    }
  });

  // --- VIAJAR A OTRA SALA ---
  socket.on("room:join", async (payload) => {
    console.log("SERVIDOR: Recibida petición de entrar a sala:", payload);
    const p = players.get(socket.id);
    if (!p) return;

    const newRoomId = Number(payload?.roomId);

    // Si no manda un ID válido, o si ya está en esa sala, ignoramos la petición
    if (!newRoomId || p.roomId === newRoomId) return;

    try {
      // Comprobamos que la sala existe y obtenemos sus datos (nombre, dimensiones...)
      const result = await pool.query(
        "SELECT id, name, width, height, owner_id FROM rooms WHERE id = $1",
        [newRoomId],
      );
      if (result.rows.length === 0) return;

      const roomData = result.rows[0]; // Guardamos los datos de la sala para usarlos luego

      const oldRoomStr = `room:${p.roomId}`;
      const newRoomStr = `room:${newRoomId}`;

      // Le sacamos de la sala antigua (Socket.io)
      socket.leave(oldRoomStr);

      // Avisamos a los de la sala antigua que este jugador ha desaparecido
      socket.to(oldRoomStr).emit("player:left", { socketId: socket.id });

      // Actualizamos sus datos (le cambiamos el ID de sala y lo mandamos al punto de aparición)
      p.roomId = newRoomId;
      p.x = 0;
      p.y = 0;

      //Lo metemos en la sala nueva (Socket.io)
      socket.join(newRoomStr);

      //Buscamos quiénes están ya en esa sala nueva para mandárselos
      const playersInNewRoom = Array.from(players.values()).filter(
        (player) => player.roomId === newRoomId,
      );
      //  Buscamos los furnis de esta sala en la BD
      const furnisResult = await pool.query(
        `
        SELECT rf.id, rf.x, rf.y, rf.direction, ci.name, ci.color_hex, ci.sprite_name, ci.is_walkable
        FROM room_furnis rf
        JOIN catalog_items ci ON rf.item_id = ci.id
        WHERE rf.room_id = $1
      `,
        [newRoomId],
      );

      //Le enviamos al jugador sus nuevos compañeros y confirmamos el viaje
      socket.emit("room:joined", {
        me: p,
        players: playersInNewRoom,
        roomName: result.rows[0].name,
        ownerId: result.rows[0].owner_id,
        width: roomData.width,
        height: roomData.height,
        furnis: furnisResult.rows,
      });

      //Avisamos a los que ya estaban en la sala de que ha llegado alguien nuevo
      socket.to(newRoomStr).emit("player:joined", p);
    } catch (err) {
      console.error("Error al cambiar de sala:", err);
    }
  });

  // Guardar cambio de camiseta y avisar a la sala
  socket.on("avatar:change_shirt", async (data) => {
    try {
      const userId = socket.data.userId;
      const newColor = data.color;

      // Validación básica
      const p = players.get(socket.id);
      if (!p) return;

      // Actualizamos su color
      p.shirtColor = newColor;

      // Guardamos el nuevo color en la BD (en avatar_config)
      await pool.query(
        `
          UPDATE users 
          SET avatar_config = jsonb_set(COALESCE(avatar_config, '{}'::jsonb), '{shirt}', $1::jsonb) 
          WHERE id = $2
        `,
        [String(newColor), userId],
      );

      // Avisamos a todos los de la sala (excepto al que envía)
      socket.to(`room:${p.roomId}`).emit("player:shirt_changed", {
        socketId: socket.id,
        newColor: newColor,
      });
    } catch (error) {
      console.error("❌ Error al cambiar ropa:", error);
    }
  });

  // Guardar cambio de pantalón y avisar a la sala
  socket.on("avatar:change_pant", async (data) => {
    const userId = socket.data.userId;
    const p = players.get(socket.id);
    if (!p) return;

    // Actualizamos el estado en memoria
    p.pantColor = data.color;

    // Guardamos el nuevo color en la BD (en avatar_config)
    await pool.query(
      `UPDATE users SET avatar_config = jsonb_set(COALESCE(avatar_config, '{}'::jsonb), '{pant}', $1::jsonb) WHERE id = $2`,
      [String(data.color), userId],
    );

    // Avisamos a los demás
    socket.to(`room:${p.roomId}`).emit("player:pant_changed", {
      socketId: socket.id,
      newColor: data.color,
    });
  });

  // Guardar cambio de zapatos y avisar a la sala
  socket.on("avatar:change_shoes", async (data) => {
    const userId = socket.data.userId;
    const p = players.get(socket.id);
    if (!p) return;
    // Actualizamos el estado en memoria
    p.shoesColor = data.color;
    // Guardamos el nuevo color en la BD (en avatar_config)
    await pool.query(
      `UPDATE users SET avatar_config = jsonb_set(COALESCE(avatar_config, '{}'::jsonb), '{shoes}', $1::jsonb) WHERE id = $2`,
      [String(data.color), userId],
    );
    // Avisamos a los demás
    socket.to(`room:${p.roomId}`).emit("player:shoes_changed", {
      socketId: socket.id,
      newColor: data.color,
    });
  });

  // Guardar cambio de cabello y avisar a la sala
  socket.on("avatar:change_hair", async (data) => {
    const userId = socket.data.userId;
    const p = players.get(socket.id);
    if (!p) return;
    // Actualizamos el estado en memoria
    p.hairColor = data.color;
    // Guardamos el nuevo color en la BD (en avatar_config)
    await pool.query(
      `UPDATE users SET avatar_config = jsonb_set(COALESCE(avatar_config, '{}'::jsonb), '{hair}', $1::jsonb) WHERE id = $2`,
      [String(data.color), userId],
    );
    // Avisamos a los demás
    socket.to(`room:${p.roomId}`).emit("player:hair_changed", {
      socketId: socket.id,
      newColor: data.color,
    });
  });

  // --- SISTEMA DE TIENDA: COMPRAR FURNI ---
  socket.on("shop:buy", async (data) => {
    const userId = socket.data.userId;
    const { itemId } = data;

    try {
      // Obtenemos el precio del item y los créditos del usuario
      const itemRes = await pool.query(
        `SELECT price FROM catalog_items WHERE id = $1`,
        [itemId],
      );
      const userRes = await pool.query(
        `SELECT creditos FROM users WHERE id = $1`,
        [userId],
      );

      if (itemRes.rows.length === 0 || userRes.rows.length === 0) return;

      const precio = itemRes.rows[0].price;
      const misCreditos = userRes.rows[0].creditos;

      //  Comprobamos que tiene créditos suficientes
      if (misCreditos < precio) {
        socket.emit("shop:error", {
          message: "No tienes suficientes créditos.",
        });
        return;
      }

      // Empieza la transacción (Restar dinero y añadir al inventario)
      await pool.query("BEGIN"); // Iniciamos transacción segura

      // Restamos los créditos
      const updateRes = await pool.query(
        `UPDATE users SET creditos = creditos - $1 WHERE id = $2 RETURNING creditos`,
        [precio, userId],
      );

      // Añadimos el objeto al inventario
      await pool.query(
        `INSERT INTO inventory (user_id, item_id) VALUES ($1, $2)`,
        [userId, itemId],
      );

      await pool.query("COMMIT"); // Guardamos todo

      // Avisamos al cliente de su nuevo saldo y de que la compra fue un éxito
      const nuevosCreditos = updateRes.rows[0].creditos;
      socket.emit("shop:success", {
        message: "¡Compra realizada con éxito!",
        creditos: nuevosCreditos,
      });
    } catch (err) {
      await pool.query("ROLLBACK"); // Si algo falla, cancelamos todo para que no pierda el dinero
      console.error("Error en la compra:", err);
      socket.emit("shop:error", { message: "Error al procesar la compra." });
    }
  });

  // --- SISTEMA DE TIENDA: PEDIR CATÁLOGO ---
  socket.on("shop:request", async () => {
    try {
      // Pedimos los datos y cruzamos las tablas para traer también el nombre de la categoría (si tiene)
      const result = await pool.query(`
        SELECT c.id, c.name, c.price, c.color_hex, c.sprite_name, c.is_walkable, cat.name as category_name
        FROM catalog_items c
        LEFT JOIN catalog_categories cat ON c.category_id = cat.id
        ORDER BY cat.id, c.id ASC
      `);

      // AGRUPAMOS POR CATEGORÍA
      const grouped = result.rows.reduce((acc: any, item: any) => {
        const cat = item.category_name || "Otros"; // Si no tiene categoría, va a "Otros"
        if (!acc[cat]) acc[cat] = [];
        acc[cat].push(item);
        return acc;
      }, {});

      //  Enviamos el objeto agrupado
      socket.emit("shop:catalog", grouped);
    } catch (err) {
      console.error("Error en shop:request:", err);
    }
  });

  // --- SISTEMA DE INVENTARIO: PEDIR MIS MUEBLES ---
  socket.on("inventory:request", async () => {
    const userId = socket.data.userId;
    if (!userId) return;

    try {
      // Buscamos los muebles del usuario y los agrupamos por tipo
      const result = await pool.query(
        `SELECT c.id as item_id, c.name, c.color_hex, c.sprite_name, c.is_walkable, COUNT(i.id) as amount
   FROM inventory i JOIN catalog_items c ON i.item_id = c.id
   WHERE i.user_id = $1 GROUP BY c.id, c.name, c.color_hex, c.sprite_name, c.is_walkable ORDER BY c.name ASC`,
        [userId],
      );

      socket.emit("inventory:list", result.rows);
    } catch (err) {
      console.error("Error pidiendo el inventario:", err);
    }
  });

  // --- SISTEMA DE CONSTRUCCIÓN: COLOCAR MUEBLE ---
  socket.on("furni:place", async (data) => {
    const userId = socket.data.userId;
    const { itemId, x, y } = data;

    const p = players.get(socket.id);
    if (!p || !p.roomId) return;

    const esDueno = await esDuenoDeLaSala(userId, p.roomId);
    if (!esDueno) {
      socket.emit("shop:error", {
        message: "No puedes colocar muebles en una sala que no es tuya.",
      });
      return;
    }

    try {
      const direction = data.direction || 0;

      // Verificamos si realmente tiene este objeto en el inventario
      const invRes = await pool.query(
        `SELECT id FROM inventory WHERE user_id = $1 AND item_id = $2 LIMIT 1`,
        [userId, itemId],
      );

      if (invRes.rows.length === 0) {
        socket.emit("shop:error", {
          message: "No tienes este objeto en tu inventario.",
        });
        return;
      }

      const invId = invRes.rows[0].id;

      await pool.query("BEGIN");

      // Lo borramos de su inventario
      await pool.query(`DELETE FROM inventory WHERE id = $1`, [invId]);

      // Lo insertamos en la sala (room_furnis) con su posición y dirección
      const insertRes = await pool.query(
        `INSERT INTO room_furnis (room_id, item_id, x, y, direction) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [p.roomId, itemId, x, y, direction],
      );

      // Obtenemos los datos del ítem para enviarlos a la sala (nombre, color...)
      const itemRes = await pool.query(
        `SELECT name, color_hex, sprite_name, is_walkable FROM catalog_items WHERE id = $1`,
        [itemId],
      );

      await pool.query("COMMIT"); // Guardamos todo

      // Avisamos a los jugadores de la sala de que hay un nuevo mueble
      io.to(`room:${p.roomId}`).emit("room:furni_placed", {
        id: insertRes.rows[0].id,
        x: x,
        y: y,
        direction: direction,
        name: itemRes.rows[0].name,
        color_hex: itemRes.rows[0].color_hex,
        sprite_name: itemRes.rows[0].sprite_name,
        is_walkable: itemRes.rows[0].is_walkable,
      });
    } catch (err) {
      await pool.query("ROLLBACK");
      console.error("Error al colocar furni:", err);
    }
  });

  // --- SISTEMA DE CONSTRUCCIÓN: MOVER MUEBLE ---
  socket.on("furni:move", async (data) => {
    const p = players.get(socket.id);
    if (!p || !p.roomId) return;

    // Solo el dueño de la sala puede mover muebles en su sala
    const esDueno = await esDuenoDeLaSala(userId, p.roomId);
    if (!esDueno) {
      socket.emit("shop:error", {
        message: "No puedes modificar muebles en una sala que no es tuya.",
      });
      return;
    }

    try {
      const { furniId, newX, newY, direction } = data;

      // Actualizamos sus coordenadas y rotación en la base de datos
      await pool.query(
        `UPDATE room_furnis SET x = $1, y = $2, direction = $3 WHERE id = $4 AND room_id = $5`,
        [newX, newY, direction || 0, furniId, p.roomId],
      );

      // Extraemos sus datos para reenviarlos al frontend
      const itemRes = await pool.query(
        `SELECT c.name, c.color_hex, c.sprite_name, c.is_walkable FROM room_furnis rf JOIN catalog_items c ON rf.item_id = c.id WHERE rf.id = $1`,
        [furniId],
      );

      // Avisamos a toda la sala
      io.to(`room:${p.roomId}`).emit("room:furni_moved", {
        id: furniId,
        x: newX,
        y: newY,
        direction: direction || 0,
        name: itemRes.rows[0].name,
        color_hex: itemRes.rows[0].color_hex,
        sprite_name: itemRes.rows[0].sprite_name,
        is_walkable: itemRes.rows[0].is_walkable,
      });
    } catch (err) {
      console.error("Error al mover furni:", err);
    }
  });

  // --- SISTEMA DE CONSTRUCCIÓN: GIRAR MUEBLE YA COLOCADO ---
  socket.on("furni:rotate", async (data) => {
    const p = players.get(socket.id);
    if (!p || !p.roomId) return;

    // Solo el dueño de la sala puede girar muebles en su sala
    const esDueno = await esDuenoDeLaSala(userId, p.roomId);
    if (!esDueno) {
      socket.emit("shop:error", {
        message: "No puedes modificar muebles en una sala que no es tuya.",
      });
      return;
    }

    try {
      // Consultamos qué dirección tiene ahora mismo
      const res = await pool.query(
        `SELECT direction FROM room_furnis WHERE id = $1 AND room_id = $2`,
        [data.furniId, p.roomId],
      );

      if (res.rows.length === 0) return;

      // Calculamos la nueva dirección (de 0 a 1, o de 1 a 0)
      const currentDir = res.rows[0].direction || 0;
      const newDir = currentDir === 0 ? 1 : 0;

      // Actualizamos la base de datos
      await pool.query(`UPDATE room_furnis SET direction = $1 WHERE id = $2`, [
        newDir,
        data.furniId,
      ]);

      //  Avisamos a todos los de la sala de que este mueble ha girado
      io.to(`room:${p.roomId}`).emit("room:furni_rotated", {
        id: data.furniId,
        direction: newDir,
      });
    } catch (err) {
      console.error("Error al rotar furni:", err);
    }
  });

  // --- SISTEMA DE CONSTRUCCIÓN: RECOGER MUEBLE ---
  socket.on("furni:pickup", async (data) => {
    const userId = socket.data.userId;
    const { furniId, x, y } = data;

    const p = players.get(socket.id);
    if (!p || !p.roomId) return;

    // comprobamos que el jugador es el dueño de la sala (solo el dueño puede recoger muebles)
    const esDueno = await esDuenoDeLaSala(userId, p.roomId);
    if (!esDueno) {
      await pool.query("ROLLBACK");
      return;
    }

    try {
      await pool.query("BEGIN"); // Iniciamos transacción

      // Buscamos el mueble en la base de datos
      const furniRes = await pool.query(
        `SELECT item_id, room_id FROM room_furnis WHERE id = $1`,
        [furniId],
      );

      if (furniRes.rows.length === 0) {
        await pool.query("ROLLBACK");
        return;
      }

      const { item_id, room_id } = furniRes.rows[0];

      //   Lo borramos de la sala
      await pool.query(`DELETE FROM room_furnis WHERE id = $1`, [furniId]);

      //  Lo devolvemos al inventario del jugador
      await pool.query(
        `INSERT INTO inventory (user_id, item_id) VALUES ($1, $2)`,
        [userId, item_id],
      );

      await pool.query("COMMIT"); // Guardamos cambios

      //  Avisamos a los jugadores de la sala de que el mueble ha desaparecido
      io.to(`room:${room_id}`).emit("room:furni_removed", { furniId, x, y });
    } catch (err) {
      await pool.query("ROLLBACK");
      console.error("Error al recoger furni:", err);
    }
  });
});

// Iniciar servidor
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
// Función auxiliar para comprobar si el jugador es dueño de la sala
async function esDuenoDeLaSala(
  userId: number,
  roomId: number,
): Promise<boolean> {
  const res = await pool.query(
    "SELECT id FROM rooms WHERE id = $1 AND owner_id = $2",
    [roomId, userId],
  );
  return res.rows.length > 0;
}
