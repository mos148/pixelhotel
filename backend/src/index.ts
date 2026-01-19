import express from "express";
import "dotenv/config";
import { pool } from "./db";
import bcrypt from "bcryptjs";
import type { RegisterBody, UserPublic } from "./types/auth";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { requireAuth } from "./middleware/requireAuth";
import http from "http";
import { Server } from "socket.io";
import type { PlayerState } from "./types/player";
import cookie from "cookie";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const players = new Map<string, PlayerState>();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "../../client")));

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "../../client/index.html"));
});



// Auth (vacías por ahora)
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
      [email]
    );

    const user = result.rows[0];
    if (!user) {
      // No revelamos si existe o no el email
      return res.status(401).json({ ok: false, error: "Credenciales incorrectas" });
    }

    // 3) Comparar password con el hash
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ ok: false, error: "Credenciales incorrectas" });
    }

    // 4) Crear JWT
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return res.status(500).json({ ok: false, error: "JWT_SECRET no configurado" });
    }

    const token = jwt.sign(
      { userId: user.id },      // payload (lo mínimo)
      secret,
      { expiresIn: "7d" }       // duración del token
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
    if (typeof body.nickname !== "string" || typeof body.birth_date !== "string") {
      return res.status(400).json({ ok: false, error: "Tipos inválidos" });
    }
    if (body.password.length < 6) {
      return res.status(400).json({ ok: false, error: "Password demasiado corta (min 6)" });
    }

    // 2) Hashear contraseña
    const password_hash = await bcrypt.hash(body.password, 10);

    // 3) Insert seguro (parametrizado) en PostgreSQL
    const result = await pool.query<UserPublic>(
      `INSERT INTO users (email, password_hash, nickname, birth_date)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, nickname, birth_date, created_at`,
      [body.email, password_hash, body.nickname, body.birth_date]
    );

    return res.status(201).json({ ok: true, user: result.rows[0] });
  } catch (err: any) {
    // Email duplicado (constraint UNIQUE)
    if (err?.code === "23505") {
      return res.status(409).json({ ok: false, error: "Ese email ya está registrado" });
    }
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});


app.post("/logout", (_req, res) => {
  res.clearCookie("auth");
  return res.json({ ok: true });
});

app.get("/protected", requireAuth, (req, res) => {
  res.json({ ok: true, message: "Acceso permitido", userId: (req as any).userId });
});

app.get("/me", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).userId;

    const result = await pool.query<UserPublic>(
      `SELECT id, email, nickname, birth_date, created_at
       FROM users
       WHERE id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ ok: false, error: "Usuario no encontrado" });
    }

    return res.json({ ok: true, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Error interno" });
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

  function broadcastOnlineCount() {
  io.emit("online:update", { count: io.engine.clientsCount });
  }


io.on("connection", (socket) => {
  console.log("✅ user connected:", socket.id);
  broadcastOnlineCount();

  socket.on("chat:send", (payload) => {
    // payload: { text, nickname }
    io.emit("chat:msg", {
      text: payload?.text ?? "",
      nickname: payload?.nickname ?? "???",
      at: Date.now(),
    });
  });

  socket.on("disconnect", () => {
    const existed = players.get(socket.id);
    players.delete(socket.id);

    if (existed) {
    socket.broadcast.emit("player:left", { socketId: socket.id });
    }
     console.log("❌ user disconnected:", socket.id);
     broadcastOnlineCount();
  });


socket.on("player:hello", async () => {
  const auth = getUserFromSocket(socket);
  if (!auth) {
    socket.disconnect();
    return;
  }

 // Obtener nickname desde la BD

  const result = await pool.query(
    "SELECT nickname FROM users WHERE id = $1",
    [auth.userId]
  );

  const nickname = result.rows[0]?.nickname ?? "Player";

  const spawnX = 0;
  const spawnY = 0;

  const me: PlayerState = {
    socketId: socket.id,
    nickname,
    x: spawnX,
    y: spawnY,
  };

  players.set(socket.id, me);

  socket.emit("players:init", {
    me: { socketId: socket.id },
    players: Array.from(players.values()),
  });

  socket.broadcast.emit("player:joined", me);
});


socket.on("player:move", (payload) => {
  const p = players.get(socket.id);
  if (!p) return;

  const toX = Number(payload?.toX);
  const toY = Number(payload?.toY);

  if (!Number.isFinite(toX) || !Number.isFinite(toY)) return;



  // Guardamos el destino como "posición" (estado simple).
  // Más adelante guardaremos posición real o haremos server autoritativo.
  p.x = toX;
  p.y = toY;

  
  io.emit("player:moved", { socketId: socket.id, toX, toY });
});




});





server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
