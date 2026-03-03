import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

interface JwtPayload {
  userId: string;
}

// Extendemos Request para añadir userId
export interface AuthRequest extends Request {
  userId?: string;
}

export function requireAuth(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const token = req.cookies?.auth;

  // 1) ¿Hay cookie?
  if (!token) {
    return res.status(401).json({ ok: false, error: "No autenticado" });
  }

  // 2) ¿Hay secreto?
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return res.status(500).json({ ok: false, error: "JWT_SECRET no configurado" });
  }

  try {
    // 3) Verificar token
    const payload = jwt.verify(token, secret) as JwtPayload;

    // 4) Guardar userId para la ruta
    req.userId = payload.userId;

    // 5) Todo OK -> seguir
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "Token inválido o expirado" });
  }
}
