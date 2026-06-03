import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import pkg from "pg"; 
const { Pool } = pkg; // Extraemos Pool de la librería

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const envPath = path.resolve(__dirname, "../../.env");

dotenv.config({ path: envPath });

export const pool = new Pool({
  host: process.env.DB_HOST || "db",
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  database: process.env.POSTGRES_DB,
  port: Number(process.env.POSTGRES_PORT || 5432),
});


