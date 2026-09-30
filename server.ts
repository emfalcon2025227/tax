import path from "path";
import fs from "fs";
import dotenv from "dotenv";

if (process.env.NODE_ENV !== "production") {
  const envPath = path.resolve(process.cwd(), ".env");
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath, override: true });
  } else {
    dotenv.config({ override: true });
  }
}

import express, { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { createServer as createViteServer } from "vite";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === "production";

function requireEnv(name: string): string {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`[FATAL CONFIG] Missing required environment variable: ${name}`);
  return value;
}

const AUTH_SECRET_KEY = requireEnv("AUTH_SECRET_KEY");
if (AUTH_SECRET_KEY.length < 32) {
  throw new Error("[FATAL CONFIG] AUTH_SECRET_KEY must be at least 32 characters.");
}

const SUPABASE_URL = requireEnv("SUPABASE_URL").replace(/\/+$/, "");
const SUPABASE_KEY = requireEnv("SUPABASE_KEY");

try {
  const parsedUrl = new URL(SUPABASE_URL);
  if (isProd && parsedUrl.protocol !== "https:") {
    throw new Error("Production SUPABASE_URL must use HTTPS.");
  }
} catch (err: any) {
  throw new Error(`[FATAL CONFIG] Invalid SUPABASE_URL: ${err.message}`);
}

function getSupabaseConfig(): { url: string; key: string } {
  return { url: SUPABASE_URL, key: SUPABASE_KEY };
}

function getUAECurrentDate(): string {
  try {
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Dubai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit"
    }).format(new Date());
  } catch {
    return new Date().toISOString().slice(0, 10);
  }
}

// Trust proxy for Cloud Run and reverse proxy environments (e.g. X-Forwarded-For)
app.set("trust proxy", 1);

// Security Headers via Helmet & Content-Security-Policy (CQ-08)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        connectSrc: ["'self'", "https://*.supabase.co", "https://*.run.app", "http://localhost:*", "ws://localhost:*"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'self'", "https://*.google.com", "https://*.googleusercontent.com", "https://*.run.app"]
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

// Standard Permissions-Policy Header
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  next();
});

// Rate Limiters (CQ-05)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Failed login attempts per 15 minutes per IP
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { success: false, error: "Too many login attempts. Please try again after 15 minutes." }
});

const userMutationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { success: false, error: "Too many user management requests. Please try again later." }
});

const importLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { success: false, error: "Too many import requests. Please slow down." }
});

const supplierImportLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { success: false, error: "Too many supplier import requests. Please slow down." }
});

const analyticsLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { success: false, error: "Too many analytics requests. Please slow down." }
});

const resetDataLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { success: false, error: "Too many reset data requests. Operation rate-limited." }
});

const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 150, // 150 requests per 10 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { success: false, error: "Too many API requests. Please slow down." }
});

// Apply general API rate limiting to all /api/ endpoints
app.use("/api/", apiLimiter);

// Increase payload limit for batch CSV imports
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Structured Audit Logging
function auditLog(actor: string, action: string, target: string, result: "SUCCESS" | "FAILURE", details?: any) {
  const timestamp = new Date().toISOString();
  const safeDetails = details ? { ...details } : undefined;
  if (safeDetails && safeDetails.password) delete safeDetails.password;
  if (safeDetails && safeDetails.token) delete safeDetails.token;
  console.log(`[AUDIT] [${timestamp}] [Actor: ${actor}] [Action: ${action}] [Target: ${target}] [Result: ${result}]`, safeDetails ? JSON.stringify(safeDetails) : "");
}

// ============================================================================
// RBAC SECURITY & ASYNCHRONOUS CRYPTOGRAPHIC AUTHENTICATION (CQ-01, CQ-02, CQ-03)
// ============================================================================
async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 12);
}

function isBcryptHash(str: string): boolean {
  if (!str || typeof str !== "string") return false;
  return str.startsWith("$2a$") || str.startsWith("$2b$") || str.startsWith("$2y$");
}

/**
 * Validates a candidate password against stored credentials.
 * - Primary secure branch: Asynchronous bcrypt compare against verified bcrypt hashes.
 * - Ephemeral migration branch: Constant-time comparison strictly for in-flight legacy plaintext accounts.
 */
async function verifyStoredPassword(
  candidatePlaintext: string,
  storedCredential: string
): Promise<{ isValid: boolean; isLegacyPlaintext: boolean }> {
  if (!candidatePlaintext || !storedCredential) {
    return { isValid: false, isLegacyPlaintext: false };
  }

  // 1. Primary Secure Path: bcrypt hash
  if (isBcryptHash(storedCredential)) {
    try {
      const match = await bcrypt.compare(candidatePlaintext, storedCredential);
      return { isValid: match, isLegacyPlaintext: false };
    } catch {
      return { isValid: false, isLegacyPlaintext: false };
    }
  }

  // 2. Ephemeral Legacy Migration Path: Timing-safe comparison against known legacy plaintext record
  try {
    const candidateBuf = Buffer.from(candidatePlaintext, "utf-8");
    const storedBuf = Buffer.from(storedCredential, "utf-8");
    if (candidateBuf.length !== storedBuf.length) {
      return { isValid: false, isLegacyPlaintext: true };
    }
    const isMatch = crypto.timingSafeEqual(candidateBuf, storedBuf);
    return { isValid: isMatch, isLegacyPlaintext: true };
  } catch {
    return { isValid: false, isLegacyPlaintext: true };
  }
}

function generateAuthToken(username: string, role: string): string {
  const payload = {
    username,
    role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 7 * 86400,
    jti: crypto.randomBytes(16).toString("hex")
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", AUTH_SECRET_KEY).update(payloadB64).digest("hex");
  return `${payloadB64}.${sig}`;
}

function verifyAuthToken(token: string): { username: string; role: string; [key: string]: any } | null {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    const [payloadB64, sig] = parts;
    const expectedSig = crypto.createHmac("sha256", AUTH_SECRET_KEY).update(payloadB64).digest("hex");
    if (sig.length !== expectedSig.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf-8"));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

// Authentication Middlewares (Strict Validation - Authorization: Bearer <token> ONLY - CQ-02)
function getAuthUser(req: Request): { username: string; role: string; [key: string]: any } | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.slice(7).trim();
  if (!token) return null;
  return verifyAuthToken(token);
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const user = getAuthUser(req);
  if (!user) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized: Invalid, missing, or expired session token."
    });
  }
  (req as any).user = user;
  next();
}

function requireOwner(req: Request, res: Response, next: NextFunction) {
  const user = getAuthUser(req);
  if (!user) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized: Invalid, missing, or expired session token."
    });
  }
  const role = String(user.role || "").trim().toLowerCase();
  if (role !== "owner") {
    auditLog(user.username, "UNAUTHORIZED_ADMIN_ACCESS", req.path, "FAILURE", { role });
    return res.status(403).json({
      success: false,
      error: "Forbidden: This action is strictly restricted to Owner role."
    });
  }
  (req as any).user = user;
  next();
}

// Helper to read and write config.json
// ============================================================================
// API ROUTES (PROTECTED SERVER-SIDE PROXY FOR SUPABASE WITH RBAC)
// ============================================================================

// 0. Authentication & User Management Routes
// Production identity is authoritative in public.users. No hardcoded or file-backed production users.
app.post("/api/login", authLimiter, async (req: Request, res: Response) => {
  const { username } = req.body;
  const rawUser = String(username || "").trim();
  const u = rawUser.toLowerCase();
  // Passwords MUST NOT be trimmed; preserve exact character sequence entered by user
  const password = typeof req.body.password === "string" ? req.body.password : "";

  if (!rawUser || !password) {
    auditLog("anonymous", "LOGIN_ATTEMPT", rawUser || "EMPTY", "FAILURE", { reason: "Missing credentials" });
    return res.status(401).json({
      success: false,
      error: "Invalid credentials"
    });
  }

  const { url, key } = getSupabaseConfig();
  let authenticatedUser: { username: string; role: "Owner" | "Clerk" } | null = null;
  let authStage: "AUTH_USER_NOT_FOUND" | "AUTH_PASSWORD_MISMATCH" | "AUTH_INVALID_ROLE" | "AUTH_DATABASE_ERROR" | "AUTH_SUCCESS" = "AUTH_USER_NOT_FOUND";
  let userFoundInDb = false;
  let databaseError = false;

  // 1. Authenticate against Supabase Database Users Table (Case-Insensitive Search)
  try {
    const srvRes = await fetch(
      `${url}/rest/v1/users?or=(username.ilike.${encodeURIComponent(rawUser)},email.ilike.${encodeURIComponent(rawUser)})`,
      {
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`
        }
      }
    );
    if (srvRes.ok) {
      const dbUsers = await srvRes.json();
      if (Array.isArray(dbUsers) && dbUsers.length === 0) {
        authStage = "AUTH_USER_NOT_FOUND";
      } else if (Array.isArray(dbUsers) && dbUsers.length > 0) {
        for (const usr of dbUsers) {
          const matchedName = String(usr.username || usr.email || "").trim().toLowerCase() === u;
          if (matchedName) {
            userFoundInDb = true;
            const storedPass = String(usr.password || usr.password_hash || usr.passwd || "");
            const verification = await verifyStoredPassword(password, storedPass);
            if (verification.isValid) {
              const rawRole = String(usr.role || "").trim().toLowerCase();
              if (rawRole !== "owner" && rawRole !== "clerk") {
                authStage = "AUTH_INVALID_ROLE";
                auditLog("anonymous", "LOGIN_REJECTED_INVALID_ROLE", rawUser, "FAILURE", { role: usr.role });
                continue;
              }
              const role: "Owner" | "Clerk" = rawRole === "clerk" ? "Clerk" : "Owner";
              authenticatedUser = {
                username: usr.username || rawUser,
                role
              };
              authStage = "AUTH_SUCCESS";

              // Ephemeral Password Migration: Upgrade legacy plaintext password to bcrypt hash asynchronously
              if (verification.isLegacyPlaintext) {
                try {
                  const newHash = await hashPassword(password);
                  await fetch(`${url}/rest/v1/users?id=eq.${encodeURIComponent(usr.id)}`, {
                    method: "PATCH",
                    headers: {
                      apikey: key,
                      Authorization: `Bearer ${key}`,
                      "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ password: newHash })
                  });
                  auditLog(authenticatedUser.username, "PASSWORD_MIGRATED_TO_BCRYPT", `USER_ID_${usr.id}`, "SUCCESS");
                } catch (migErr) {
                  // Migration failure must not break valid login
                  console.warn("[AUTH] Notice: Automatic password hash upgrade deferred:", migErr);
                }
              }
              break;
            } else {
              authStage = "AUTH_PASSWORD_MISMATCH";
            }
          }
        }
      }
    } else {
      console.warn(`[AUTH] Supabase user lookup returned status ${srvRes.status}`);
      if (srvRes.status === 404) {
        authStage = "AUTH_USER_NOT_FOUND";
      } else {
        databaseError = true;
        authStage = "AUTH_DATABASE_ERROR";
      }
    }
  } catch (err) {
    console.warn("[AUTH] Supabase user query notice:", err);
    databaseError = true;
    authStage = "AUTH_DATABASE_ERROR";
  }

  // Safe internal diagnostics logging (No passwords, hashes, JWTs, or secret keys exposed)
  console.log(`[AUTH-DIAG] userFound=${userFoundInDb} userIdPresent=${!!authenticatedUser} passwordFieldPresent=true passwordHashFormat=bcrypt role=${authenticatedUser?.role || "none"} stage=${authStage}`);

  // 3. Fail-safe production database outage check
  if (databaseError && isProd) {
    auditLog("anonymous", "LOGIN_ATTEMPT_DB_FAILURE", rawUser, "FAILURE", { reason: "Database unavailable" });
    return res.status(503).json({
      success: false,
      error: "Service temporarily unavailable. Please try again later."
    });
  }

  // 4. Reject if unverified
  if (!authenticatedUser) {
    auditLog("anonymous", "LOGIN_ATTEMPT", rawUser, "FAILURE", { reason: "Invalid credentials", stage: authStage });
    return res.status(401).json({
      success: false,
      error: "Invalid credentials"
    });
  }

  const token = generateAuthToken(authenticatedUser.username, authenticatedUser.role);
  auditLog(authenticatedUser.username, "LOGIN_SUCCESS", "SYSTEM", "SUCCESS", { role: authenticatedUser.role });
  return res.json({
    success: true,
    token,
    role: authenticatedUser.role,
    username: authenticatedUser.username
  });
});

app.get("/api/auth/me", requireAuth, (req: Request, res: Response) => {
  res.json({ success: true, user: (req as any).user });
});

// User Management API Endpoints (Owner Only) - Rate Limited with userMutationLimiter
app.get("/api/users", requireOwner, async (_req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const response = await fetch(`${url}/rest/v1/users?select=id,username,email,role,created_at&order=username.asc`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` }
    });
    if (!response.ok) {
      return res.status(response.status).json({ success: false, error: "Unable to load users from the database." });
    }
    const users = await response.json();
    return res.json({ success: true, users: Array.isArray(users) ? users : [] });
  } catch {
    return res.status(503).json({ success: false, error: "User directory is temporarily unavailable." });
  }
});

app.post("/api/users", userMutationLimiter, requireOwner, async (req: Request, res: Response) => {
  const username = String(req.body?.username || "").trim();
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const roleInput = String(req.body?.role || "").trim().toLowerCase();

  if (!/^[a-zA-Z0-9_.-]{3,50}$/.test(username)) {
    return res.status(400).json({ success: false, error: "Username must be 3-50 characters using letters, numbers, _, . or -." });
  }
  if (password.length < 6) {
    return res.status(400).json({ success: false, error: "Password must be at least 6 characters long." });
  }
  if (roleInput !== "owner" && roleInput !== "clerk") {
    return res.status(400).json({ success: false, error: "Role must be Owner or Clerk." });
  }

  const { url, key } = getSupabaseConfig();
  const hashedPassword = await hashPassword(password);

  try {
    const response = await fetch(`${url}/rest/v1/users`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify({
        username,
        password: hashedPassword,
        role: roleInput === "owner" ? "Owner" : "Clerk",
        created_at: new Date().toISOString()
      })
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Failed to create user." });
    }
    await response.text().catch(() => "");
    auditLog((req as any).user.username, "CREATE_USER", username, "SUCCESS", { role: roleInput });
    return res.status(201).json({
      success: true,
      message: `User '${username}' registered successfully.`,
      user: { username, role: roleInput === "owner" ? "Owner" : "Clerk" }
    });
  } catch {
    return res.status(503).json({ success: false, error: "User service is temporarily unavailable." });
  }
});

app.put("/api/users/:identifier", userMutationLimiter, requireOwner, async (req: Request, res: Response) => {
  const identifier = String(req.params.identifier || "").trim();
  if (!identifier) return res.status(400).json({ success: false, error: "User identifier is required." });

  const password = req.body?.password !== undefined
    ? (typeof req.body.password === "string" ? req.body.password : "")
    : undefined;
  const username = req.body?.username !== undefined ? String(req.body.username).trim() : undefined;
  const role = req.body?.role !== undefined ? String(req.body.role).trim().toLowerCase() : undefined;

  if (password !== undefined && password.length < 6) {
    return res.status(400).json({ success: false, error: "Password must be at least 6 characters long." });
  }
  if (username !== undefined && !/^[a-zA-Z0-9_.-]{3,50}$/.test(username)) {
    return res.status(400).json({ success: false, error: "Username must be 3-50 characters using letters, numbers, _, . or -." });
  }
  if (role !== undefined && role !== "owner" && role !== "clerk") {
    return res.status(400).json({ success: false, error: "Role must be Owner or Clerk." });
  }

  const updatePayload: Record<string, string> = {};
  if (password !== undefined) updatePayload.password = await hashPassword(password);
  if (username !== undefined) updatePayload.username = username;
  if (role !== undefined) updatePayload.role = role === "owner" ? "Owner" : "Clerk";
  if (Object.keys(updatePayload).length === 0) {
    return res.status(400).json({ success: false, error: "No supported fields provided for update." });
  }

  const { url, key } = getSupabaseConfig();
  const filter = /^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\}?$/.test(identifier)
    ? `id=eq.${encodeURIComponent(identifier.replace(/[{}]/g, ""))}`
    : `username=eq.${encodeURIComponent(identifier)}`;

  try {
    const response = await fetch(`${url}/rest/v1/users?${filter}`, {
      method: "PATCH",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(updatePayload)
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Failed to update user." });
    }
    const data = await response.json().catch(() => []);
    if (!Array.isArray(data) || data.length === 0) {
      return res.status(404).json({ success: false, error: "User not found." });
    }
    auditLog((req as any).user.username, "UPDATE_USER", identifier, "SUCCESS");
    const updatedUser = data[0] || {};
    return res.json({
      success: true,
      message: "User updated successfully.",
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        role: updatedUser.role,
        created_at: updatedUser.created_at
      }
    });
  } catch {
    return res.status(503).json({ success: false, error: "User service is temporarily unavailable." });
  }
});

app.delete("/api/users/:identifier", requireOwner, async (req: Request, res: Response) => {
  const identifier = String(req.params.identifier || "").trim();
  const actor = String((req as any).user?.username || "").trim().toLowerCase();

  if (!identifier) return res.status(400).json({ success: false, error: "User identifier is required." });
  if (identifier.toLowerCase() === actor) {
    return res.status(400).json({ success: false, error: "Self-lockout prevented: You cannot delete your own account." });
  }

  const { url, key } = getSupabaseConfig();
  const filter = /^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\}?$/.test(identifier)
    ? `id=eq.${encodeURIComponent(identifier.replace(/[{}]/g, ""))}`
    : `username=eq.${encodeURIComponent(identifier)}`;

  try {
    const response = await fetch(`${url}/rest/v1/users?${filter}`, {
      method: "DELETE",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        Prefer: "return=representation"
      }
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Failed to delete user." });
    }
    const data = await response.json().catch(() => []);
    if (!Array.isArray(data) || data.length === 0) {
      return res.status(404).json({ success: false, error: "User not found." });
    }
    auditLog(actor, "DELETE_USER", identifier, "SUCCESS");
    return res.json({ success: true, message: `User '${identifier}' deleted successfully.` });
  } catch {
    return res.status(503).json({ success: false, error: "User service is temporarily unavailable." });
  }
});

// 0.1 Settings
app.get("/api/settings", requireOwner, async (_req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const response = await fetch(`${url}/rest/v1/settings?id=eq.application_config&select=value&limit=1`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` }
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(502).json({ success: false, error: errText || "Unable to load application settings." });
    }
    const rows = await response.json().catch(() => []);
    const value = Array.isArray(rows) && rows.length > 0 && rows[0].value && typeof rows[0].value === "object"
      ? rows[0].value
      : {};
    return res.json({
      success: true,
      database: { configured: true, host: new URL(SUPABASE_URL).hostname },
      default_vat_rate: Number(value.default_vat_rate ?? 5.0)
    });
  } catch {
    return res.status(503).json({ success: false, error: "Application settings are temporarily unavailable." });
  }
});

app.post("/api/settings", requireOwner, async (req: Request, res: Response) => {
  const vatRate = Number(req.body?.default_vat_rate);
  if (!Number.isFinite(vatRate) || vatRate < 0 || vatRate > 100) {
    return res.status(400).json({ success: false, error: "default_vat_rate must be a number between 0 and 100." });
  }

  const { url, key } = getSupabaseConfig();
  const value = { default_vat_rate: Math.round(vatRate * 100) / 100 };

  try {
    const response = await fetch(`${url}/rest/v1/settings`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates,return=representation"
      },
      body: JSON.stringify({
        id: "application_config",
        value,
        updated_at: new Date().toISOString()
      })
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Application settings save was rejected by the database." });
    }
    return res.json({ success: true, message: "Application settings saved successfully.", default_vat_rate: value.default_vat_rate });
  } catch {
    return res.status(503).json({ success: false, error: "Application settings are temporarily unavailable." });
  }
});

app.get("/api/settings/recipients", requireAuth, async (_req: Request, res: Response) => {
  try {
    const { url, key } = getSupabaseConfig();
    const response = await fetch(`${url}/rest/v1/settings?id=eq.report_recipients&select=value&limit=1`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` }
    });
    if (!response.ok) {
      return res.status(response.status).json({ success: false, error: "Unable to load report recipients." });
    }
    const rows = await response.json().catch(() => []);
    const raw = Array.isArray(rows) && rows.length > 0 ? rows[0].value : [];
    let recipients: string[] = [];
    if (Array.isArray(raw)) recipients = raw.map((x: unknown) => String(x).trim().toLowerCase()).filter(Boolean);
    return res.json({ success: true, recipients: Array.from(new Set(recipients)) });
  } catch {
    return res.status(503).json({ success: false, error: "Report recipient settings are temporarily unavailable." });
  }
});

app.post("/api/settings/recipients", requireOwner, async (req: Request, res: Response) => {
  const rawList = req.body?.recipients;
  let list: string[] = [];

  if (Array.isArray(rawList)) {
    list = rawList.map((x: unknown) => String(x).trim().toLowerCase()).filter(Boolean);
  } else if (typeof rawList === "string") {
    list = rawList.split(/[\n,;]+/).map((s: string) => s.trim().toLowerCase()).filter(Boolean);
  }

  list = Array.from(new Set(list));
  const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  list = list.filter(email => validEmail.test(email));

  if (list.length > 50) {
    return res.status(400).json({ success: false, error: "A maximum of 50 report recipients is allowed." });
  }

  const { url, key } = getSupabaseConfig();

  try {
    const response = await fetch(`${url}/rest/v1/settings`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates,return=representation"
      },
      body: JSON.stringify({
        id: "report_recipients",
        value: list,
        updated_at: new Date().toISOString()
      })
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Report recipient settings were rejected by the database." });
    }

    return res.json({ success: true, recipients: list });
  } catch {
    return res.status(503).json({ success: false, error: "Report recipient settings are temporarily unavailable." });
  }
});

// 0.3 Daily Financial Report Cron Endpoint
app.all(["/api/cron/daily-report", "/api/daily-report"], requireOwner, async (_req: Request, res: Response) => {
  return res.status(503).json({
    success: false,
    error: "Daily report execution is not included in the Cloud Run build. No simulated or legacy desktop fallback is used."
  });
});

app.post("/api/test-connection", requireOwner, async (_req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const check = await fetch(`${url}/rest/v1/suppliers?select=id&limit=1`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` }
    });
    if (!check.ok) {
      return res.status(502).json({
        status: "error",
        message: `Supabase returned HTTP ${check.status}.`
      });
    }
    return res.json({
      status: "success",
      message: "Database connection verified successfully."
    });
  } catch {
    return res.status(503).json({
      status: "error",
      message: "Database connection is unavailable."
    });
  }
});

// 1. Health & Connection Status
let supabaseConnected = false;
let lastSupabaseCheckAt = 0;

async function verifySupabaseConnection(): Promise<boolean> {
  const { url, key } = getSupabaseConfig();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(`${url}/rest/v1/suppliers?select=id&limit=1`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` },
      signal: controller.signal
    });
    supabaseConnected = response.ok;
    lastSupabaseCheckAt = Date.now();
    return supabaseConnected;
  } catch {
    supabaseConnected = false;
    lastSupabaseCheckAt = Date.now();
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

app.get("/_health", (_req: Request, res: Response) => {
  return res.status(supabaseConnected ? 200 : 503).json({
    status: supabaseConnected ? "healthy" : "degraded",
    supabase_connected: supabaseConnected
  });
});

app.get("/api/health", (_req: Request, res: Response) => {
  return res.status(200).json({
    status: "ok",
    supabase_connected: supabaseConnected,
    timestamp: new Date().toISOString()
  });
});

app.get("/api/status", async (_req: Request, res: Response) => {
  const connected = await verifySupabaseConnection();
  return res.status(connected ? 200 : 503).json({
    status: connected ? "ok" : "degraded",
    supabase_connected: connected,
    checked_at: new Date().toISOString()
  });
});

// 2. Suppliers Endpoints (Both Owner & Clerk can read and create)
app.get("/api/suppliers", requireAuth, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();

  try {
    const response = await fetch(`${url}/rest/v1/suppliers?select=id,name,trn&order=name.asc`, {
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`
      }
    });
    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: errText });
    }
    const data = await response.json();
    return res.json(Array.isArray(data) ? data : []);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/suppliers", requireAuth, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const rawBody = req.body;
  const items = Array.isArray(rawBody) ? rawBody : [rawBody];

  if (items.length === 0 || items.length > 100) {
    return res.status(400).json({ success: false, error: "Request must contain between 1 and 100 suppliers." });
  }

  const cleanedSuppliers = items.map((item: any) => ({
    name: String(item?.name || "").trim(),
    trn: String(item?.trn || "").trim()
  }));

  for (let i = 0; i < cleanedSuppliers.length; i++) {
    const supplier = cleanedSuppliers[i];
    if (!supplier.name) {
      return res.status(400).json({ success: false, error: `Supplier name is required for row ${i + 1}.` });
    }
    if (!/^\d{15}$/.test(supplier.trn)) {
      return res.status(400).json({ success: false, error: `Supplier TRN must contain exactly 15 numeric digits for row ${i + 1}.` });
    }
  }

  try {
    const response = await fetch(`${url}/rest/v1/suppliers`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(cleanedSuppliers)
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Supplier registration rejected by database." });
    }

    const data = await response.json().catch(() => []);
    return res.status(201).json({ success: true, data });
  } catch {
    return res.status(503).json({ success: false, error: "Supplier service is temporarily unavailable." });
  }
});

// Update Supplier (PUT /api/suppliers/:identifier or PUT /api/suppliers)
app.put(["/api/suppliers/:identifier", "/api/suppliers"], requireAuth, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const identifier = String(req.params.identifier || req.body?.identifier || req.body?.old_trn || req.body?.id || "").trim();
  const name = String(req.body?.name || "").trim();
  const trn = String(req.body?.trn || "").trim();

  if (!identifier) return res.status(400).json({ success: false, error: "Supplier identifier is required." });
  if (!name) return res.status(400).json({ success: false, error: "Supplier name is required." });
  if (!/^\d{15}$/.test(trn)) {
    return res.status(400).json({ success: false, error: "Supplier TRN must contain exactly 15 numeric digits." });
  }

  const filter = /^\d+$/.test(identifier)
    ? `id=eq.${encodeURIComponent(identifier)}`
    : `trn=eq.${encodeURIComponent(identifier)}`;

  try {
    const response = await fetch(`${url}/rest/v1/suppliers?${filter}`, {
      method: "PATCH",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify({ name, trn })
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Supplier update rejected by database." });
    }
    const rows = await response.json().catch(() => []);
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(404).json({ success: false, error: "Supplier not found." });
    }
    return res.json({ success: true, message: `Supplier '${name}' updated successfully.`, supplier: rows[0] });
  } catch {
    return res.status(503).json({ success: false, error: "Supplier service is temporarily unavailable." });
  }
});

// Delete Supplier (DELETE /api/suppliers/:identifier or DELETE /api/suppliers)
app.delete(["/api/suppliers/:identifier", "/api/suppliers"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const identifier = String(req.params.identifier || req.query.identifier || req.query.trn || req.body?.identifier || req.body?.trn || req.body?.id || "").trim();

  if (!identifier) {
    return res.status(400).json({ success: false, error: "Missing supplier identifier (TRN or ID)." });
  }

  const headers = {
    apikey: key,
    Authorization: `Bearer ${key}`
  };

  try {
    const lookupFilter = /^\d{15}$/.test(identifier)
      ? `trn=eq.${encodeURIComponent(identifier)}`
      : /^\d+$/.test(identifier)
        ? `id=eq.${encodeURIComponent(identifier)}`
        : `name=eq.${encodeURIComponent(identifier)}`;

    const supplierResp = await fetch(`${url}/rest/v1/suppliers?select=id,name,trn&${lookupFilter}`, { headers });
    if (!supplierResp.ok) {
      return res.status(supplierResp.status).json({ success: false, error: "Unable to locate supplier." });
    }
    const suppliers = await supplierResp.json().catch(() => []);
    if (!Array.isArray(suppliers) || suppliers.length === 0) {
      return res.status(404).json({ success: false, error: "Supplier not found." });
    }
    if (suppliers.length > 1) {
      return res.status(409).json({ success: false, error: "Supplier identifier is not unique." });
    }

    const supplier = suppliers[0];
    const supplierId = String(supplier.id);

    // Prevent deletion when any existing transaction references the exact supplier TRN or party name.
    const txOr = [];
    if (supplier.trn) txOr.push(`trn.eq.${encodeURIComponent(String(supplier.trn))}`);
    if (supplier.name) txOr.push(`party_name.eq.${encodeURIComponent(String(supplier.name))}`);

    if (txOr.length > 0) {
      const chkResp = await fetch(`${url}/rest/v1/transactions?select=id&or=(${txOr.join(",")})&limit=1`, { headers });
      if (!chkResp.ok) {
        return res.status(502).json({ success: false, error: "Unable to verify supplier transaction references." });
      }
      const chkData = await chkResp.json().catch(() => []);
      if (Array.isArray(chkData) && chkData.length > 0) {
        return res.status(409).json({
          success: false,
          error: "Cannot delete supplier because existing invoices reference this supplier."
        });
      }
    }

    const response = await fetch(`${url}/rest/v1/suppliers?id=eq.${encodeURIComponent(supplierId)}`, {
      method: "DELETE",
      headers: { ...headers, Prefer: "return=representation" }
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Supplier deletion rejected by database." });
    }

    const deleted = await response.json().catch(() => []);
    if (!Array.isArray(deleted) || deleted.length !== 1) {
      return res.status(404).json({ success: false, error: "Supplier was not deleted." });
    }

    return res.json({ success: true, message: `Supplier '${supplier.name}' deleted successfully.`, deleted: deleted[0] });
  } catch {
    return res.status(503).json({ success: false, error: "Supplier service is temporarily unavailable." });
  }
});


// Helper to fetch all transactions from Supabase bypassing the PostgREST 1,000 max-rows limit via Range pagination
async function fetchAllSupabaseTransactions(
  url: string,
  key: string,
  order = "transaction_date.desc",
  select = "*"
): Promise<any[]> {
  const allRows: any[] = [];
  const batchSize = 1000;

  for (let offset = 0; ; offset += batchSize) {
    const end = offset + batchSize - 1;
    const response = await fetch(`${url}/rest/v1/transactions?select=${encodeURIComponent(select)}&order=${encodeURIComponent(order)}`, {
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        Range: `${offset}-${end}`,
        "Range-Unit": "items"
      }
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      throw new Error(`Supabase transactions query failed (HTTP ${response.status})${errText ? `: ${errText}` : ""}`);
    }

    const batch = await response.json();
    if (!Array.isArray(batch)) {
      throw new Error("Supabase transactions query returned an invalid response.");
    }

    allRows.push(...batch);

    if (batch.length < batchSize) {
      return allRows;
    }
  }
}

// Top-level Helpers to compute strict 100% all-column fingerprint for exact duplicate identification
function normalizeTransactionType(t: any): "sales" | "purchases" {
  const str = String(t || "").toLowerCase().trim();
  if (str === "sales" || str === "sale" || str === "revenue" || str === "income" || str.includes("مبيع") || str.includes("ايراد")) {
    return "sales";
  }
  return "purchases";
}

function normalizeTransactionTrn(raw: any): string {
  if (!raw) return "000000000000000";
  const digits = String(raw).replace(/\D/g, "");
  if (!digits || digits === "0") return "000000000000000";
  if (digits.length < 15) return digits.padStart(15, "0");
  return digits.slice(0, 15);
}

function normalizeVatRate(raw: any): number {
  let val = parseFloat(raw);
  if (isNaN(val) || val <= 0) return 5;
  if (val > 1.0) {
    if (val >= 1.01 && val <= 1.50) {
      val = val - 1.0; // e.g. 1.05 or 1.0501 -> 0.05
    } else if (val >= 2.0 && val <= 100.0) {
      val = val / 100.0; // e.g. 5.0 -> 0.05
    }
  }
  return Math.round(val * 100); // normalized to percentage integer (5 for 5%)
}

function getTransactionStrictFingerprint(tx: any): string {
  const type = normalizeTransactionType(tx.transaction_type);
  const date = String(tx.transaction_date || "").split("T")[0].trim();
  const inv = String(tx.invoice_no || "").replace(/^[#\s]+/, "").trim().toLowerCase();
  const party = String(tx.party_name || "").replace(/\s+/g, " ").trim().toLowerCase();
  const trn = normalizeTransactionTrn(tx.trn);
  const amtBefore = Math.round(Number(tx.amount_before_tax || 0) * 100);
  const vatRate = normalizeVatRate(tx.vat_rate);
  const vatAmt = Math.round(Number(tx.vat_amount || 0) * 100);
  const amtWithTax = Math.round(Number(tx.amount_with_tax || 0) * 100);
  
  // All 9 columns must match identically for a record to be considered a duplicate
  return `${type}:::${date}:::${inv}:::${party}:::${trn}:::${amtBefore}:::${vatRate}:::${vatAmt}:::${amtWithTax}`;
}

// 3. Transactions Endpoints
function roundMoney(value: number): number {
  return Math.round(value * 100) / 100;
}

function normalizeTaxMode(raw: unknown): "inclusive" | "exclusive" | "exempt" {
  const mode = String(raw ?? "").trim().toLowerCase();
  if (mode === "inclusive" || mode === "exclusive" || mode === "exempt") return mode;
  throw new Error("tax_mode must be inclusive, exclusive, or exempt.");
}

function parsePositiveAmount(raw: unknown): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("Amount must be a valid number greater than 0.00.");
  }
  return value;
}

/**
 * Server-authoritative VAT calculation.
 * For new entries amount_input is the only trusted monetary input.
 * For edits, amount_input may be omitted and is derived from the selected tax mode.
 */
function calculateAuthoritativeTax(input: Record<string, any>, allowDerivedInput = false) {
  const taxMode = normalizeTaxMode(input.tax_mode);

  let inputAmount: number;
  if (input.amount_input !== undefined && input.amount_input !== null && input.amount_input !== "") {
    inputAmount = parsePositiveAmount(input.amount_input);
  } else if (allowDerivedInput) {
    if (taxMode === "inclusive") {
      inputAmount = parsePositiveAmount(input.amount_with_tax);
    } else {
      inputAmount = parsePositiveAmount(input.amount_before_tax);
    }
  } else {
    throw new Error("amount_input is required.");
  }

  if (taxMode === "inclusive") {
    const amountBeforeTax = roundMoney(inputAmount / 1.05);
    const vatAmount = roundMoney(inputAmount - amountBeforeTax);
    return {
      amount_input: inputAmount,
      amount_before_tax: amountBeforeTax,
      vat_rate: 0.05,
      vat_amount: vatAmount,
      amount_with_tax: inputAmount,
      tax_mode: "inclusive" as const
    };
  }

  if (taxMode === "exclusive") {
    const amountBeforeTax = inputAmount;
    const vatAmount = roundMoney(amountBeforeTax * 0.05);
    const amountWithTax = roundMoney(amountBeforeTax + vatAmount);
    return {
      amount_input: inputAmount,
      amount_before_tax: amountBeforeTax,
      vat_rate: 0.05,
      vat_amount: vatAmount,
      amount_with_tax: amountWithTax,
      tax_mode: "exclusive" as const
    };
  }

  return {
    amount_input: inputAmount,
    amount_before_tax: inputAmount,
    vat_rate: 0.0,
    vat_amount: 0.0,
    amount_with_tax: inputAmount,
    tax_mode: "exempt" as const
  };
}

async function transactionExists(url: string, key: string, tx: {
  transaction_type: string;
  transaction_date: string;
  invoice_no: string;
  trn: string;
}): Promise<boolean> {
  const params = new URLSearchParams({
    select: "id",
    transaction_type: `eq.${tx.transaction_type}`,
    transaction_date: `eq.${tx.transaction_date}`,
    invoice_no: `eq.${tx.invoice_no}`,
    trn: `eq.${tx.trn}`,
    limit: "1"
  });
  const response = await fetch(`${url}/rest/v1/transactions?${params.toString()}`, {
    headers: { apikey: key, Authorization: `Bearer ${key}` }
  });
  if (!response.ok) {
    const errText = await response.text().catch(() => "");
    throw new Error(`Duplicate check failed (HTTP ${response.status})${errText ? `: ${errText}` : ""}`);
  }
  const data = await response.json();
  return Array.isArray(data) && data.length > 0;
}


// Read Transactions: Owner Only (Clerks use blind data entry) - Fully paginated with database filtering & sorting (CQ-04)
app.get("/api/transactions", requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const rawPage = parseInt(req.query.page as string, 10);
    const rawPageSize = parseInt((req.query.pageSize || req.query.limit) as string, 10);
    const hasPaginationParams = !isNaN(rawPage) || !isNaN(rawPageSize) || req.query.paginated === "true";

    const page = Math.max(1, isNaN(rawPage) ? 1 : rawPage);
    const MAX_PAGE_SIZE = 500;
    const DEFAULT_PAGE_SIZE = 50;
    const pageSize = Math.min(MAX_PAGE_SIZE, Math.max(1, isNaN(rawPageSize) ? DEFAULT_PAGE_SIZE : rawPageSize));

    const offset = (page - 1) * pageSize;
    const end = offset + pageSize - 1;

    const order = (req.query.order as string) || "transaction_date.desc";
    const type = (req.query.type || req.query.transaction_type) as string;
    const search = ((req.query.search || "") as string).trim();
    const from = (req.query.from || req.query.date_from) as string;
    const to = (req.query.to || req.query.date_to) as string;

    let queryUrl = `${url}/rest/v1/transactions?select=*&order=${encodeURIComponent(order)}`;
    if (type === "sales" || type === "purchases") {
      queryUrl += `&transaction_type=eq.${encodeURIComponent(type)}`;
    }
    if (from && /^\d{4}-\d{2}-\d{2}$/.test(from)) {
      queryUrl += `&transaction_date=gte.${encodeURIComponent(from)}`;
    }
    if (to && /^\d{4}-\d{2}-\d{2}$/.test(to)) {
      queryUrl += `&transaction_date=lte.${encodeURIComponent(to)}`;
    }
    if (search) {
      queryUrl += `&or=(party_name.ilike.*${encodeURIComponent(search)}*,invoice_no.ilike.*${encodeURIComponent(search)}*,trn.ilike.*${encodeURIComponent(search)}*)`;
    }

    if (hasPaginationParams) {
      const response = await fetch(queryUrl, {
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
          Range: `${offset}-${end}`,
          "Range-Unit": "items",
          Prefer: "count=exact"
        }
      });

      if (!response.ok) {
        const errText = await response.text();
        return res.status(response.status).json({ error: errText });
      }

      const contentRange = response.headers.get("content-range") || "";
      let totalRecords = 0;
      if (contentRange.includes("/")) {
        const totalStr = contentRange.split("/")[1];
        totalRecords = parseInt(totalStr, 10) || 0;
      }

      const rawData = await response.json();
      const data = (Array.isArray(rawData) ? rawData : []).filter((t: any) => !isSummaryOrInvalidRow(t)).map(normalizeTransaction);
      const totalPages = Math.ceil(totalRecords / pageSize);

      return res.json({
        success: true,
        data,
        pagination: {
          page,
          pageSize,
          totalRecords,
          totalPages,
          hasMore: page < totalPages
        }
      });
    }

    // Default legacy unbounded fetch with a safe maximum cap of 2,000 records
    const rawData = await fetchAllSupabaseTransactions(url, key, order, "*");
    const data = (rawData || []).filter((t: any) => !isSummaryOrInvalidRow(t)).map(normalizeTransaction);
    res.json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Insert Transactions: Both Owner and Clerk can insert transactions with duplicate protection
app.post("/api/transactions", requireAuth, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const rawBody = req.body;
  const items = Array.isArray(rawBody) ? rawBody : [rawBody];

  if (items.length === 0 || items.length > 50) {
    return res.status(400).json({ success: false, error: "Request must contain between 1 and 50 transactions." });
  }

  try {
    const prepared: any[] = [];

    for (const item of items) {
      const transactionType = String(item?.transaction_type || "").trim().toLowerCase();
      if (transactionType !== "sales" && transactionType !== "purchases") {
        return res.status(400).json({ success: false, error: "transaction_type must be sales or purchases." });
      }

      const transactionDate = String(item?.transaction_date || "").split("T")[0];
      if (!/^\d{4}-\d{2}-\d{2}$/.test(transactionDate)) {
        return res.status(400).json({ success: false, error: "transaction_date must be YYYY-MM-DD." });
      }

      const invoiceNo = item?.invoice_no == null ? "" : String(item.invoice_no).trim();
      let partyName = String(item?.party_name || "").trim();
      let trn = String(item?.trn || "").trim().replace(/\D/g, "");

      if (transactionType === "sales") {
        partyName = "Cash Customer";
        trn = "000000000000000";
      } else {
        if (!partyName) {
          return res.status(400).json({ success: false, error: "Supplier / party name is required for purchases." });
        }
        if (!/^\d{15}$/.test(trn)) {
          return res.status(400).json({ success: false, error: "TRN must contain exactly 15 numeric digits for purchases." });
        }
      }

      const tax = calculateAuthoritativeTax(item, false);

      const row = {
        transaction_type: transactionType,
        transaction_date: transactionDate,
        invoice_no: invoiceNo,
        party_name: partyName,
        trn,
        amount_before_tax: tax.amount_before_tax,
        vat_rate: tax.vat_rate,
        vat_amount: tax.vat_amount,
        amount_with_tax: tax.amount_with_tax,
        tax_mode: tax.tax_mode
      };

      if (await transactionExists(url, key, {
        transaction_type: row.transaction_type,
        transaction_date: row.transaction_date,
        invoice_no: row.invoice_no,
        trn: row.trn
      })) {
        return res.status(409).json({
          success: false,
          error: "Duplicate transaction detected for the same transaction type, invoice number, TRN, and transaction date."
        });
      }

      prepared.push(row);
    }

    const response = await fetch(`${url}/rest/v1/transactions`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(prepared)
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Transaction insert rejected by database." });
    }

    const data = await response.json();
    return res.status(201).json(data);
  } catch (err: any) {
    console.error("[SERVER] Transaction insert exception:", err);
    const message = err?.message || "Transaction insert failed.";
    return res.status(message.includes("Duplicate check failed") ? 503 : 400).json({
      success: false,
      error: message
    });
  }
});

// 3.1 Update Transaction// 3.1 Update Transaction (PUT /api/transactions/:id or /api/transactions - Owner Only)
app.put(["/api/transactions/:id", "/api/transactions"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const txId = String(req.params.id || req.body?.id || "").trim();

  if (!txId || !/^\d+$/.test(txId)) {
    return res.status(400).json({ success: false, error: "A valid numeric transaction ID is required for update." });
  }

  try {
    const transactionType = String(req.body?.transaction_type || "").trim().toLowerCase();
    if (transactionType !== "sales" && transactionType !== "purchases") {
      return res.status(400).json({ success: false, error: "transaction_type must be sales or purchases." });
    }

    const transactionDate = String(req.body?.transaction_date || "").split("T")[0];
    if (!/^\d{4}-\d{2}-\d{2}$/.test(transactionDate)) {
      return res.status(400).json({ success: false, error: "transaction_date must be YYYY-MM-DD." });
    }

    const invoiceNo = req.body?.invoice_no == null ? "" : String(req.body.invoice_no).trim();
    let partyName = String(req.body?.party_name || "").trim();
    let trn = String(req.body?.trn || "").trim().replace(/\D/g, "");

    if (transactionType === "sales") {
      partyName = "Cash Customer";
      trn = "000000000000000";
    } else {
      if (!partyName) return res.status(400).json({ success: false, error: "Supplier / party name is required for purchases." });
      if (!/^\d{15}$/.test(trn)) return res.status(400).json({ success: false, error: "TRN must contain exactly 15 numeric digits for purchases." });
    }

    const tax = calculateAuthoritativeTax(req.body || {}, true);
    const payload = {
      transaction_type: transactionType,
      transaction_date: transactionDate,
      invoice_no: invoiceNo,
      party_name: partyName,
      trn,
      amount_before_tax: tax.amount_before_tax,
      vat_rate: tax.vat_rate,
      vat_amount: tax.vat_amount,
      amount_with_tax: tax.amount_with_tax,
      tax_mode: tax.tax_mode
    };

    const response = await fetch(`${url}/rest/v1/transactions?id=eq.${encodeURIComponent(txId)}`, {
      method: "PATCH",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Transaction update rejected by database." });
    }

    const data = await response.json().catch(() => []);
    if (!Array.isArray(data) || data.length === 0) {
      return res.status(404).json({ success: false, error: "Transaction not found." });
    }

    return res.json({ success: true, data: data[0], recalculated: payload });
  } catch (err: any) {
    console.error("[SERVER] Update transaction exception:", err);
    return res.status(400).json({ success: false, error: err?.message || "Transaction update failed." });
  }
});

// 3.2 Delete Transaction (DELETE /api/transactions/:id or /api/transactions - Owner Only)
app.delete(["/api/transactions/:id", "/api/transactions"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const rawId = String(req.params.id || req.body?.id || req.query?.id || "").trim();

  if (!/^\d+$/.test(rawId)) {
    return res.status(400).json({
      success: false,
      error: "A numeric transaction ID is required for deletion. Invoice number deletion is disabled for data safety."
    });
  }

  try {
    const response = await fetch(`${url}/rest/v1/transactions?id=eq.${encodeURIComponent(rawId)}`, {
      method: "DELETE",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        Prefer: "return=representation"
      }
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({ success: false, error: errText || "Transaction deletion rejected by database." });
    }

    const deletedRows = await response.json().catch(() => []);
    if (!Array.isArray(deletedRows) || deletedRows.length !== 1) {
      return res.status(404).json({ success: false, error: "Transaction not found." });
    }

    auditLog(String((req as any).user?.username || "unknown"), "DELETE_TRANSACTION", rawId, "SUCCESS");
    return res.json({ success: true, id: rawId, deleted: deletedRows });
  } catch {
    return res.status(503).json({ success: false, error: "Transaction service is temporarily unavailable." });
  }
});

// 3.3 Danger Zone: Destructive Actions Suite Endpoint (POST Method - Owner Only)
app.post("/api/settings/reset_data", resetDataLimiter, requireOwner, async (req: Request, res: Response) => {
  const actor = String((req as any).user?.username || "unknown");
  auditLog(actor, "DANGER_ZONE_RESET_BLOCKED", "production_database", "FAILURE", {
    reason: "Destructive database reset is permanently disabled."
  });
  return res.status(403).json({
    success: false,
    error: "Destructive database reset is permanently disabled in this application."
  });
});

// Helper to safely clean numeric values from CSV imports without NaN
function parseImportDecimal(val: any): number {
  if (val === null || val === undefined) return 0.0;
  if (typeof val === "number") return isNaN(val) ? 0.0 : Math.round(val * 100) / 100;
  let s = String(val).trim().replace(/^['"]|['"]$/g, "");
  if (!s || ["#n/a", "null", "none", "nan", "blank", "n/a", "-", "."].includes(s.toLowerCase())) return 0.0;
  let isNeg = false;
  if (s.startsWith("(") && s.endsWith(")")) {
    isNeg = true;
    s = s.slice(1, -1).trim();
  }
  let cleaned = s.replace(/AED|USD|\$|€|£|,/gi, "").replace(/[^0-9.-]/g, "");
  if (!cleaned || cleaned === "-" || cleaned === "." || cleaned === "-.") return 0.0;
  let num = parseFloat(cleaned);
  if (isNaN(num)) return 0.0;
  if (isNeg) num = -Math.abs(num);
  return Math.round(num * 100) / 100;
}

// 4. Batch CSV Import Endpoint for Transactions (Owner Only - Rate Limited)
app.post("/api/import/transactions", importLimiter, requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const { rows, forced_type } = req.body || {};

  if (!Array.isArray(rows) || rows.length === 0 || rows.length > 5000) {
    return res.status(400).json({
      success: false,
      error: "rows must be a non-empty array containing no more than 5,000 records."
    });
  }

  const preparedRows: any[] = [];
  const validationErrors: Array<{ row: number; error: string }> = [];

  for (let index = 0; index < rows.length; index++) {
    const r = rows[index] || {};
    try {
      const transactionType = forced_type
        ? String(normalizeTransactionType(forced_type))
        : String(normalizeTransactionType(r.transaction_type));

      const transactionDate = String(r.transaction_date || "").split("T")[0];
      if (!/^\d{4}-\d{2}-\d{2}$/.test(transactionDate)) {
        throw new Error("transaction_date must be YYYY-MM-DD.");
      }

      let partyName = String(r.party_name || "").trim();
      let trn = String(r.trn || "").trim().replace(/\D/g, "");
      if (transactionType === "sales") {
        partyName = "Cash Customer";
        trn = "000000000000000";
      } else {
        if (!partyName) throw new Error("Supplier / party name is required.");
        if (!/^\d{15}$/.test(trn)) throw new Error("Purchase TRN must contain exactly 15 digits.");
      }

      const taxMode = normalizeTaxMode(r.tax_mode || "inclusive");
      const sourceAmount =
        taxMode === "inclusive"
          ? (r.amount_input ?? r.amount_with_tax ?? r.total_amount ?? r.amount)
          : (r.amount_input ?? r.amount_before_tax ?? r.amount);

      const tax = calculateAuthoritativeTax(
        { tax_mode: taxMode, amount_input: sourceAmount },
        false
      );

      const providedBefore = r.amount_before_tax !== undefined && r.amount_before_tax !== null && r.amount_before_tax !== ""
        ? parseImportDecimal(r.amount_before_tax) : null;
      const providedVat = r.vat_amount !== undefined && r.vat_amount !== null && r.vat_amount !== ""
        ? parseImportDecimal(r.vat_amount) : null;
      const providedTotal = r.amount_with_tax !== undefined && r.amount_with_tax !== null && r.amount_with_tax !== ""
        ? parseImportDecimal(r.amount_with_tax) : null;

      if (providedBefore !== null && Math.abs(providedBefore - tax.amount_before_tax) > 0.01) {
        throw new Error("amount_before_tax does not match the selected tax mode.");
      }
      if (providedVat !== null && Math.abs(providedVat - tax.vat_amount) > 0.01) {
        throw new Error("vat_amount does not match the selected tax mode.");
      }
      if (providedTotal !== null && Math.abs(providedTotal - tax.amount_with_tax) > 0.01) {
        throw new Error("amount_with_tax does not match the selected tax mode.");
      }

      preparedRows.push({
        transaction_type: transactionType,
        transaction_date: transactionDate,
        invoice_no: r.invoice_no == null ? "" : String(r.invoice_no).trim(),
        party_name: partyName,
        trn,
        amount_before_tax: tax.amount_before_tax,
        vat_rate: tax.vat_rate,
        vat_amount: tax.vat_amount,
        amount_with_tax: tax.amount_with_tax,
        tax_mode: tax.tax_mode
      });
    } catch (err: any) {
      validationErrors.push({ row: index + 1, error: err?.message || "Invalid row." });
    }
  }

  if (validationErrors.length > 0) {
    return res.status(422).json({
      success: false,
      inserted: 0,
      errors: validationErrors,
      message: "Import rejected. No records were sent to the database because one or more rows failed validation."
    });
  }

  try {
    const response = await fetch(`${url}/rest/v1/rpc/import_transactions_batch`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ rows: preparedRows })
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      return res.status(response.status).json({
        success: false,
        inserted: 0,
        errors: [{ error: errText || "Atomic batch procedure rejected the import." }],
        message: "Atomic batch import failed. No partial success is reported."
      });
    }

    const result = await response.json().catch(() => null);
    return res.json({
      success: true,
      inserted: preparedRows.length,
      skipped_duplicates: 0,
      errors: [],
      procedure_result: result,
      message: `Successfully and atomically imported ${preparedRows.length} transactions.`
    });
  } catch (err: any) {
    return res.status(503).json({
      success: false,
      inserted: 0,
      errors: [{ error: "Database connection unavailable during atomic import." }],
      message: err?.message || "Atomic batch import could not be completed."
    });
  }
});

// 5. Duplicate scanningapp.get("/api/transactions/scan-duplicates", requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const allTx: any[] = await fetchAllSupabaseTransactions(url, key, "created_at.asc", "*");
    if (!Array.isArray(allTx) || allTx.length === 0) {
      return res.json({
        success: true,
        total_scanned: 0,
        duplicate_groups_count: 0,
        total_duplicates_found: 0,
        unique_retained_count: 0,
        groups: []
      });
    }

    // Group strictly by exact all-column fingerprint
    const groupsMap = new Map<string, any[]>();
    for (const tx of allTx) {
      const fp = getTransactionStrictFingerprint(tx);
      if (!groupsMap.has(fp)) {
        groupsMap.set(fp, []);
      }
      groupsMap.get(fp)!.push(tx);
    }

    const duplicateGroups: any[] = [];
    let totalDuplicates = 0;
    let groupIdx = 1;

    for (const [fp, rows] of groupsMap.entries()) {
      if (rows.length > 1) {
        // First record (earliest created) is preserved as original; subsequent records are duplicates to be purged
        const original = rows[0];
        const duplicates = rows.slice(1);
        totalDuplicates += duplicates.length;

        duplicateGroups.push({
          group_id: groupIdx++,
          signature: fp,
          type: original.transaction_type,
          count: rows.length,
          original: original,
          duplicates: duplicates
        });
      }
    }

    res.json({
      success: true,
      total_scanned: allTx.length,
      duplicate_groups_count: duplicateGroups.length,
      total_duplicates_found: totalDuplicates,
      unique_retained_count: allTx.length - totalDuplicates,
      groups: duplicateGroups
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Safely Delete User-Confirmed Duplicate Transaction IDs
app.post("/api/transactions/delete-duplicates", requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const { ids } = req.body;

  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ success: false, error: "No duplicate IDs provided for deletion" });
  }

  try {
    let removedCount = 0;
    const errors: any[] = [];

    // Delete in safe batches of 50
    const CHUNK_SIZE = 50;
    for (let i = 0; i < ids.length; i += CHUNK_SIZE) {
      const chunk = ids.slice(i, i + CHUNK_SIZE);
      try {
        const idListStr = chunk.map(id => `"${id}"`).join(",");
        const delRes = await fetch(`${url}/rest/v1/transactions?id=in.(${idListStr})`, {
          method: "DELETE",
          headers: {
            apikey: key,
            Authorization: `Bearer ${key}`,
            Prefer: "return=representation"
          }
        });
        if (delRes.ok) {
          const deleted = await delRes.json();
          removedCount += Array.isArray(deleted) ? deleted.length : chunk.length;
        } else {
          // Fallback to row-by-row deletion
          for (const dupId of chunk) {
            const singleDel = await fetch(`${url}/rest/v1/transactions?id=eq.${encodeURIComponent(dupId)}`, {
              method: "DELETE",
              headers: {
                apikey: key,
                Authorization: `Bearer ${key}`
              }
            });
            if (singleDel.ok) removedCount++;
          }
        }
      } catch (e: any) {
        errors.push(e.message);
      }
    }

    res.json({
      success: true,
      removed_count: removedCount,
      requested_count: ids.length,
      errors
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Clean and Deduplicate Database Transactions (Legacy Direct Cleanup with Strict Matching)
app.post("/api/transactions/deduplicate", requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const allTx: any[] = await fetchAllSupabaseTransactions(url, key, "created_at.asc", "*");
    if (!Array.isArray(allTx) || allTx.length === 0) {
      return res.json({ success: true, removed_count: 0, message: "No transactions found" });
    }

    const seen = new Set<string>();
    const duplicateIds: any[] = [];

    allTx.forEach(tx => {
      const sig = getTransactionStrictFingerprint(tx);
      if (seen.has(sig)) {
        if (tx.id) duplicateIds.push(tx.id);
      } else {
        seen.add(sig);
      }
    });

    let removedCount = 0;
    for (const dupId of duplicateIds) {
      try {
        const delRes = await fetch(`${url}/rest/v1/transactions?id=eq.${encodeURIComponent(dupId)}`, {
          method: "DELETE",
          headers: {
            apikey: key,
            Authorization: `Bearer ${key}`
          }
        });
        if (delRes.ok) removedCount++;
      } catch (e) {
        console.warn("Failed to delete duplicate ID:", dupId, e);
      }
    }

    res.json({
      success: true,
      total_scanned: allTx.length,
      removed_count: removedCount,
      unique_retained: allTx.length - removedCount
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Batch CSV Import Endpoint for Suppliers (Owner Only)
app.post("/api/import/suppliers", supplierImportLimiter, requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const { rows } = req.body;

  if (!rows || !Array.isArray(rows)) {
    return res.status(400).json({ success: false, error: "Invalid payload, 'rows' array expected" });
  }

  const cleanedSuppliers = rows.map((r: any) => {
    let trnRaw = String(r.trn || "").trim();
    let trnDigits = trnRaw.replace(/\D/g, "");
    if (trnDigits.length > 0 && trnDigits.length < 15) trnDigits = trnDigits.padStart(15, "0");
    if (trnDigits.length > 15) trnDigits = trnDigits.slice(0, 15);
    return {
      name: String(r.name || "UNKNOWN_SUPPLIER").trim(),
      trn: trnDigits || trnRaw
    };
  });

  try {
    const response = await fetch(`${url}/rest/v1/suppliers`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation,resolution=merge-duplicates"
      },
      body: JSON.stringify(cleanedSuppliers)
    });

    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ success: false, error: errText });
    }

    res.json({
      success: true,
      inserted_count: cleanedSuppliers.length
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. Analytics & Forecast Aggregation Endpoint (Owner Only)
function isSummaryOrInvalidRow(t: any): boolean {
  if (!t) return true;
  const party = String(t.party_name || "").trim();
  if (/^\d+(\.\d+)?$/.test(party)) return true;
  const lower = party.toLowerCase();
  if (lower === "total" || lower === "grand total" || lower === "subtotal" || lower === "sum" || lower === "unknown_invoice" || party.includes("المجموع") || party.includes("الإجمالي")) {
    return true;
  }
  return false;
}

function normalizeTransaction(t: any): any {
  if (!t) return t;

  const isExempt = t.tax_mode === "exempt" || 
                   Number(t.vat_rate) === 0 || 
                   t.is_exempt === true ||
                   (t.tax_mode && String(t.tax_mode).toLowerCase().includes("exempt")) ||
                   (t.tax_mode && String(t.tax_mode).includes("معفى"));

  const rawAmt = Number(t.amount_before_tax) || 0;
  const rawTot = Number(t.amount_with_tax) || 0;
  const rawVat = Number(t.vat_amount) || 0;

  let baseAmt = 0;
  let totAmt = 0;

  if (rawAmt > 0 && rawTot > 0) {
    if (Math.abs(rawTot - rawAmt) < 0.01) {
      if (isExempt) {
        baseAmt = rawAmt;
        totAmt = rawAmt;
      } else {
        totAmt = rawTot;
        baseAmt = Math.round((rawTot / 1.05) * 100) / 100;
      }
    } else if (rawTot > rawAmt) {
      baseAmt = rawAmt;
      totAmt = rawTot;
    } else {
      baseAmt = rawAmt;
      totAmt = Math.round((rawAmt * (isExempt ? 1.0 : 1.05)) * 100) / 100;
    }
  } else if (rawAmt > 0) {
    baseAmt = rawAmt;
    totAmt = Math.round((rawAmt * (isExempt ? 1.0 : 1.05)) * 100) / 100;
  } else if (rawTot > 0) {
    totAmt = rawTot;
    baseAmt = isExempt ? rawTot : Math.round((rawTot / 1.05) * 100) / 100;
  }

  let vatAmt = 0;
  if (isExempt) {
    vatAmt = 0;
  } else if (rawVat > 0 && rawVat <= (baseAmt * 0.10)) {
    vatAmt = Math.round(rawVat * 100) / 100;
  } else {
    vatAmt = Math.round((totAmt - baseAmt) * 100) / 100;
  }

  totAmt = Math.round((baseAmt + vatAmt) * 100) / 100;

  return {
    ...t,
    amount_before_tax: Math.round(baseAmt * 100) / 100,
    vat_amount: Math.round(vatAmt * 100) / 100,
    amount_with_tax: Math.round(totAmt * 100) / 100,
    vat_rate: isExempt ? 0 : 0.05,
    tax_mode: isExempt ? "exempt" : (t.tax_mode || "inclusive")
  };
}

app.get("/api/analytics", analyticsLimiter, requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const rawTransactions = await fetchAllSupabaseTransactions(url, key, "transaction_date.desc", "*");

    const filter = (req.query.filter as string) || "current_quarter";
    const dateFrom = req.query.date_from as string;
    const dateTo = req.query.date_to as string;
    const search = (req.query.search as string || "").toLowerCase();

    // Financial KPI aggregation
    let salesTotal = 0;
    let salesBeforeTax = 0;
    let outputVat = 0;
    let purchasesTotal = 0;
    let purchasesBeforeTax = 0;
    let inputVat = 0;

    const filtered = (rawTransactions || []).filter((t: any) => !isSummaryOrInvalidRow(t)).map(normalizeTransaction).filter((t: any) => {
      if (dateFrom && t.transaction_date < dateFrom) return false;
      if (dateTo && t.transaction_date > dateTo) return false;
      if (search) {
        const match =
          String(t.party_name || "").toLowerCase().includes(search) ||
          String(t.invoice_no || "").toLowerCase().includes(search) ||
          String(t.trn || "").includes(search);
        if (!match) return false;
      }
      return true;
    });

    filtered.forEach((t: any) => {
      const isSales = String(t.transaction_type || "").trim().toLowerCase() === "sales";
      const beforeTax = t.amount_before_tax;
      const vat = t.vat_amount;
      const withTax = t.amount_with_tax;

      if (isSales) {
        salesBeforeTax += beforeTax;
        outputVat += vat;
        salesTotal += withTax;
      } else {
        purchasesBeforeTax += beforeTax;
        inputVat += vat;
        purchasesTotal += withTax;
      }
    });

    salesBeforeTax = Math.round(salesBeforeTax * 100) / 100;
    outputVat = Math.round(outputVat * 100) / 100;
    salesTotal = Math.round(salesTotal * 100) / 100;

    purchasesBeforeTax = Math.round(purchasesBeforeTax * 100) / 100;
    inputVat = Math.round(inputVat * 100) / 100;
    purchasesTotal = Math.round(purchasesTotal * 100) / 100;

    const netVatPayable = Math.round((outputVat - inputVat) * 100) / 100;
    const profitBeforeTax = Math.round((salesBeforeTax - purchasesBeforeTax) * 100) / 100;
    const profitVat = netVatPayable;
    const profitAfterTax = Math.round((profitBeforeTax + profitVat) * 100) / 100;
    const profitMarginPct = salesBeforeTax !== 0 ? Math.round((profitBeforeTax / salesBeforeTax) * 1000) / 10 : 0.0;

    res.json({
      success: true,
      time_filter: filter,
      transactions: filtered,
      kpis: {
        total_sales_before_tax: salesBeforeTax,
        output_vat_sales: outputVat,
        total_sales_with_tax: salesTotal,
        total_purchases_before_tax: purchasesBeforeTax,
        input_vat_purchases: inputVat,
        total_purchases_with_tax: purchasesTotal,
        net_vat_payable: netVatPayable,
        net_vat_due: netVatPayable,
        net_vat_status: netVatPayable >= 0 ? "PAYABLE TO FTA" : "REFUNDABLE FROM FTA",
        gross_profit: profitBeforeTax,
        profit_before_tax: profitBeforeTax,
        profit_vat_5: profitVat,
        profit_after_tax: profitAfterTax,
        profit_with_tax: profitAfterTax,
        profit_margin_pct: profitMarginPct,
        transaction_count: filtered.length
      }
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Helper for building Excel/CSV export rows
function generateLedgerCsv(type: "sales" | "purchases", transactions: any[], periodLabel: string) {
  const filtered = transactions.filter((t: any) =>
    type === "sales" ? t.transaction_type === "sales" : t.transaction_type !== "sales"
  );

  let csv = "\ufeff"; // UTF-8 BOM for Excel Arabic support
  csv += `Seq,Date,Invoice No,Party Name,TRN,Amount Before Tax,VAT (5%),Amount With Tax\n`;

  let totBefore = 0;
  let totVat = 0;
  let totWith = 0;

  filtered.forEach((t: any, idx: number) => {
    const before = Number(t.amount_before_tax || 0);
    const vat = Number(t.vat_amount || 0);
    const withTax = Number(t.amount_with_tax || 0);

    totBefore += before;
    totVat += vat;
    totWith += withTax;

    const safeParty = `"${String(t.party_name || "").replace(/"/g, '""')}"`;
    const safeInv = `"${String(t.invoice_no || "").replace(/"/g, '""')}"`;
    const safeTrn = `"${String(t.trn || "")}"`;
    csv += `${idx + 1},${t.transaction_date || ""},${safeInv},${safeParty},${safeTrn},${before.toFixed(2)},${vat.toFixed(2)},${withTax.toFixed(2)}\n`;
  });

  csv += `TOTAL,,,,,"${totBefore.toFixed(2)}","${totVat.toFixed(2)}","${totWith.toFixed(2)}"\n\n`;
  csv += `"Developed by Eng. Mahmoud Mohamed | mahmoud.m@sdi.ae"\n`;

  return {
    csvContent: csv,
    filename: `UAE_${type === "sales" ? "Sales" : "Purchases"}_Tax_Ledger_${new Date().toISOString().slice(0, 10)}.csv`,
    transactions: filtered,
    totals: {
      total_before_tax: Math.round(totBefore * 100) / 100,
      vat_amount: Math.round(totVat * 100) / 100,
      total_with_tax: Math.round(totWith * 100) / 100
    }
  };
}

// 7. Export Excel Sales (Owner Only)
app.all(["/api/export/excel/sales"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const transactions = await fetchAllSupabaseTransactions(url, key, "transaction_date.desc", "*");
    const filter = (req.query.filter || req.body?.time_filter || "all_time") as string;
    const dateFrom = (req.query.date_from || req.body?.date_from) as string;
    const dateTo = (req.query.date_to || req.body?.date_to) as string;
    const search = ((req.query.search || req.body?.search || "") as string).toLowerCase();

    const filtered = transactions.filter((t: any) => {
      if (dateFrom && t.transaction_date < dateFrom) return false;
      if (dateTo && t.transaction_date > dateTo) return false;
      if (search) {
        const match =
          String(t.party_name || "").toLowerCase().includes(search) ||
          String(t.invoice_no || "").toLowerCase().includes(search) ||
          String(t.trn || "").includes(search);
        if (!match) return false;
      }
      return true;
    });

    const exportData = generateLedgerCsv("sales", filtered, filter);
    res.json({
      success: true,
      filename: exportData.filename,
      csv_content: exportData.csvContent,
      message: "Sales Tax Ledger Excel export generated successfully"
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 8. Export Excel Purchases (Owner Only)
app.all(["/api/export/excel/purchases"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const transactions = await fetchAllSupabaseTransactions(url, key, "transaction_date.desc", "*");
    const filter = (req.query.filter || req.body?.time_filter || "all_time") as string;
    const dateFrom = (req.query.date_from || req.body?.date_from) as string;
    const dateTo = (req.query.date_to || req.body?.date_to) as string;
    const search = ((req.query.search || req.body?.search || "") as string).toLowerCase();

    const filtered = transactions.filter((t: any) => {
      if (dateFrom && t.transaction_date < dateFrom) return false;
      if (dateTo && t.transaction_date > dateTo) return false;
      if (search) {
        const match =
          String(t.party_name || "").toLowerCase().includes(search) ||
          String(t.invoice_no || "").toLowerCase().includes(search) ||
          String(t.trn || "").includes(search);
        if (!match) return false;
      }
      return true;
    });

    const exportData = generateLedgerCsv("purchases", filtered, filter);
    res.json({
      success: true,
      filename: exportData.filename,
      csv_content: exportData.csvContent,
      message: "Purchases Tax Ledger Excel export generated successfully"
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 9. Export PDF Sales (Owner Only)
app.all(["/api/export/pdf/sales"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const transactions = await fetchAllSupabaseTransactions(url, key, "transaction_date.desc", "*");
    const salesTx = transactions.filter((t: any) => t.transaction_type === "sales");
    res.json({
      success: true,
      transactions: salesTx,
      title: "SALES TAX LEDGER (OUTPUT VAT 5%)",
      filename: `UAE_Sales_Tax_Ledger_${new Date().toISOString().slice(0, 10)}.pdf`
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 10. Export PDF Purchases (Owner Only)
app.all(["/api/export/pdf/purchases"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const transactions = await fetchAllSupabaseTransactions(url, key, "transaction_date.desc", "*");
    const purTx = transactions.filter((t: any) => t.transaction_type !== "sales");
    res.json({
      success: true,
      transactions: purTx,
      title: "PURCHASES TAX LEDGER (INPUT VAT 5%)",
      filename: `UAE_Purchases_Tax_Ledger_${new Date().toISOString().slice(0, 10)}.pdf`
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.use("/api", (_req: Request, res: Response) => {
  return res.status(404).json({ success: false, error: "API endpoint not found." });
});

// ============================================================================
// SERVER INITIALIZATION & VITE MIDDLEWARE
// ============================================================================

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));

    const safeSendFile = (res: Response, fileName: string) => {
      const distFile = path.join(distPath, fileName);
      if (fs.existsSync(distFile)) {
        return res.sendFile(distFile);
      }
      const rootFile = path.join(process.cwd(), fileName);
      if (fs.existsSync(rootFile)) {
        return res.sendFile(rootFile);
      }
      return res.sendFile(path.join(distPath, "index.html"));
    };

    app.get(["/login", "/login.html"], (req, res) => {
      safeSendFile(res, "login.html");
    });
    app.get(["/admin", "/admin.html"], (req, res) => {
      safeSendFile(res, "admin.html");
    });
    app.get("*", (req, res) => {
      safeSendFile(res, "index.html");
    });
  }

  await verifySupabaseConnection();
  setInterval(() => {
    verifySupabaseConnection().catch(() => undefined);
  }, 5 * 60 * 1000).unref();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[SERVER] Full-Stack Accounting Server running on http://0.0.0.0:${PORT}`);
    console.log(`[SERVER] Supabase connection at startup: ${supabaseConnected ? "verified" : "unavailable"}`);
  });
}

startServer();
