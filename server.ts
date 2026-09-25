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

// ============================================================================
// PRODUCTION SECRET & ENVIRONMENT VALIDATION (CQ-03)
// ============================================================================
const isProd = process.env.NODE_ENV === "production";

if (isProd) {
  if (!process.env.AUTH_SECRET_KEY && !process.env.JWT_SECRET) {
    throw new Error("[FATAL CONFIG] AUTH_SECRET_KEY or JWT_SECRET is required in production environment.");
  }
  const checkKey = (process.env.AUTH_SECRET_KEY || process.env.JWT_SECRET || "").trim();
  if (checkKey.length < 32) {
    throw new Error("[FATAL CONFIG] AUTH_SECRET_KEY must be at least 32 characters in production.");
  }
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
    throw new Error("[FATAL CONFIG] SUPABASE_URL and SUPABASE_KEY are required in production environment.");
  }
}

const rawAuthSecret = (process.env.AUTH_SECRET_KEY || process.env.JWT_SECRET || "").trim();
const AUTH_SECRET_KEY: string = rawAuthSecret;

const SUPABASE_URL: string = (process.env.SUPABASE_URL || "").trim().replace(/\/+$/, "");
const SUPABASE_KEY: string = (process.env.SUPABASE_KEY || "").trim();

function getUAECurrentDate(): string {
  try {
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Dubai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit"
    }).format(new Date());
  } catch (err) {
    console.warn("[TIMEZONE] Fallback to UTC date string:", err);
    return new Date().toISOString().split("T")[0];
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
  max: 200, // Generous limit for dev / preview testing
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
function readConfigJson() {
  const cfgPath = path.join(process.cwd(), "config.json");
  if (fs.existsSync(cfgPath)) {
    try {
      return JSON.parse(fs.readFileSync(cfgPath, "utf-8"));
    } catch {
      return { default_vat_rate: 5.0 };
    }
  }
  return { default_vat_rate: 5.0 };
}

function writeConfigJson(data: any) {
  const cfgPath = path.join(process.cwd(), "config.json");
  fs.writeFileSync(cfgPath, JSON.stringify(data, null, 2), "utf-8");
}

function updateEnvFile(url: string, key: string) {
  const envPath = path.join(process.cwd(), ".env");
  let content = "";
  if (fs.existsSync(envPath)) {
    content = fs.readFileSync(envPath, "utf-8");
  }
  const lines = content.split(/\r?\n/);
  let urlSet = false;
  let keySet = false;
  const newLines = lines.map(line => {
    if (line.startsWith("SUPABASE_URL=") || line.startsWith("export SUPABASE_URL=")) {
      urlSet = true;
      return `SUPABASE_URL=${url}`;
    }
    if (line.startsWith("SUPABASE_KEY=") || line.startsWith("export SUPABASE_KEY=")) {
      keySet = true;
      return `SUPABASE_KEY=${key}`;
    }
    return line;
  });
  if (!urlSet) newLines.push(`SUPABASE_URL=${url}`);
  if (!keySet) newLines.push(`SUPABASE_KEY=${key}`);
  fs.writeFileSync(envPath, newLines.filter(Boolean).join("\n") + "\n", "utf-8");
  process.env.SUPABASE_URL = url;
  process.env.SUPABASE_KEY = key;
}

// Helper to safely get Supabase credentials with fallback defaults
function getSupabaseConfig(): { url: string; key: string } {
  const url = (process.env.SUPABASE_URL || SUPABASE_URL || "").trim().replace(/\/+$/, "");
  const key = (process.env.SUPABASE_KEY || SUPABASE_KEY || "").trim();
  return { url, key };
}

// ============================================================================
// API ROUTES (PROTECTED SERVER-SIDE PROXY FOR SUPABASE WITH RBAC)
// ============================================================================

// 0. Authentication & User Management Routes
interface PersistedUser {
  id: string;
  username: string;
  passwordHash: string;
  role: "Owner" | "Clerk";
  created_at: string;
}

const USERS_FILE_PATH = path.join(process.cwd(), "users.json");

function loadPersistedUsers(): PersistedUser[] {
  if (fs.existsSync(USERS_FILE_PATH)) {
    try {
      const data = JSON.parse(fs.readFileSync(USERS_FILE_PATH, "utf-8"));
      if (Array.isArray(data)) return data;
    } catch (err) {
      console.warn("[USERS] Failed to load users.json:", err);
    }
  }
  return [];
}

function savePersistedUsers(users: PersistedUser[]) {
  try {
    const tempPath = USERS_FILE_PATH + ".tmp";
    fs.writeFileSync(tempPath, JSON.stringify(users, null, 2), "utf-8");
    fs.renameSync(tempPath, USERS_FILE_PATH);
  } catch (err) {
    console.error("[USERS] Failed to save users.json atomically:", err);
  }
}

const MEMORY_USERS: Array<PersistedUser> = [];

// 1. Environment variable configured custom accounts (take highest priority)
const configuredOwnerUser = (process.env.OWNER_USER || "").trim();
const configuredOwnerPass = process.env.OWNER_PASS || "";
const configuredClerkUser = (process.env.CLERK_USER || "").trim();
const configuredClerkPass = process.env.CLERK_PASS || "";

if (configuredOwnerUser && configuredOwnerPass) {
  MEMORY_USERS.push({
    id: "env-owner-custom",
    username: configuredOwnerUser,
    passwordHash: bcrypt.hashSync(configuredOwnerPass, 12),
    role: "Owner",
    created_at: new Date().toISOString()
  });
}

if (configuredClerkUser && configuredClerkPass && configuredClerkUser.toLowerCase() !== configuredOwnerUser.toLowerCase()) {
  MEMORY_USERS.push({
    id: "env-clerk-custom",
    username: configuredClerkUser,
    passwordHash: bcrypt.hashSync(configuredClerkPass, 12),
    role: "Clerk",
    created_at: new Date().toISOString()
  });
}

// 2. Standard system accounts (seed defaults if not overridden by env config)
const defaultUsers: Array<{ id: string; username: string; pass: string; role: "Owner" | "Clerk" }> = [
  { id: "seed-owner-admin", username: "admin", pass: "Owner@123456", role: "Owner" },
  { id: "seed-owner-owner", username: "owner", pass: "Owner@123456", role: "Owner" },
  { id: "seed-clerk-shareef", username: "shareef", pass: "Clerk@123456", role: "Clerk" },
  { id: "seed-clerk-clerk", username: "clerk", pass: "Clerk@123456", role: "Clerk" },
];

for (const def of defaultUsers) {
  if (!MEMORY_USERS.some(u => u.username.toLowerCase() === def.username.toLowerCase())) {
    MEMORY_USERS.push({
      id: def.id,
      username: def.username,
      passwordHash: bcrypt.hashSync(def.pass, 12),
      role: def.role,
      created_at: new Date().toISOString()
    });
  }
}

// 3. Load persisted custom users from users.json on disk
const persistedUsersList = loadPersistedUsers();
for (const pu of persistedUsersList) {
  const existingIdx = MEMORY_USERS.findIndex(u => u.username.toLowerCase() === pu.username.toLowerCase());
  if (existingIdx !== -1) {
    MEMORY_USERS[existingIdx] = pu;
  } else {
    MEMORY_USERS.push(pu);
  }
}

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
  let userFoundInMem = false;
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
      if (Array.isArray(dbUsers) && dbUsers.length > 0) {
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
      databaseError = true;
      authStage = "AUTH_DATABASE_ERROR";
    }
  } catch (err) {
    console.warn("[AUTH] Supabase user query notice:", err);
    databaseError = true;
    authStage = "AUTH_DATABASE_ERROR";
  }

  // 2. Check seed/memory user store (FORBIDDEN IN PRODUCTION - fallback restricted to local dev sandbox environments only)
  if (!authenticatedUser && !isProd) {
    for (const mu of MEMORY_USERS) {
      if (mu.username.toLowerCase() === u) {
        userFoundInMem = true;
        const match = await bcrypt.compare(password, mu.passwordHash);
        if (match) {
          authenticatedUser = { username: mu.username, role: mu.role };
          authStage = "AUTH_SUCCESS";
          break;
        } else {
          authStage = "AUTH_PASSWORD_MISMATCH";
        }
      }
    }
  }

  // Safe internal diagnostics logging (No passwords, hashes, JWTs, or secret keys exposed)
  console.log(`[AUTH-DIAG] userFound=${userFoundInDb || userFoundInMem} userIdPresent=${!!authenticatedUser} passwordFieldPresent=true passwordHashFormat=bcrypt role=${authenticatedUser?.role || "none"} stage=${authStage}`);

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
app.get("/api/users", requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  let supabaseUsers: any[] = [];

  try {
    const srvRes = await fetch(`${url}/rest/v1/users?select=id,username,role,created_at`, {
      headers: { apikey: key, Authorization: `Bearer ${key}` }
    });
    if (srvRes.ok) {
      const data = await srvRes.json();
      if (Array.isArray(data)) supabaseUsers = data;
    }
  } catch (err) {
    console.warn("[USERS] Fetch users from Supabase notice:", err);
  }

  // Merge users from MEMORY_USERS and Supabase list, keeping usernames unique
  const mergedMap = new Map<string, any>();

  // 1. Populate with all local memory users
  MEMORY_USERS.forEach(mu => {
    mergedMap.set(mu.username.toLowerCase().trim(), {
      id: mu.id,
      username: mu.username,
      role: mu.role,
      created_at: mu.created_at
    });
  });

  // 2. Merge Supabase users
  supabaseUsers.forEach(su => {
    if (su && su.username) {
      const uname = String(su.username).toLowerCase().trim();
      const existing = mergedMap.get(uname);
      mergedMap.set(uname, {
        id: existing?.id || su.id || `user-${Date.now()}`,
        username: su.username,
        role: su.role || existing?.role || "Clerk",
        created_at: su.created_at || existing?.created_at || new Date().toISOString()
      });
    }
  });

  const usersList = Array.from(mergedMap.values());
  return res.json({ success: true, users: usersList });
});

app.post("/api/users", userMutationLimiter, requireOwner, async (req: Request, res: Response) => {
  const { username, role } = req.body;
  const rawUser = String(username || "").trim();
  // Passwords MUST NOT be trimmed; preserve exact character sequence entered by user
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const rawRole: "Clerk" | "Owner" = String(role || "Owner").trim().toLowerCase() === "clerk" ? "Clerk" : "Owner";

  // Strict Input Validation
  if (!rawUser || rawUser.length < 3 || rawUser.length > 50 || !/^[a-zA-Z0-9_.-]+$/.test(rawUser)) {
    return res.status(400).json({ success: false, error: "Username must be 3-50 alphanumeric characters (or _ . -)." });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({ success: false, error: "Password must be at least 6 characters long." });
  }

  const { url, key } = getSupabaseConfig();
  const hashedPassword = await hashPassword(password);
  const newUser = {
    username: rawUser,
    password: hashedPassword,
    role: rawRole,
    created_at: new Date().toISOString()
  };

  // 1. Try posting to Supabase users table
  try {
    await fetch(`${url}/rest/v1/users`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(newUser)
    });
  } catch (err) {
    console.warn("[USERS] Insert into Supabase notice:", err);
  }

  // 2. Cache in memory store and persist to users.json disk file
  const createdObj: PersistedUser = {
    id: `user-${Date.now()}`,
    username: rawUser,
    passwordHash: hashedPassword,
    role: rawRole,
    created_at: newUser.created_at
  };

  const existingIdx = MEMORY_USERS.findIndex(u => u.username.toLowerCase() === rawUser.toLowerCase());
  if (existingIdx !== -1) {
    MEMORY_USERS[existingIdx] = createdObj;
  } else {
    MEMORY_USERS.push(createdObj);
  }

  // Persist created/updated users (excluding bootstrap seed entries)
  savePersistedUsers(MEMORY_USERS.filter(u => !u.id.startsWith("seed-") && !u.id.startsWith("env-")));

  auditLog((req as any).user.username, "CREATE_USER", rawUser, "SUCCESS", { role: rawRole });
  return res.json({ success: true, message: `User '${rawUser}' registered successfully.` });
});

app.put("/api/users/:identifier", userMutationLimiter, requireOwner, async (req: Request, res: Response) => {
  const { identifier } = req.params;
  const { role, username } = req.body;
  const targetIdStr = String(identifier || "").trim();
  const password = typeof req.body.password === "string" ? req.body.password : undefined;
  const rawRole = role ? (String(role).trim().toLowerCase() === "clerk" ? "Clerk" : "Owner") : undefined;
  const newUsername = username ? String(username).trim() : undefined;

  if (password === undefined && !rawRole && !newUsername) {
    return res.status(400).json({ success: false, error: "No fields provided to update." });
  }

  if (password !== undefined && password.length < 6) {
    return res.status(400).json({ success: false, error: "Password must be at least 6 characters long." });
  }

  if (newUsername && (newUsername.length < 3 || newUsername.length > 50 || !/^[a-zA-Z0-9_.-]+$/.test(newUsername))) {
    return res.status(400).json({ success: false, error: "Username must be 3-50 alphanumeric characters (or _ . -)." });
  }

  const { url, key } = getSupabaseConfig();
  const updatePayload: Record<string, any> = {};
  if (password !== undefined) updatePayload.password = await hashPassword(password);
  if (rawRole) updatePayload.role = rawRole;
  if (newUsername) updatePayload.username = newUsername;

  // 1. Try updating in Supabase
  try {
    const isNumeric = /^\d+$/.test(targetIdStr);
    let supabaseUrl = "";
    if (isNumeric) {
      supabaseUrl = `${url}/rest/v1/users?or=(id.eq.${encodeURIComponent(targetIdStr)},username.eq.${encodeURIComponent(targetIdStr)})`;
    } else {
      supabaseUrl = `${url}/rest/v1/users?username.eq.${encodeURIComponent(targetIdStr)}`;
    }
    await fetch(supabaseUrl, {
      method: "PATCH",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(updatePayload)
    });
  } catch (err) {
    console.warn("[USERS] Supabase update user notice:", err);
  }

  // 2. Update memory cache and disk store
  const idx = MEMORY_USERS.findIndex(u => String(u.id).toLowerCase() === targetIdStr.toLowerCase() || u.username.toLowerCase() === targetIdStr.toLowerCase());
  if (idx !== -1) {
    if (updatePayload.password) MEMORY_USERS[idx].passwordHash = updatePayload.password;
    if (rawRole) MEMORY_USERS[idx].role = rawRole;
    if (newUsername) MEMORY_USERS[idx].username = newUsername;
    savePersistedUsers(MEMORY_USERS.filter(u => !u.id.startsWith("seed-") && !u.id.startsWith("env-")));
  }

  auditLog((req as any).user.username, "UPDATE_USER", targetIdStr, "SUCCESS", { role: rawRole, updatedUsername: !!newUsername, updatedPassword: password !== undefined });
  return res.json({ success: true, message: `User '${newUsername || targetIdStr}' updated successfully.` });
});

app.delete("/api/users/:identifier", requireOwner, async (req: Request, res: Response) => {
  const { identifier } = req.params;
  const requestingUser = (req as any).user?.username || (req as any).user?.user || "";
  const targetIdStr = String(identifier || "").trim().toLowerCase();
  const reqUserStr = String(requestingUser || "").trim().toLowerCase();

  // SELF-LOCKOUT PREVENTION CHECK
  if (targetIdStr && (targetIdStr === reqUserStr || targetIdStr === "admin" && reqUserStr === "admin")) {
    return res.status(400).json({
      success: false,
      error: "Self-lockout prevented: You cannot delete your own currently logged-in account."
    });
  }

  const { url, key } = getSupabaseConfig();

  // 1. Try deleting from Supabase
  try {
    const isNumeric = /^\d+$/.test(identifier);
    let supabaseUrl = "";
    if (isNumeric) {
      supabaseUrl = `${url}/rest/v1/users?or=(id.eq.${encodeURIComponent(identifier)},username.eq.${encodeURIComponent(identifier)})`;
    } else {
      supabaseUrl = `${url}/rest/v1/users?username.eq.${encodeURIComponent(identifier)}`;
    }
    await fetch(supabaseUrl, {
      method: "DELETE",
      headers: { apikey: key, Authorization: `Bearer ${key}` }
    });
  } catch (err) {
    console.warn("[USERS] Delete from Supabase notice:", err);
  }

  // 2. Remove from memory cache and disk store
  const idx = MEMORY_USERS.findIndex(u => String(u.id).toLowerCase() === targetIdStr || u.username.toLowerCase() === targetIdStr);
  if (idx !== -1) {
    if (MEMORY_USERS[idx].username.toLowerCase() === reqUserStr) {
      return res.status(400).json({
        success: false,
        error: "Self-lockout prevented: You cannot delete your own currently logged-in account."
      });
    }
    MEMORY_USERS.splice(idx, 1);
    savePersistedUsers(MEMORY_USERS.filter(u => !u.id.startsWith("seed-") && !u.id.startsWith("env-")));
  }

  console.log(`[USERS] Deleted user '${identifier}' by admin '${requestingUser}'`);
  return res.json({ success: true, message: `User '${identifier}' deleted successfully.` });
});

// 0.1 Settings & Dynamic Supabase Configuration (Owner Only)
app.get("/api/settings", requireOwner, (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const cfg = readConfigJson();
  let maskedKey = "";
  if (key) {
    if (key.length > 8) {
      maskedKey = key.slice(0, 4) + "•".repeat(key.length - 8) + key.slice(-4);
    } else {
      maskedKey = "••••••••";
    }
  }
  res.json({
    success: true,
    supabase_url: url,
    supabase_key: key,
    supabase_key_masked: maskedKey,
    default_vat_rate: cfg.default_vat_rate ?? 5.0
  });
});

app.post("/api/settings", requireOwner, (req: Request, res: Response) => {
  const { supabase_url, supabase_key, default_vat_rate } = req.body;
  if (!supabase_url || !supabase_key) {
    return res.status(400).json({ error: "Both SUPABASE_URL and SUPABASE_KEY are required." });
  }
  const vatRate = parseFloat(default_vat_rate) || 5.0;
  updateEnvFile(supabase_url.trim(), supabase_key.trim());
  writeConfigJson({ default_vat_rate: vatRate });
  res.json({
    success: true,
    message: "Settings saved successfully! Database credentials updated and client reloaded.",
    supabase_url: supabase_url.trim(),
    default_vat_rate: vatRate
  });
});

// 0.2 Report Recipients Settings
app.get("/api/settings/recipients", requireAuth, async (req: Request, res: Response) => {
  try {
    const { url, key } = getSupabaseConfig();
    let recipients: string[] = [];
    if (url && key) {
      try {
        const resp = await fetch(`${url.replace(/\/+$/, "")}/rest/v1/settings?key=eq.daily_report_recipients&select=value`, {
          headers: { apikey: key, Authorization: `Bearer ${key}` }
        });
        if (resp.ok) {
          const rows = await resp.json();
          if (Array.isArray(rows) && rows.length > 0 && rows[0].value) {
            recipients = typeof rows[0].value === "string" ? JSON.parse(rows[0].value) : rows[0].value;
          }
        }
      } catch (e) {
        console.warn("[WARN] Could not query Supabase settings table:", e);
      }
    }
    if (!recipients || recipients.length === 0) {
      const cfg = readConfigJson();
      recipients = cfg.report_recipients || [];
    }
    return res.json({ success: true, recipients });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/api/settings/recipients", requireOwner, async (req: Request, res: Response) => {
  try {
    const rawList = req.body.recipients;
    let list: string[] = [];
    if (Array.isArray(rawList)) {
      list = rawList.map((x: any) => String(x).trim().toLowerCase()).filter(Boolean);
    } else if (typeof rawList === "string") {
      list = rawList.split(/[\n,;]+/).map((s: string) => s.trim().toLowerCase()).filter(Boolean);
    }
    // Deduplicate
    list = Array.from(new Set(list));

    // Update local config.json
    const cfg = readConfigJson();
    cfg.report_recipients = list;
    writeConfigJson(cfg);

    // Update Supabase settings table if accessible
    const { url, key } = getSupabaseConfig();
    if (url && key) {
      try {
        await fetch(`${url.replace(/\/+$/, "")}/rest/v1/settings`, {
          method: "POST",
          headers: {
            apikey: key,
            Authorization: `Bearer ${key}`,
            "Content-Type": "application/json",
            Prefer: "resolution=merge-duplicates"
          },
          body: JSON.stringify({
            key: "daily_report_recipients",
            value: JSON.stringify(list),
            updated_at: new Date().toISOString()
          })
        });
      } catch (e) {
        console.warn("[WARN] Supabase settings update error:", e);
      }
    }

    return res.json({ success: true, recipients: list, message: "Recipients saved successfully." });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// 0.3 Daily Financial Report Cron Endpoint
app.all(["/api/cron/daily-report", "/api/daily-report"], async (req: Request, res: Response) => {
  const cronSecret = process.env.CRON_SECRET || "uae_accounting_cron_secret_2026";
  const authHeader = req.headers.authorization || "";
  const cronHeader = (req.headers["x-cron-secret"] as string) || "";
  const qSecret = (req.query.secret as string) || "";
  const bSecret = (req.body?.secret as string) || "";

  let authorized = false;
  if (authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7).trim();
    if (token === cronSecret) {
      authorized = true;
    } else {
      const user = verifyAuthToken(token);
      if (user && String(user.role).toLowerCase() === "owner") {
        authorized = true;
      }
    }
  }
  if (!authorized && (cronHeader === cronSecret || qSecret === cronSecret || bSecret === cronSecret)) {
    authorized = true;
  }

  if (!authorized) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized: Invalid or missing CRON_SECRET."
    });
  }

  const targetDate = (req.query.date as string) || (req.body?.date as string) || "";
  const dryRun = String(req.query.dry_run || req.body?.dry_run || "").toLowerCase() === "true" || req.query.dry_run === "1";

  // Execute admin_backend.py with arguments
  const args = ["admin_backend.py", "--daily-report"];
  if (targetDate) {
    args.push("--date", targetDate);
  }
  if (dryRun) {
    args.push("--dry-run");
  }

  const { spawn } = await import("child_process");
  const py = spawn("python3", args, { cwd: process.cwd() });
  let stdout = "";
  let stderr = "";

  py.stdout.on("data", (data) => { stdout += data.toString(); });
  py.stderr.on("data", (data) => { stderr += data.toString(); });

  py.on("close", (code) => {
    const jsonMatch = stdout.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[0]);
        return res.status(parsed.success ? 200 : 500).json(parsed);
      } catch (e) {
        // Fall through
      }
    }
    if (code === 0) {
      return res.json({ success: true, stdout, message: "Report processed successfully" });
    } else {
      return res.status(500).json({ success: false, error: stderr || stdout || `Process exited with code ${code}` });
    }
  });
});

app.post("/api/test-connection", requireOwner, async (req: Request, res: Response) => {
  const targetUrl = (req.body.supabase_url || process.env.SUPABASE_URL || "https://frmgpbwbmarkatjroflr.supabase.co").replace(/\/+$/, "");
  const targetKey = req.body.supabase_key || process.env.SUPABASE_KEY || "";
  try {
    const check = await fetch(`${targetUrl}/rest/v1/suppliers?select=name,trn&limit=1`, {
      headers: {
        apikey: targetKey,
        Authorization: `Bearer ${targetKey}`
      }
    });
    if (!check.ok) {
      const errText = await check.text();
      return res.json({ status: "error", message: `Supabase returned HTTP ${check.status}: ${errText}` });
    }
    const data = await check.json();
    return res.json({
      status: "success",
      message: `Connection verified successfully! Queried 'suppliers' table (${Array.isArray(data) ? data.length : 1} row checked).`
    });
  } catch (err: any) {
    return res.json({ status: "error", message: err.message || "Network error connecting to Supabase" });
  }
});

// 1. Health & Connection Status
app.get("/api/health", (req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.get("/api/status", async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  try {
    const check = await fetch(`${url}/rest/v1/suppliers?select=id&limit=1`, {
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`
      }
    });
    res.json({
      status: "ok",
      supabase_connected: check.ok,
      url: url.replace(/https?:\/\//, "").split(".")[0] + ".supabase.co"
    });
  } catch (err: any) {
    res.json({
      status: "ok",
      supabase_connected: false,
      error: err.message
    });
  }
});

// 2. Suppliers Endpoints (Both Owner & Clerk can read and create)
app.get("/api/suppliers", requireAuth, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const cfg = readConfigJson();
  const deletedSuppliers: string[] = Array.isArray(cfg.deleted_suppliers) 
    ? cfg.deleted_suppliers.map((x: any) => String(x).trim()) 
    : [];

  try {
    const response = await fetch(`${url}/rest/v1/suppliers?select=*&order=name.asc`, {
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
    const filtered = Array.isArray(data)
      ? data.filter((s: any) => 
          !deletedSuppliers.includes(String(s.trn || "").trim()) &&
          !deletedSuppliers.includes(String(s.name || "").trim()) &&
          !deletedSuppliers.includes(String(s.id || "").trim())
        )
      : data;
    res.json(filtered);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/suppliers", requireAuth, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const rawBody = req.body;
  const items = Array.isArray(rawBody) ? rawBody : [rawBody];

  // Clean suppliers: ensure format as text
  const cleanedSuppliers = items.map((item: any) => {
    let trnRaw = String(item.trn || "").trim();
    let trnDigits = trnRaw.replace(/\D/g, "");
    if (trnDigits.length > 0 && trnDigits.length < 15) trnDigits = trnDigits.padStart(15, "0");
    if (trnDigits.length > 15) trnDigits = trnDigits.slice(0, 15);
    return {
      name: String(item.name || "UNKNOWN_SUPPLIER").trim(),
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
      return res.status(response.status).json({ error: errText });
    }
    const data = await response.json();
    res.status(201).json(data);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Update Supplier (PUT /api/suppliers/:identifier or PUT /api/suppliers)
app.put(["/api/suppliers/:identifier", "/api/suppliers"], requireAuth, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const identifier = String(req.params.identifier || req.body.identifier || req.body.old_trn || req.body.trn || req.body.id || "").trim();
  const name = String(req.body.name || "").trim();
  let trnRaw = String(req.body.trn || "").trim();
  let trnDigits = trnRaw.replace(/\D/g, "");

  if (!name) {
    return res.status(400).json({ success: false, error: "Party / Supplier name is required." });
  }
  if (trnDigits.length > 0 && trnDigits.length < 15) trnDigits = trnDigits.padStart(15, "0");
  if (trnDigits.length > 15) trnDigits = trnDigits.slice(0, 15);
  const finalTrn = trnDigits || trnRaw;

  try {
    const response = await fetch(`${url}/rest/v1/suppliers?or=(trn.eq.${encodeURIComponent(identifier)},id.eq.${encodeURIComponent(identifier)})`, {
      method: "PATCH",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify({ name, trn: finalTrn })
    });

    if (!response.ok) {
      const errText = await response.text();
      return res.status(500).json({ success: false, error: errText });
    }
    const data = await response.json().catch(() => ([]));
    return res.json({ success: true, message: `Supplier '${name}' updated successfully.`, supplier: { name, trn: finalTrn }, data });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
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
    // Foreign Key / Relational Integrity Check
    const chkResp = await fetch(`${url}/rest/v1/transactions?select=id&or=(trn.eq.${encodeURIComponent(identifier)},party_name.ilike.${encodeURIComponent("%" + identifier + "%")})`, { headers });
    if (chkResp.ok) {
      const chkData = await chkResp.json().catch(() => []);
      if (Array.isArray(chkData) && chkData.length > 0) {
        return res.status(400).json({
          success: false,
          error: "Cannot delete supplier. They have existing invoices in the system."
        });
      }
    }

    let delFilter = "";
    if (/^\d{15}$/.test(identifier)) {
      delFilter = `trn=eq.${encodeURIComponent(identifier)}`;
    } else if (/^\d+$/.test(identifier) && identifier.length < 12) {
      delFilter = `or=(id.eq.${encodeURIComponent(identifier)},trn.eq.${encodeURIComponent(identifier)})`;
    } else {
      delFilter = `or=(name.eq.${encodeURIComponent(identifier)},trn.eq.${encodeURIComponent(identifier)})`;
    }

    const response = await fetch(`${url}/rest/v1/suppliers?${delFilter}`, {
      method: "DELETE",
      headers: { ...headers, Prefer: "return=representation" }
    });

    if (!response.ok) {
      const errText = await response.text();
      return res.status(400).json({ success: false, error: errText || "Failed to delete supplier" });
    }

    try {
      const cfg = readConfigJson();
      if (!Array.isArray(cfg.deleted_suppliers)) {
        cfg.deleted_suppliers = [];
      }
      if (!cfg.deleted_suppliers.includes(identifier)) {
        cfg.deleted_suppliers.push(identifier);
      }
      writeConfigJson(cfg);
    } catch (e) {
      console.warn("Could not save deleted_suppliers to config.json:", e);
    }

    return res.json({ success: true, message: `Supplier '${identifier}' deleted successfully.` });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Helper to fetch all transactions from Supabase bypassing the PostgREST 1,000 max-rows limit via Range pagination
async function fetchAllSupabaseTransactions(url: string, key: string, order = "transaction_date.desc", select = "*"): Promise<any[]> {
  const allRows: any[] = [];
  const batchSize = 1000;
  let offset = 0;
  let hasMore = true;

  while (hasMore) {
    const end = offset + batchSize - 1;
    try {
      const response = await fetch(`${url}/rest/v1/transactions?select=${select}&order=${order}`, {
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
          Range: `${offset}-${end}`,
          "Range-Unit": "items"
        }
      });

      if (!response.ok) {
        if (offset === 0) {
          const fallbackRes = await fetch(`${url}/rest/v1/transactions?select=${select}&order=${order}`, {
            headers: { apikey: key, Authorization: `Bearer ${key}` }
          });
          if (fallbackRes.ok) {
            const data = await fallbackRes.json();
            return Array.isArray(data) ? data : [];
          }
        }
        break;
      }

      const batch = await response.json();
      if (Array.isArray(batch) && batch.length > 0) {
        allRows.push(...batch);
        if (batch.length < batchSize) {
          hasMore = false;
        } else {
          offset += batchSize;
        }
      } else {
        hasMore = false;
      }
    } catch (e) {
      console.warn("fetchAllSupabaseTransactions pagination error at offset " + offset, e);
      break;
    }
  }

  return allRows;
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

  if (items.length === 0) {
    return res.status(400).json({ error: "Empty transaction list" });
  }

  // Sanitize transaction payloads for Supabase schema
  const cleanedItems = items.map((item: any) => {
    let trnRaw = String(item.trn || "").trim();
    let trnDigits = trnRaw.replace(/\D/g, "");
    if (trnDigits.length > 0 && trnDigits.length < 15) trnDigits = trnDigits.padStart(15, "0");
    if (trnDigits.length > 15) trnDigits = trnDigits.slice(0, 15);

    // Check for tax-exempt status or zero VAT
    const isExempt = item.tax_mode === "exempt" || item.is_exempt === true || (item.vat_amount !== undefined && item.vat_amount !== null && Number(item.vat_amount) === 0);

    let amountWithTax = Number(item.amount_with_tax || item.total_amount || 0);
    let amountBeforeTax = Number(item.amount_before_tax || 0);
    let vatAmount = Number(item.vat_amount || 0);
    let vatRate = 0.05;
    let taxMode = item.tax_mode || "exclusive";

    if (isExempt) {
      vatAmount = 0;
      vatRate = 0;
      taxMode = "exempt";
      if (amountBeforeTax > 0) {
        amountWithTax = amountWithTax > 0 ? amountWithTax : amountBeforeTax;
      } else if (amountWithTax > 0) {
        amountBeforeTax = amountWithTax;
      }
    } else {
      if (amountWithTax > 0 && amountBeforeTax === 0) {
        amountBeforeTax = Math.round((amountWithTax / 1.05) * 100) / 100;
        vatAmount = Math.round((amountWithTax - amountBeforeTax) * 100) / 100;
      } else if (amountBeforeTax > 0 && amountWithTax === 0) {
        vatAmount = Math.round((amountBeforeTax * 0.05) * 100) / 100;
        amountWithTax = Math.round((amountBeforeTax + vatAmount) * 100) / 100;
      }
    }

    let txDate = String(item.transaction_date || "").split("T")[0];
    if (!txDate || !/^\d{4}-\d{2}-\d{2}$/.test(txDate)) {
      txDate = getUAECurrentDate();
    }

    const partyNameRaw = String(item.party_name || "").trim();
    const partyNameLower = partyNameRaw.toLowerCase();
    const rawTypeLower = String(item.transaction_type || "").trim().toLowerCase();
    const invNoLower = String(item.invoice_no || "").trim().toLowerCase();

    let txType = normalizeTransactionType(item.transaction_type);

    const invNo = item.invoice_no !== undefined && item.invoice_no !== null ? String(item.invoice_no).trim() : "";

    return {
      transaction_type: txType,
      transaction_date: txDate,
      invoice_no: invNo,
      party_name: String(item.party_name || "UNKNOWN_PARTY").trim(),
      trn: trnDigits || trnRaw || "000000000000000",
      amount_before_tax: amountBeforeTax,
      vat_rate: vatRate,
      vat_amount: vatAmount,
      amount_with_tax: amountWithTax,
      tax_mode: taxMode
    };
  });

  // Guard against duplicate insertions (both existing DB rows and duplicates inside request batch)
  let itemsToInsert = cleanedItems;
  try {
    const existingList = await fetchAllSupabaseTransactions(url, key, "created_at.asc", "*");
    const seenFingerprints = new Set(existingList.map(ex => getTransactionStrictFingerprint(ex)));
    itemsToInsert = [];
    for (const it of cleanedItems) {
      const fp = getTransactionStrictFingerprint(it);
      if (!seenFingerprints.has(fp)) {
        seenFingerprints.add(fp);
        itemsToInsert.push(it);
      }
    }
  } catch (dupCheckErr) {
    console.warn("Direct insert duplicate pre-check skipped:", dupCheckErr);
  }

  if (itemsToInsert.length === 0) {
    // If all submitted items were already in database, return success with existing records representation
    return res.status(200).json({ message: "Duplicate records detected and skipped", inserted: 0, items: [] });
  }

  try {
    const response = await fetch(`${url}/rest/v1/transactions`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(itemsToInsert)
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error("[SERVER] Supabase insert error:", errText);
      return res.status(response.status).json({ error: errText });
    }

    const data = await response.json();
    res.status(201).json(data);
  } catch (err: any) {
    console.error("[SERVER] Transaction insert exception:", err);
    res.status(500).json({ error: err.message });
  }
});

// 3.1 Update Transaction (PUT /api/transactions/:id or /api/transactions - Owner Only)
app.put(["/api/transactions/:id", "/api/transactions"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const txId = req.params.id || req.body.id;

  if (!txId) {
    return res.status(400).json({ success: false, error: "Transaction ID is required for update" });
  }

  try {
    let trnRaw = String(req.body.trn || "").trim();
    let trnDigits = trnRaw.replace(/\D/g, "");
    if (trnDigits.length > 0 && trnDigits.length < 15) trnDigits = trnDigits.padStart(15, "0");
    if (trnDigits.length > 15) trnDigits = trnDigits.slice(0, 15);

    // Check if record is marked as tax-exempt or has zero VAT
    const isExempt = req.body.tax_mode === "exempt" || req.body.is_exempt === true || (req.body.vat_amount !== undefined && req.body.vat_amount !== null && Number(req.body.vat_amount) === 0);

    let amountWithTax = Number(req.body.amount_with_tax ?? 0);
    let amountBeforeTax = Number(req.body.amount_before_tax ?? 0);
    let vatAmount = 0;
    let vatRate = 0.05;
    let taxMode = req.body.tax_mode || "inclusive";

    if (isExempt) {
      vatAmount = 0;
      vatRate = 0;
      taxMode = "exempt";
      if (amountBeforeTax > 0) {
        amountWithTax = amountWithTax > 0 ? amountWithTax : amountBeforeTax;
      } else if (amountWithTax > 0) {
        amountBeforeTax = amountWithTax;
      }
    } else {
      if (amountWithTax > 0 && amountBeforeTax === 0) {
        amountBeforeTax = Math.round((amountWithTax / 1.05) * 100) / 100;
        vatAmount = Math.round((amountWithTax - amountBeforeTax) * 100) / 100;
      } else if (amountBeforeTax > 0 && amountWithTax === 0) {
        vatAmount = Math.round((amountBeforeTax * 0.05) * 100) / 100;
        amountWithTax = Math.round((amountBeforeTax + vatAmount) * 100) / 100;
      } else if (req.body.vat_amount !== undefined && Number(req.body.vat_amount) > 0) {
        vatAmount = Number(req.body.vat_amount);
      } else if (amountWithTax > 0 && amountBeforeTax > 0) {
        vatAmount = Math.round((amountWithTax - amountBeforeTax) * 100) / 100;
      }
    }

    let txDate = String(req.body.transaction_date || "").split("T")[0];
    if (!txDate || !/^\d{4}-\d{2}-\d{2}$/.test(txDate)) {
      txDate = getUAECurrentDate();
    }

    let txType = String(req.body.transaction_type || "purchases").toLowerCase().trim();
    if (txType !== "sales" && txType !== "purchases") {
      txType = "purchases";
    }

    const invNo = req.body.invoice_no !== undefined && req.body.invoice_no !== null ? String(req.body.invoice_no).trim() : "";

    const payload = {
      transaction_type: txType,
      transaction_date: txDate,
      invoice_no: invNo,
      party_name: String(req.body.party_name || "UNKNOWN_PARTY").trim(),
      trn: trnDigits || trnRaw,
      amount_before_tax: amountBeforeTax,
      vat_rate: vatRate,
      vat_amount: vatAmount,
      amount_with_tax: amountWithTax,
      tax_mode: taxMode
    };

    const response = await fetch(`${url}/rest/v1/transactions?id=eq.${txId}`, {
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
      const errText = await response.text();
      return res.status(response.status).json({ success: false, error: errText });
    }

    const data = await response.json();
    res.json({ success: true, data: Array.isArray(data) ? data[0] : data, recalculated: payload });
  } catch (err: any) {
    console.error("[SERVER] Update transaction exception:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3.2 Delete Transaction (DELETE /api/transactions/:id or /api/transactions - Owner Only)
app.delete(["/api/transactions/:id", "/api/transactions"], requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const txId = req.params.id || req.body?.id || req.query?.id;
  const invoiceNo = req.body?.invoice_no || req.query?.invoice_no;

  if (!txId && !invoiceNo) {
    return res.status(400).json({ success: false, error: "Transaction ID or Invoice Number is required for delete" });
  }

  try {
    let deletedRows: any[] = [];
    let lastError = "";

    // 1. If txId is provided, try delete by 'id'
    if (txId && txId !== "undefined" && txId !== "null") {
      try {
        const resp = await fetch(`${url}/rest/v1/transactions?id=eq.${encodeURIComponent(txId)}`, {
          method: "DELETE",
          headers: {
            apikey: key,
            Authorization: `Bearer ${key}`,
            "Content-Type": "application/json",
            Prefer: "return=representation"
          }
        });
        if (resp.ok) {
          deletedRows = await resp.json().catch(() => []);
          if (Array.isArray(deletedRows) && deletedRows.length > 0) {
            return res.json({ success: true, id: txId, deleted: deletedRows });
          }
        } else {
          lastError = await resp.text().catch(() => "");
        }
      } catch (e: any) {
        lastError = e.message;
      }
    }

    // 2. If not deleted yet, try delete by 'invoice_no'
    const invTarget = invoiceNo || txId;
    if (invTarget && invTarget !== "undefined" && invTarget !== "null") {
      try {
        const respInv = await fetch(`${url}/rest/v1/transactions?invoice_no=eq.${encodeURIComponent(invTarget)}`, {
          method: "DELETE",
          headers: {
            apikey: key,
            Authorization: `Bearer ${key}`,
            "Content-Type": "application/json",
            Prefer: "return=representation"
          }
        });
        if (respInv.ok) {
          deletedRows = await respInv.json().catch(() => []);
          return res.json({ success: true, id: invTarget, deleted: deletedRows });
        } else {
          const invErr = await respInv.text().catch(() => "");
          lastError = invErr || lastError;
        }
      } catch (e: any) {
        lastError = e.message || lastError;
      }
    }

    if (deletedRows.length === 0 && lastError) {
      return res.status(400).json({ success: false, error: lastError });
    }

    res.json({ success: true, id: txId || invoiceNo, deleted: deletedRows });
  } catch (err: any) {
    console.error("[SERVER] Delete transaction exception:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3.3 Danger Zone: Destructive Actions Suite Endpoint (POST Method - Owner Only)
app.post("/api/settings/reset_data", resetDataLimiter, requireOwner, async (req: Request, res: Response) => {
  const { url, key } = getSupabaseConfig();
  const actor = (req as any).user?.username || "Owner";
  const actionType = String(
    req.body?.action_type || req.body?.transaction_type || req.body?.type_to_reset || ""
  ).toLowerCase().trim();
  const confirmPhrase = String(req.body?.confirm_phrase || req.body?.confirmText || "").trim();

  try {
    const headers = {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "return=representation"
    };

    if (actionType === "sales" || actionType === "reset_sales") {
      if (confirmPhrase !== "DELETE ALL SALES") {
        auditLog(actor, "DANGER_ZONE_RESET_REJECTED", "sales", "FAILURE", { reason: "Invalid confirmation phrase" });
        return res.status(400).json({
          success: false,
          error: "Confirmation failed: You must type 'DELETE ALL SALES' to reset sales transactions."
        });
      }
      const response = await fetch(`${url}/rest/v1/transactions?transaction_type=eq.sales`, { method: "DELETE", headers });
      if (!response.ok) {
        const errText = await response.text();
        return res.status(500).json({ success: false, error: errText || `HTTP ${response.status} from Supabase` });
      }
      const data = await response.json().catch(() => []);
      const deletedCount = Array.isArray(data) ? data.length : 0;
      auditLog(actor, "DANGER_ZONE_RESET", "sales", "SUCCESS", { actionType: "sales", deleted_count: deletedCount });
      return res.json({ success: true, action_type: "sales", deleted_count: deletedCount, message: "Successfully deleted all SALES transactions." });
    }

    if (actionType === "purchases" || actionType === "reset_purchases") {
      if (confirmPhrase !== "DELETE ALL PURCHASES") {
        auditLog(actor, "DANGER_ZONE_RESET_REJECTED", "purchases", "FAILURE", { reason: "Invalid confirmation phrase" });
        return res.status(400).json({
          success: false,
          error: "Confirmation failed: You must type 'DELETE ALL PURCHASES' to reset purchase transactions."
        });
      }
      const response = await fetch(`${url}/rest/v1/transactions?transaction_type=eq.purchases`, { method: "DELETE", headers });
      if (!response.ok) {
        const errText = await response.text();
        return res.status(500).json({ success: false, error: errText || `HTTP ${response.status} from Supabase` });
      }
      const data = await response.json().catch(() => []);
      const deletedCount = Array.isArray(data) ? data.length : 0;
      auditLog(actor, "DANGER_ZONE_RESET", "purchases", "SUCCESS", { actionType: "purchases", deleted_count: deletedCount });
      return res.json({ success: true, action_type: "purchases", deleted_count: deletedCount, message: "Successfully deleted all PURCHASES transactions." });
    }

    if (actionType === "single_supplier" || actionType === "delete_single_supplier") {
      const supplierIdOrTrn = String(req.body?.supplier_identifier || req.body?.trn || req.body?.id || "").trim();
      if (!supplierIdOrTrn) {
        return res.status(400).json({ success: false, error: "Missing supplier identifier (TRN or ID)." });
      }

      // Foreign Key / Relational Integrity Check
      const chkResp = await fetch(`${url}/rest/v1/transactions?select=id&trn=eq.${encodeURIComponent(supplierIdOrTrn)}`, { headers });
      if (chkResp.ok) {
        const chkData = await chkResp.json().catch(() => []);
        if (Array.isArray(chkData) && chkData.length > 0) {
          return res.status(500).json({
            success: false,
            error: `Foreign Key / Relational Integrity Violation: Supplier '${supplierIdOrTrn}' has ${chkData.length} existing transactions. Delete those transactions first.`
          });
        }
      }

      let delFilter = "";
      if (/^\d{15}$/.test(supplierIdOrTrn)) {
        delFilter = `trn=eq.${encodeURIComponent(supplierIdOrTrn)}`;
      } else if (/^\d+$/.test(supplierIdOrTrn) && supplierIdOrTrn.length < 12) {
        delFilter = `or=(id.eq.${encodeURIComponent(supplierIdOrTrn)},trn.eq.${encodeURIComponent(supplierIdOrTrn)})`;
      } else {
        delFilter = `or=(name.eq.${encodeURIComponent(supplierIdOrTrn)},trn.eq.${encodeURIComponent(supplierIdOrTrn)})`;
      }

      const response = await fetch(`${url}/rest/v1/suppliers?${delFilter}`, { method: "DELETE", headers: { ...headers, Prefer: "return=representation" } });
      if (!response.ok) {
        const errText = await response.text();
        return res.status(500).json({ success: false, error: errText || `HTTP ${response.status} from Supabase` });
      }
      const data = await response.json().catch(() => []);
      return res.json({ success: true, action_type: "single_supplier", deleted_count: Array.isArray(data) ? data.length : 0, message: `Supplier '${supplierIdOrTrn}' deleted successfully.` });
    }

    if (actionType === "all_suppliers" || actionType === "reset_suppliers") {
      const chkResp = await fetch(`${url}/rest/v1/transactions?select=id&limit=1`, { headers });
      if (chkResp.ok) {
        const chkData = await chkResp.json().catch(() => []);
        if (Array.isArray(chkData) && chkData.length > 0) {
          return res.status(500).json({
            success: false,
            error: "Relational Constraint Violation: Cannot delete all suppliers while transaction records exist. Run Factory Reset or clear transactions first."
          });
        }
      }

      const response = await fetch(`${url}/rest/v1/suppliers?trn=not.is.null`, { method: "DELETE", headers: { ...headers, Prefer: "return=representation" } });
      if (!response.ok) {
        const errText = await response.text();
        return res.status(500).json({ success: false, error: errText || `HTTP ${response.status} from Supabase` });
      }
      const data = await response.json().catch(() => []);
      return res.json({ success: true, action_type: "all_suppliers", deleted_count: Array.isArray(data) ? data.length : 0, message: "Successfully deleted all registered suppliers." });
    }

    if (actionType === "factory_reset" || actionType === "wipe_database" || actionType === "reset_all") {
      if (confirmPhrase !== "WIPE ENTIRE DATABASE") {
        auditLog(actor, "DANGER_ZONE_RESET_REJECTED", "factory_reset", "FAILURE", { reason: "Invalid confirmation phrase" });
        return res.status(400).json({
          success: false,
          error: "Confirmation failed: You must type 'WIPE ENTIRE DATABASE' to perform factory reset."
        });
      }
      // 1. Delete transactions first
      const txResp = await fetch(`${url}/rest/v1/transactions?id=neq.0`, { method: "DELETE", headers: { ...headers, Prefer: "return=representation" } });
      if (!txResp.ok) {
        const errText = await txResp.text();
        return res.status(500).json({ success: false, error: `Failed to wipe transactions: ${errText}` });
      }
      const txData = await txResp.json().catch(() => []);

      // 2. Delete suppliers
      const supResp = await fetch(`${url}/rest/v1/suppliers?trn=not.is.null`, { method: "DELETE", headers: { ...headers, Prefer: "return=representation" } });
      if (!supResp.ok) {
        const errText = await supResp.text();
        return res.status(500).json({ success: false, error: `Failed to wipe suppliers: ${errText}` });
      }
      const supData = await supResp.json().catch(() => []);

      return res.json({
        success: true,
        action_type: "factory_reset",
        transactions_deleted: Array.isArray(txData) ? txData.length : 0,
        suppliers_deleted: Array.isArray(supData) ? supData.length : 0,
        message: "Factory Reset Complete! Database completely wiped."
      });
    }

    return res.status(400).json({
      success: false,
      error: `Invalid action_type: '${actionType}'. Supported actions: 'sales', 'purchases', 'single_supplier', 'all_suppliers', or 'factory_reset'.`
    });

  } catch (err: any) {
    console.error(`[SERVER] Exception in reset_data (${actionType}):`, err);
    return res.status(500).json({ success: false, error: err.message || String(err) });
  }
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
  const { rows, forced_type } = req.body; // Array of row objects from CSV and optional forced_type

  if (!rows || !Array.isArray(rows)) {
    return res.status(400).json({ success: false, error: "Invalid payload, 'rows' array expected" });
  }

  const cleanedRows = rows.map((r: any) => {
    let trnRaw = String(r.trn || "").trim();
    let trnDigits = trnRaw.replace(/\D/g, "");
    if (trnDigits.length > 0 && trnDigits.length < 15) trnDigits = trnDigits.padStart(15, "0");
    if (trnDigits.length > 15) trnDigits = trnDigits.slice(0, 15);

    let rawBefore = (r.amount_before_tax !== undefined && r.amount_before_tax !== null && r.amount_before_tax !== "") 
      ? parseImportDecimal(r.amount_before_tax) 
      : null;
    let rawVat = (r.vat_amount !== undefined && r.vat_amount !== null && r.vat_amount !== "") 
      ? parseImportDecimal(r.vat_amount) 
      : null;
    let rawWith = (r.amount_with_tax !== undefined && r.amount_with_tax !== null && r.amount_with_tax !== "") 
      ? parseImportDecimal(r.amount_with_tax) 
      : ((r.total_amount !== undefined && r.total_amount !== null && r.total_amount !== "") ? parseImportDecimal(r.total_amount) : null);

    let rawTaxMode = String(r.tax_mode || "").toLowerCase().trim();
    let isExempt = false;
    if (rawTaxMode === "exempt" || r.is_exempt === true || rawTaxMode.includes("exempt") || rawTaxMode.includes("zero") || rawTaxMode.includes("0%") || rawTaxMode.includes("مستثن") || rawTaxMode.includes("اعفاء") || rawTaxMode.includes("إعفاء")) {
      isExempt = true;
    } else if (rawVat !== null && rawVat === 0) {
      isExempt = true;
    } else if (rawBefore !== null && rawWith !== null && rawBefore > 0 && Math.abs(rawBefore - rawWith) < 0.001) {
      isExempt = true;
    }

    let amountBeforeTax = 0.0;
    let vatAmount = 0.0;
    let amountWithTax = 0.0;
    let vatRate = 0.05;
    let taxMode = r.tax_mode || "inclusive";

    if (isExempt) {
      vatAmount = 0.0;
      vatRate = 0.0;
      taxMode = "exempt";
      if (rawBefore !== null && rawBefore > 0) {
        amountBeforeTax = rawBefore;
        amountWithTax = (rawWith !== null && rawWith > 0) ? rawWith : rawBefore;
      } else if (rawWith !== null && rawWith > 0) {
        amountWithTax = rawWith;
        amountBeforeTax = rawWith;
      }
    } else {
      // PRESERVE VALUES AS-IS FROM EXTERNAL FILE WITHOUT UNWANTED RECALCULATION
      if (rawBefore !== null && rawVat !== null && rawWith !== null) {
        amountBeforeTax = rawBefore;
        vatAmount = rawVat;
        amountWithTax = rawWith;
        vatRate = 0.05;
      } else if (rawBefore !== null && rawVat !== null) {
        amountBeforeTax = rawBefore;
        vatAmount = rawVat;
        amountWithTax = Math.round((amountBeforeTax + vatAmount) * 100) / 100;
        vatRate = 0.05;
      } else if (rawWith !== null && rawVat !== null) {
        amountWithTax = rawWith;
        vatAmount = rawVat;
        amountBeforeTax = Math.round((amountWithTax - vatAmount) * 100) / 100;
        vatRate = 0.05;
      } else if (rawWith !== null && rawBefore !== null) {
        amountWithTax = rawWith;
        amountBeforeTax = rawBefore;
        vatAmount = Math.round((amountWithTax - amountBeforeTax) * 100) / 100;
        vatRate = 0.05;
      } else if (rawWith !== null && rawWith > 0) {
        amountWithTax = rawWith;
        amountBeforeTax = Math.round((amountWithTax / 1.05) * 100) / 100;
        vatAmount = Math.round((amountWithTax - amountBeforeTax) * 100) / 100;
        vatRate = 0.05;
      } else if (rawBefore !== null && rawBefore > 0) {
        amountBeforeTax = rawBefore;
        vatAmount = Math.round((amountBeforeTax * 0.05) * 100) / 100;
        amountWithTax = Math.round((amountBeforeTax + vatAmount) * 100) / 100;
        vatRate = 0.05;
      }
    }

    let txDate = String(r.transaction_date || "").split("T")[0];
    if (!txDate || !/^\d{4}-\d{2}-\d{2}$/.test(txDate)) {
      txDate = getUAECurrentDate();
    }

    const partyNameRaw = String(r.party_name || "").trim();
    const partyNameLower = partyNameRaw.toLowerCase();
    const rawTypeLower = String(r.transaction_type || "").trim().toLowerCase();
    const invNoLower = String(r.invoice_no || "").trim().toLowerCase();

    let txType = forced_type ? normalizeTransactionType(forced_type) : normalizeTransactionType(r.transaction_type);
    const invNo = r.invoice_no !== undefined && r.invoice_no !== null ? String(r.invoice_no).trim() : "";

    return {
      transaction_type: txType,
      transaction_date: txDate,
      invoice_no: invNo,
      party_name: String(r.party_name || "UNKNOWN_PARTY").trim(),
      trn: trnDigits || trnRaw || "000000000000000",
      amount_before_tax: isNaN(amountBeforeTax) ? 0.0 : amountBeforeTax,
      vat_rate: isNaN(vatRate) ? 0.05 : vatRate,
      vat_amount: isNaN(vatAmount) ? 0.0 : vatAmount,
      amount_with_tax: isNaN(amountWithTax) ? 0.0 : amountWithTax,
      tax_mode: taxMode
    };
  });

  // Check for and skip duplicates during batch import using strict 100% all-column matching (both DB and intra-batch)
  let rowsToInsert = cleanedRows;
  try {
    const existingList = await fetchAllSupabaseTransactions(url, key, "created_at.asc", "*");
    const seenFingerprints = new Set(existingList.map(ex => getTransactionStrictFingerprint(ex)));
    rowsToInsert = [];
    for (const nr of cleanedRows) {
      const fp = getTransactionStrictFingerprint(nr);
      if (!seenFingerprints.has(fp)) {
        seenFingerprints.add(fp);
        rowsToInsert.push(nr);
      }
    }
  } catch (dupCheckErr) {
    console.warn("Duplicate check pre-fetch skipped:", dupCheckErr);
  }

  if (rowsToInsert.length === 0) {
    return res.json({ success: true, inserted: 0, skipped_duplicates: cleanedRows.length, errors: [], message: "All imported rows were duplicates and skipped." });
  }

  // ATOMIC BATCH IMPORT (CQ-07):
  // PostgREST executes a single POST request with a JSON array as a single atomic PostgreSQL transaction.
  // If any row fails, PostgreSQL rolls back the entire batch insert so no partial data remains.
  try {
    const response = await fetch(`${url}/rest/v1/transactions`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify(rowsToInsert)
    });

    if (!response.ok) {
      const errText = await response.text();
      return res.status(400).json({
        success: false,
        error: `Atomic batch import failed and was completely rolled back: ${errText}`,
        inserted: 0,
        errors: [{ error: errText }]
      });
    }

    const insertedData = await response.json();
    const count = Array.isArray(insertedData) ? insertedData.length : rowsToInsert.length;

    return res.json({
      success: true,
      inserted: count,
      skipped_duplicates: cleanedRows.length - rowsToInsert.length,
      errors: [],
      message: `Successfully and atomically imported ${count} transactions.`
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: `Network or database error during atomic batch import (0 rows saved): ${err.message}`,
      inserted: 0
    });
  }
});

// 1. Scan Database Transactions for 100% Exact Duplicates (Preview Mode - No Deletion)
app.get("/api/transactions/scan-duplicates", requireOwner, async (req: Request, res: Response) => {
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

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[SERVER] Full-Stack Accounting Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
