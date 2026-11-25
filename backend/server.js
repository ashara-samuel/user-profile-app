const crypto = require("node:crypto");
const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = Number(process.env.PORT || 5000);
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/userdb";
const isProduction = process.env.NODE_ENV === "production";
const sessionDurationMs = 7 * 24 * 60 * 60 * 1000;

app.disable("x-powered-by");
if (process.env.TRUST_PROXY === "true") app.set("trust proxy", 1);
else if (/^\d+$/.test(process.env.TRUST_PROXY || "")) app.set("trust proxy", Number(process.env.TRUST_PROXY));
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, minlength: 1, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  passwordHash: { type: String, required: true, select: false },
  bio: { type: String, default: "", maxlength: 500 },
  location: { type: String, default: "", maxlength: 100 },
  website: { type: String, default: "", maxlength: 200 },
  avatarUrl: { type: String, default: "", maxlength: 500 },
  visibility: { type: String, enum: ["public", "private"], default: "public" },
  emailVerified: { type: Boolean, default: false }
}, { timestamps: true });

const sessionSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }
});

const tokenSchema = new mongoose.Schema({
  tokenHash: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  purpose: { type: String, enum: ["verify", "reset"], required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }
});

const User = mongoose.model("User", userSchema);
const Session = mongoose.model("Session", sessionSchema);
const AccountToken = mongoose.model("AccountToken", tokenSchema);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." }
});
const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." }
});

let mailer;
function getMailer() {
  if (!mailer && process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD) {
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
    });
  }
  return mailer;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) return reject(error);
      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

function verifyPassword(password, storedHash) {
  const [salt, key] = (storedHash || "").split(":");
  if (!salt || !key) return Promise.resolve(false);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) return reject(error);
      const expected = Buffer.from(key, "hex");
      resolve(expected.length === derivedKey.length && crypto.timingSafeEqual(expected, derivedKey));
    });
  });
}

function publicUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    bio: user.bio,
    location: user.location,
    website: user.website,
    avatarUrl: user.avatarUrl,
    visibility: user.visibility,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt
  };
}

function validEmail(value) {
  return typeof value === "string" && value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function validateProfile(input, { registration = false } = {}) {
  const errors = {};
  const result = {};
  if (registration || Object.hasOwn(input, "name")) {
    const name = typeof input.name === "string" ? input.name.trim() : "";
    if (!name || name.length > 80) errors.name = "Name must be between 1 and 80 characters.";
    else result.name = name;
  }
  if (registration) {
    const email = typeof input.email === "string" ? input.email.trim() : "";
    if (!validEmail(email)) errors.email = "Enter a valid email address.";
    else result.email = email.toLowerCase();
    if (typeof input.password !== "string" || input.password.length < 10 || input.password.length > 128) {
      errors.password = "Password must be between 10 and 128 characters.";
    } else result.password = input.password;
  }
  for (const [field, max] of [["bio", 500], ["location", 100], ["website", 200], ["avatarUrl", 500]]) {
    if (!Object.hasOwn(input, field)) continue;
    if (typeof input[field] !== "string" || input[field].length > max) {
      errors[field] = `${field} must be a string of at most ${max} characters.`;
      continue;
    }
    const value = input[field].trim();
    const urlPattern = field === "avatarUrl" ? /^https:\/\/\S+$/i : /^https?:\/\/\S+$/i;
    if ((field === "website" || field === "avatarUrl") && value && !urlPattern.test(value)) {
      errors[field] = field === "avatarUrl"
        ? "avatarUrl must be a valid HTTPS URL."
        : "website must be a valid HTTP or HTTPS URL.";
      continue;
    }
    result[field] = value;
  }
  if (Object.hasOwn(input, "visibility")) {
    if (!["public", "private"].includes(input.visibility)) errors.visibility = "Visibility must be public or private.";
    else result.visibility = input.visibility;
  }
  return { errors, value: result };
}

function sessionCookie(res, token, expires) {
  res.cookie("session", token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    expires,
    path: "/"
  });
}

function clearSessionCookie(res) {
  res.clearCookie("session", { httpOnly: true, secure: isProduction, sameSite: "strict", path: "/" });
}

async function sendAccountEmail(user, purpose, rawToken) {
  const transport = getMailer();
  if (!transport) {
    if (isProduction) throw new Error("SMTP is required in production for account email.");
    console.info(`${purpose} link for ${user.email}: ${process.env.APP_ORIGIN || "http://localhost:8080"}/?${purpose}=${encodeURIComponent(rawToken)}`);
    return;
  }
  const origin = process.env.APP_ORIGIN || "http://localhost:8080";
  const path = purpose === "verify" ? "verify" : "reset";
  const subject = purpose === "verify" ? "Verify your email" : "Reset your password";
  await transport.sendMail({
    from: process.env.EMAIL_FROM || process.env.SMTP_USER,
    to: user.email,
    subject,
    text: `Use this link within 1 hour: ${origin}/?${path}=${encodeURIComponent(rawToken)}`
  });
}

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies && req.cookies.session;
    if (!token) return res.status(401).json({ error: "Authentication required." });
    const session = await Session.findOne({ tokenHash: hashToken(token), expiresAt: { $gt: new Date() } });
    if (!session) {
      clearSessionCookie(res);
      return res.status(401).json({ error: "Session expired. Please sign in again." });
    }
    const user = await User.findById(session.userId);
    if (!user || !user.emailVerified) {
      await Session.deleteOne({ _id: session._id });
      clearSessionCookie(res);
      return res.status(401).json({ error: "Account is unavailable." });
    }
    req.user = user;
    req.sessionId = session._id;
    next();
  } catch (error) {
    next(error);
  }
}

app.use((req, res, next) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    const origin = req.get("origin");
    const expectedOrigin = process.env.APP_ORIGIN;
    if (origin && expectedOrigin) {
      try {
        if (new URL(origin).origin !== new URL(expectedOrigin).origin) {
          return res.status(403).json({ error: "Request origin is not allowed." });
        }
      } catch {
        return res.status(403).json({ error: "Request origin is not allowed." });
      }
    }
  }
  next();
});

app.get("/api/health", (req, res) => {
  const healthy = mongoose.connection.readyState === 1;
  res.status(healthy ? 200 : 503).json({ status: healthy ? "ok" : "unavailable" });
});

app.post("/api/auth/register", authLimiter, async (req, res, next) => {
  try {
    const { errors, value } = validateProfile(req.body || {}, { registration: true });
    if (Object.keys(errors).length) return res.status(400).json({ error: "Invalid registration details.", fields: errors });
    const existing = await User.findOne({
      email: { $regex: `^${escapeRegex(value.email)}$`, $options: "i" }
    }).select("+passwordHash");
    if (existing && existing.passwordHash) {
      return res.status(409).json({ error: "An account with that email already exists." });
    }
    const emailVerified = !getMailer() && !isProduction;
    const passwordHash = await hashPassword(value.password);
    const user = existing || new User();
    user.name = value.name;
    user.email = value.email;
    user.passwordHash = passwordHash;
    user.emailVerified = emailVerified;
    if (existing && !emailVerified) user.visibility = "private";
    await user.save();
    if (!user.emailVerified) {
      const token = createToken();
      await AccountToken.create({
        tokenHash: hashToken(token),
        userId: user._id,
        purpose: "verify",
        expiresAt: new Date(Date.now() + 60 * 60 * 1000)
      });
      await sendAccountEmail(user, "verify", token);
      return res.status(201).json({ message: "Account created. Check your email to verify it." });
    }
    const token = createToken();
    const expiresAt = new Date(Date.now() + sessionDurationMs);
    await Session.create({ tokenHash: hashToken(token), userId: user._id, expiresAt });
    sessionCookie(res, token, expiresAt);
    res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: "An account with that email already exists." });
    next(error);
  }
});

app.post("/api/auth/verify", authLimiter, async (req, res, next) => {
  try {
    const rawToken = req.body && req.body.token;
    if (typeof rawToken !== "string" || rawToken.length > 200) return res.status(400).json({ error: "Invalid or expired verification link." });
    const token = await AccountToken.findOneAndDelete({
      tokenHash: hashToken(rawToken),
      purpose: "verify",
      expiresAt: { $gt: new Date() }
    });
    if (!token) return res.status(400).json({ error: "Invalid or expired verification link." });
    const user = await User.findByIdAndUpdate(token.userId, { emailVerified: true }, { new: true });
    if (!user) return res.status(400).json({ error: "Account could not be verified." });
    const sessionToken = createToken();
    const expiresAt = new Date(Date.now() + sessionDurationMs);
    await Session.create({ tokenHash: hashToken(sessionToken), userId: user._id, expiresAt });
    sessionCookie(res, sessionToken, expiresAt);
    res.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/verification", resetLimiter, async (req, res, next) => {
  try {
    const email = typeof (req.body || {}).email === "string" ? req.body.email.trim().toLowerCase() : "";
    if (validEmail(email)) {
      const user = await User.findOne({ email, emailVerified: false });
      if (user) {
        await AccountToken.deleteMany({ userId: user._id, purpose: "verify" });
        const token = createToken();
        await AccountToken.create({
          tokenHash: hashToken(token),
          userId: user._id,
          purpose: "verify",
          expiresAt: new Date(Date.now() + 60 * 60 * 1000)
        });
        await sendAccountEmail(user, "verify", token);
      }
    }
    res.json({ message: "If the account needs verification, a link will be sent." });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const body = req.body || {};
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = body.password;
    if (!validEmail(email) || typeof password !== "string") return res.status(400).json({ error: "Email and password are required." });
    const user = await User.findOne({ email }).select("+passwordHash");
    if (!user || !(await verifyPassword(password, user.passwordHash))) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }
    if (!user.emailVerified) return res.status(403).json({ error: "Verify your email before signing in." });
    const token = createToken();
    const expiresAt = new Date(Date.now() + sessionDurationMs);
    await Session.create({ tokenHash: hashToken(token), userId: user._id, expiresAt });
    sessionCookie(res, token, expiresAt);
    res.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/logout", requireAuth, async (req, res, next) => {
  try {
    await Session.deleteOne({ _id: req.sessionId });
    clearSessionCookie(res);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/password-reset", resetLimiter, async (req, res, next) => {
  try {
    const email = typeof (req.body || {}).email === "string" ? req.body.email.trim().toLowerCase() : "";
    if (validEmail(email)) {
      const user = await User.findOne({ email });
      if (user && getMailer()) {
        const token = createToken();
        await AccountToken.deleteMany({ userId: user._id, purpose: "reset" });
        await AccountToken.create({
          tokenHash: hashToken(token),
          userId: user._id,
          purpose: "reset",
          expiresAt: new Date(Date.now() + 60 * 60 * 1000)
        });
        await sendAccountEmail(user, "reset", token);
      }
    }
    res.json({ message: "If the account exists, password reset instructions will be sent." });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/password-reset/confirm", authLimiter, async (req, res, next) => {
  try {
    const { token, password } = req.body || {};
    if (typeof token !== "string" || token.length > 200 || typeof password !== "string" || password.length < 10 || password.length > 128) {
      return res.status(400).json({ error: "A valid reset link and a password of 10 to 128 characters are required." });
    }
    const reset = await AccountToken.findOneAndDelete({
      tokenHash: hashToken(token),
      purpose: "reset",
      expiresAt: { $gt: new Date() }
    });
    if (!reset) return res.status(400).json({ error: "Invalid or expired password reset link." });
    await User.updateOne({ _id: reset.userId }, { passwordHash: await hashPassword(password) });
    await Session.deleteMany({ userId: reset.userId });
    res.json({ message: "Password updated. Please sign in." });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

app.patch("/api/me", requireAuth, async (req, res, next) => {
  try {
    const { errors, value } = validateProfile(req.body || {});
    if (Object.keys(errors).length) return res.status(400).json({ error: "Invalid profile details.", fields: errors });
    if (!Object.keys(value).length) return res.status(400).json({ error: "Provide at least one profile field to update." });
    const user = await User.findByIdAndUpdate(req.user._id, { $set: value }, { new: true, runValidators: true });
    res.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/me", requireAuth, async (req, res, next) => {
  try {
    await Promise.all([
      User.deleteOne({ _id: req.user._id }),
      Session.deleteMany({ userId: req.user._id }),
      AccountToken.deleteMany({ userId: req.user._id })
    ]);
    clearSessionCookie(res);
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get("/api/profiles", requireAuth, async (req, res, next) => {
  try {
    const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 80) : "";
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 20, 1), 50);
    const filter = { visibility: "public", emailVerified: true };
    if (search) filter.name = { $regex: escapeRegex(search), $options: "i" };
    if (req.query.cursor) {
      if (!mongoose.isValidObjectId(req.query.cursor)) return res.status(400).json({ error: "Invalid pagination cursor." });
      filter._id = { $gt: req.query.cursor };
    }
    const users = await User.find(filter).select("name bio location website avatarUrl createdAt").sort({ _id: 1 }).limit(limit + 1);
    const hasMore = users.length > limit;
    const page = users.slice(0, limit);
    const results = page.map(user => ({
      id: user._id, name: user.name, bio: user.bio, location: user.location,
      website: user.website, avatarUrl: user.avatarUrl, createdAt: user.createdAt
    }));
    res.json({ profiles: results, hasMore, nextCursor: hasMore ? page[page.length - 1]._id : null });
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => res.status(404).json({ error: "Not found." }));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
    return res.status(400).json({ error: "Request body must be valid JSON." });
  }
  console.error("Request failed:", error);
  res.status(500).json({ error: "An unexpected error occurred." });
});

async function start() {
  if (isProduction) {
    if (!process.env.MONGO_URI || !process.env.APP_ORIGIN) {
      throw new Error("MONGO_URI and APP_ORIGIN must be configured in production.");
    }
    let appOrigin;
    try {
      appOrigin = new URL(process.env.APP_ORIGIN);
    } catch {
      throw new Error("APP_ORIGIN must be a valid HTTPS origin.");
    }
    if (appOrigin.protocol !== "https:" || appOrigin.pathname !== "/" || appOrigin.search || appOrigin.hash) {
      throw new Error("APP_ORIGIN must be a valid HTTPS origin without a path.");
    }
    if (!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD)) {
      throw new Error("SMTP_HOST, SMTP_USER, and SMTP_PASSWORD must be configured in production.");
    }
    await getMailer().verify();
  }
  await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 });
  const server = app.listen(PORT, () => console.info(`API listening on port ${PORT}`));
  const shutdown = async signal => {
    console.info(`${signal} received; shutting down.`);
    server.close(async () => {
      await mongoose.disconnect();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

if (require.main === module) {
  start().catch(error => {
    console.error("Startup failed:", error);
    process.exit(1);
  });
}

module.exports = { app, hashPassword, verifyPassword, validateProfile, publicUser, start };
