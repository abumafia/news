/**
 * NEWS.ULTRA — Mini Project
 * Files: server.js + public/*.html
 *
 * Install:
 *  npm i express mongoose cookie-parser cors helmet compression express-rate-limit dotenv cloudinary multer
 *
 * Run:
 *  node server.js
 */

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");

const app = express();

// ==============================
// Config
// ==============================
const PORT = parseInt(process.env.PORT || "3000", 10);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const SITE_NAME = process.env.SITE_NAME || "NEWS.ULTRA";
const SITE_LOGO_URL = process.env.SITE_LOGO_URL || `${BASE_URL}/logo.png`;

// Cloudinary (optional)
if (process.env.CLOUDINARY_CLOUD_NAME) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY || "",
    api_secret: process.env.CLOUDINARY_API_SECRET || "",
  });
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024 } });

// ==============================
// Middleware
// ==============================
app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: false, // CDN ishlatilyapti (Tailwind/Icons/Animate/Quill). Istasangiz keyin CSP qo‘shamiz.
}));
app.use(compression());
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 240,
}));

app.use(express.static("public", { extensions: ["html"] }));

// Guest id cookie (views/likes/comments/follow uchun)
app.use((req, res, next) => {
  if (!req.cookies.guestId) {
    const guestId = "g_" + crypto.randomBytes(12).toString("hex");
    res.cookie("guestId", guestId, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });
    req.cookies.guestId = guestId;
  }
  next();
});

// ==============================
// Helpers
// ==============================
function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function safeText(v, max = 2000) {
  if (v === null || v === undefined) return "";
  let s = String(v);
  s = s.replace(/\u0000/g, "");
  if (s.length > max) s = s.slice(0, max);
  return s.trim();
}

function slugify(input) {
  const s = safeText(input, 200)
    .toLowerCase()
    .replace(/['"]/g, "")
    .replace(/[^a-z0-9\u0400-\u04FF]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-");
  return s || ("news-" + crypto.randomBytes(4).toString("hex"));
}

async function ensureUniqueSlug(title) {
  let base = slugify(title);
  let slug = base;
  let i = 0;
  while (await Article.exists({ slug })) {
    i += 1;
    slug = `${base}-${i}`;
  }
  return slug;
}

function nowISO() {
  return new Date().toISOString();
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Zararli kontentni tozalash (script/iframe/on* attrs/javascript:)
function sanitizeRichHtml(html) {
  let s = String(html || "");

  // remove <script>...</script> and <style>...</style>
  s = s.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");
  s = s.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "");

  // remove iframes/object/embed
  s = s.replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "");
  s = s.replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, "");
  s = s.replace(/<embed\b[^>]*>/gi, "");

  // remove inline event handlers: onclick=, onerror= ...
  s = s.replace(/\son\w+="[^"]*"/gi, "");
  s = s.replace(/\son\w+='[^']*'/gi, "");
  s = s.replace(/\son\w+=\S+/gi, "");

  // block javascript: in href/src
  s = s.replace(/href\s*=\s*(['"])\s*javascript:[\s\S]*?\1/gi, 'href="#"');
  s = s.replace(/src\s*=\s*(['"])\s*javascript:[\s\S]*?\1/gi, 'src=""');

  return s;
}

// ==============================
// Auth token (cookie)
// ==============================
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expect = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  if (sig !== expect) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf-8"));
    if (!payload || !payload.uid || !payload.role) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireRole(roles = []) {
  return (req, res, next) => {
    const token = req.cookies?.auth || req.headers["x-auth"];
    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: "Unauthorized" });
    if (roles.length && !roles.includes(decoded.role)) return res.status(403).json({ error: "Forbidden" });
    req.user = decoded;
    next();
  };
}

// ==============================
// Mongo / Models
// ==============================
async function connectMongo() {
  const uri = process.env.MONGODB_URI || "mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/news45?appName=abumafia";
  await mongoose.connect(uri);
  console.log("✅ MongoDB connected");
}

const AuthorSchema = new mongoose.Schema({
  role: { type: String, enum: ["admin", "editor", "author"], default: "author", index: true },
  username: { type: String, unique: true, index: true },
  passwordHash: { type: String },

  firstName: String,
  lastName: String,
  email: String,
  phone: String,
  bio: String,

  avatarUrl: String,
  avatarPublicId: String,

  isActive: { type: Boolean, default: true, index: true },
}, { timestamps: true });

const ArticleSchema = new mongoose.Schema({
  status: { type: String, enum: ["draft", "scheduled", "published"], default: "draft", index: true },
  slug: { type: String, unique: true, index: true },

  title: { type: String, index: "text" },
  excerpt: String,
  contentHtml: String,

  coverUrl: String,
  coverPublicId: String,

  category: { type: String, index: true },
  subcategory: { type: String, index: true },
  tags: [String],

  youtubeUrl: String,
  instagramUrl: String,
  telegramUrl: String,

  // Author info (display + profile link)
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: "Author", index: true },
  authorName: { type: String, index: true },
  authorUsername: { type: String, index: true },

  publishedAt: { type: Date, index: true },

  views: { type: Number, default: 0, index: true },
  likes: { type: Number, default: 0, index: true },
  commentsCount: { type: Number, default: 0, index: true },
}, { timestamps: true });

ArticleSchema.index({ title: "text", excerpt: "text", contentHtml: "text" });

const ViewSchema = new mongoose.Schema({
  articleId: { type: mongoose.Schema.Types.ObjectId, ref: "Article", index: true },
  guestId: { type: String, index: true },
  dayKey: { type: String, index: true }, // YYYY-MM-DD
}, { timestamps: true });
ViewSchema.index({ articleId: 1, guestId: 1, dayKey: 1 }, { unique: true });

const LikeSchema = new mongoose.Schema({
  articleId: { type: mongoose.Schema.Types.ObjectId, ref: "Article", index: true },
  guestId: { type: String, index: true },
}, { timestamps: true });
LikeSchema.index({ articleId: 1, guestId: 1 }, { unique: true });

const CommentSchema = new mongoose.Schema({
  articleId: { type: mongoose.Schema.Types.ObjectId, ref: "Article", index: true },
  guestId: { type: String, index: true },
  name: String,
  text: String,
}, { timestamps: true });

const FollowSchema = new mongoose.Schema({
  authorId: { type: mongoose.Schema.Types.ObjectId, ref: "Author", index: true },
  guestId: { type: String, index: true },
}, { timestamps: true });
FollowSchema.index({ authorId: 1, guestId: 1 }, { unique: true });

const Author = mongoose.model("Author", AuthorSchema);
const Article = mongoose.model("Article", ArticleSchema);
const View = mongoose.model("View", ViewSchema);
const Like = mongoose.model("Like", LikeSchema);
const Comment = mongoose.model("Comment", CommentSchema);
const Follow = mongoose.model("Follow", FollowSchema);

// ==============================
// Default admin (auto)
// ==============================
async function ensureDefaultAdmin() {
  const existing = await Author.findOne({ role: "admin" }).lean();
  if (existing) return;

  const username = "admin";
  const password = "admin123"; // siz so‘ragan
  await Author.create({
    role: "admin",
    username,
    passwordHash: sha256(password),
    firstName: "Admin",
    lastName: "",
    isActive: true,
  });

  console.log("✅ Default admin created: admin / admin123");
}

// ==============================
// Auth API
// ==============================
app.post("/api/auth/login", async (req, res) => {
  const username = safeText(req.body?.username, 60);
  const password = String(req.body?.password || "");
  if (!username || !password) return res.status(400).json({ error: "username/password required" });

  const user = await Author.findOne({ username, isActive: true }).lean();
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  if (user.passwordHash !== sha256(password)) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken({ uid: String(user._id), role: user.role, username: user.username, iat: Date.now() });
  res.cookie("auth", token, { httpOnly: true, sameSite: "lax", secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.json({ ok: true, role: user.role, username: user.username });
});

app.post("/api/auth/logout", async (req, res) => {
  res.clearCookie("auth");
  res.json({ ok: true });
});

app.get("/api/auth/me", async (req, res) => {
  const token = req.cookies?.auth || req.headers["x-auth"];
  const decoded = verifyToken(token);
  if (!decoded) return res.json({ ok: true, user: null });

  const user = await Author.findById(decoded.uid).lean();
  if (!user) return res.json({ ok: true, user: null });

  res.json({
    ok: true,
    user: {
      id: String(user._id),
      role: user.role,
      username: user.username,
      firstName: user.firstName || "",
      lastName: user.lastName || "",
      email: user.email || "",
      phone: user.phone || "",
      bio: user.bio || "",
      avatarUrl: user.avatarUrl || "",
    },
  });
});

// ==============================
// Upload (cover/avatar/media)
// ==============================
app.post("/api/upload", requireRole(["admin", "editor", "author"]), upload.single("file"), async (req, res) => {
  try {
    if (!process.env.CLOUDINARY_CLOUD_NAME) return res.status(400).json({ error: "Cloudinary not configured" });
    if (!req.file?.buffer) return res.status(400).json({ error: "file required" });

    const b64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;
    const up = await cloudinary.uploader.upload(b64, { folder: "news_site", resource_type: "auto" });

    res.json({ ok: true, url: up.secure_url, publicId: up.public_id, bytes: up.bytes, format: up.format });
  } catch (e) {
    res.status(500).json({ error: "Upload failed", details: String(e.message || e) });
  }
});

// ==============================
// Public Articles API
// ==============================

// list
app.get("/api/articles", async (req, res) => {
  const {
    sort = "latest",
    category,
    subcategory,
    q,
    page = "1",
    limit = "12",
    status = "published",
  } = req.query;

  const pg = Math.max(parseInt(page, 10) || 1, 1);
  const lim = Math.min(Math.max(parseInt(limit, 10) || 12, 1), 48);

  const filter = {};
  if (status) filter.status = safeText(status, 20);
  if (filter.status === "published") filter.publishedAt = { $lte: new Date() };
  if (category) filter.category = safeText(category, 60);
  if (subcategory) filter.subcategory = safeText(subcategory, 60);

  let query = Article.find(filter);

  if (q) {
    const qq = safeText(q, 120);
    query = Article.find({ ...filter, $text: { $search: qq } }, { score: { $meta: "textScore" } })
      .sort({ score: { $meta: "textScore" } });
  }

  const sortMap = {
    latest: { publishedAt: -1, createdAt: -1 },
    views: { views: -1, publishedAt: -1 },
    likes: { likes: -1, publishedAt: -1 },
    comments: { commentsCount: -1, publishedAt: -1 },
  };

  if (!q) query = query.sort(sortMap[sort] || sortMap.latest);

  const total = await Article.countDocuments(filter);
  const items = await query
    .skip((pg - 1) * lim)
    .limit(lim)
    .select("title slug excerpt coverUrl category subcategory tags publishedAt views likes commentsCount authorName authorUsername authorId")
    .lean();

  // Fallback: agar eski postlarda authorUsername bo‘lmasa — authorId’dan batch qilib olib to‘ldiramiz
  const need = items.filter(x => !x.authorUsername && x.authorId).map(x => String(x.authorId));
  if (need.length) {
    const authors = await Author.find({ _id: { $in: [...new Set(need)] } }).select("username firstName lastName").lean();
    const map = new Map(authors.map(a => [String(a._id), a]));
    for (const it of items) {
      if (!it.authorUsername && it.authorId) {
        const a = map.get(String(it.authorId));
        if (a) {
          it.authorUsername = a.username;
          it.authorName = it.authorName || [a.firstName, a.lastName].filter(Boolean).join(" ").trim() || a.username;
        }
      }
    }
  }

  res.json({ ok: true, page: pg, limit: lim, total, items });
});

// one by slug
app.get("/api/articles/:slug", async (req, res) => {
  const slug = safeText(req.params.slug, 200);
  const item = await Article.findOne({ slug, status: "published", publishedAt: { $lte: new Date() } }).lean();
  if (!item) return res.status(404).json({ error: "Not found" });

  // fallback author fields
  if ((!item.authorUsername || !item.authorName) && item.authorId) {
    const a = await Author.findById(item.authorId).select("username firstName lastName").lean();
    if (a) {
      const name = [a.firstName, a.lastName].filter(Boolean).join(" ").trim() || a.username;
      item.authorUsername = item.authorUsername || a.username;
      item.authorName = item.authorName || name;
      // best-effort persist
      await Article.updateOne({ _id: item._id }, { $set: { authorUsername: item.authorUsername, authorName: item.authorName } });
    }
  }

  res.json({ ok: true, item });
});

// Views (unique per guest per day)
app.post("/api/articles/:id/view", async (req, res) => {
  const id = req.params.id;
  const guestId = req.cookies.guestId;
  const dayKey = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  try {
    await View.create({ articleId: id, guestId, dayKey });
    await Article.updateOne({ _id: id }, { $inc: { views: 1 } });
    res.json({ ok: true, counted: true });
  } catch {
    res.json({ ok: true, counted: false });
  }
});

// Like toggle (guest)
app.post("/api/articles/:id/like", async (req, res) => {
  const id = req.params.id;
  const guestId = req.cookies.guestId;

  try {
    await Like.create({ articleId: id, guestId });
    await Article.updateOne({ _id: id }, { $inc: { likes: 1 } });
    return res.json({ ok: true, liked: true });
  } catch {
    const del = await Like.deleteOne({ articleId: id, guestId });
    if (del.deletedCount) {
      await Article.updateOne({ _id: id }, { $inc: { likes: -1 } });
      return res.json({ ok: true, liked: false });
    }
    return res.status(500).json({ error: "Like toggle failed" });
  }
});

// Comments
app.get("/api/articles/:id/comments", async (req, res) => {
  const id = req.params.id;
  const items = await Comment.find({ articleId: id }).sort({ createdAt: -1 }).limit(60).lean();
  res.json({ ok: true, items });
});

app.post("/api/articles/:id/comment", async (req, res) => {
  const id = req.params.id;
  const guestId = req.cookies.guestId;

  const name = safeText(req.body?.name, 60);
  const text = safeText(req.body?.text, 1200);

  if (!text || text.length < 2) return res.status(400).json({ error: "Comment too short" });

  await Comment.create({ articleId: id, guestId, name: name || "Guest", text });
  await Article.updateOne({ _id: id }, { $inc: { commentsCount: 1 } });

  res.json({ ok: true });
});

// ==============================
// SEO SSR page for Google News (/a/:slug)
// (JSON-LD + og meta + canonical)
// + Views count also here
// ==============================
app.get("/a/:slug", async (req, res) => {
  const slug = safeText(req.params.slug, 200);
  const a = await Article.findOne({ slug, status: "published", publishedAt: { $lte: new Date() } }).lean();
  if (!a) return res.status(404).send("Not found");

  // Count view here too (unique/day)
  try {
    const dayKey = new Date().toISOString().slice(0, 10);
    await View.create({ articleId: a._id, guestId: req.cookies.guestId, dayKey });
    await Article.updateOne({ _id: a._id }, { $inc: { views: 1 } });
  } catch {}

  // fallback author
  let authorUsername = a.authorUsername || "";
  let authorName = a.authorName || "Editor";
  if ((!authorUsername || !authorName) && a.authorId) {
    const au = await Author.findById(a.authorId).select("username firstName lastName").lean();
    if (au) {
      authorUsername = authorUsername || au.username;
      authorName = authorName || ([au.firstName, au.lastName].filter(Boolean).join(" ").trim() || au.username);
      await Article.updateOne({ _id: a._id }, { $set: { authorUsername, authorName } });
    }
  }

  const title = a.title || "News";
  const desc = (a.excerpt || "").slice(0, 180);
  const ogImage = a.coverUrl || "";
  const url = `${BASE_URL}/a/${a.slug}`;
  const published = a.publishedAt ? new Date(a.publishedAt).toISOString() : nowISO();
  const modified = a.updatedAt ? new Date(a.updatedAt).toISOString() : published;

  const authorProfileUrl = authorUsername ? `${BASE_URL}/profile.html?u=${encodeURIComponent(authorUsername)}` : undefined;

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "NewsArticle",
    mainEntityOfPage: { "@type": "WebPage", "@id": url },
    headline: title,
    description: desc,
    image: ogImage ? [ogImage] : undefined,
    datePublished: published,
    dateModified: modified,
    author: [{
      "@type": "Person",
      name: authorName,
      url: authorProfileUrl,
    }],
    publisher: {
      "@type": "Organization",
      name: SITE_NAME,
      logo: { "@type": "ImageObject", url: SITE_LOGO_URL },
    },
  };

  // Sanitized content for SSR
  const bodyHtml = sanitizeRichHtml(a.contentHtml || "");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(desc)}"/>
<link rel="canonical" href="${url}"/>

<meta property="og:type" content="article"/>
<meta property="og:title" content="${escapeHtml(title)}"/>
<meta property="og:description" content="${escapeHtml(desc)}"/>
${ogImage ? `<meta property="og:image" content="${ogImage}"/>` : ""}

<meta name="twitter:card" content="summary_large_image"/>
<meta name="twitter:title" content="${escapeHtml(title)}"/>
<meta name="twitter:description" content="${escapeHtml(desc)}"/>
${ogImage ? `<meta name="twitter:image" content="${ogImage}"/>` : ""}

<meta name="robots" content="max-image-preview:large" />
<meta name="googlebot" content="max-image-preview:large" />
${authorProfileUrl ? `<link rel="author" href="${authorProfileUrl}"/>` : ""}

<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>

<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css"/>
<style>
  .glass{background:rgba(0,0,0,.72);backdrop-filter:blur(14px)}
  .card{background:rgba(0,0,0,.48);border:1px solid rgba(255,255,255,.10)}
  .prose a{color:#38bdf8}
</style>
</head>
<body class="bg-slate-950 text-slate-100">
<header class="sticky top-0 z-50 border-b border-white/10 glass">
  <div class="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
    <a href="/" class="font-extrabold text-xl tracking-tight">NEWS<span class="text-sky-400">.ULTRA</span></a>
    <nav class="text-sm text-slate-300 flex gap-2">
      <a class="px-3 py-2 rounded-xl hover:bg-white/10" href="/articles.html"><i class="bi bi-grid-1x2"></i> Articles</a>
      <a class="px-3 py-2 rounded-xl hover:bg-white/10" href="/article.html?slug=${encodeURIComponent(a.slug)}"><i class="bi bi-book"></i> Reader</a>
    </nav>
  </div>
</header>

<main class="max-w-4xl mx-auto px-4 py-8">
  <article class="card rounded-3xl p-6">
    <div class="text-xs text-slate-400 flex flex-wrap gap-2 items-center">
      <span class="px-2 py-1 rounded bg-white/5 border border-white/10">${escapeHtml(a.category || "General")}</span>
      ${a.subcategory ? `<span class="px-2 py-1 rounded bg-white/5 border border-white/10">${escapeHtml(a.subcategory)}</span>` : ""}
      <span class="ml-auto">${a.publishedAt ? escapeHtml(new Date(a.publishedAt).toLocaleString()) : ""}</span>
    </div>

    <h1 class="mt-4 text-3xl md:text-5xl font-black leading-tight">${escapeHtml(title)}</h1>
    ${desc ? `<p class="mt-3 text-slate-300">${escapeHtml(desc)}</p>` : ""}

    <div class="mt-4 text-sm text-slate-300">
      <span class="text-slate-400">By</span>
      ${authorProfileUrl ? `<a class="text-sky-300 hover:underline" href="/profile.html?u=${encodeURIComponent(authorUsername)}">${escapeHtml(authorName)}</a>` : `${escapeHtml(authorName)}`}
    </div>

    ${ogImage ? `<img class="mt-6 w-full rounded-3xl border border-white/10" src="${ogImage}" alt="cover"/>` : ""}

    <div class="mt-7 card rounded-3xl p-6">
      <div class="prose prose-invert max-w-none">${bodyHtml}</div>
    </div>

    <div class="mt-6 flex gap-2 flex-wrap">
      <a class="px-4 py-2 rounded-xl bg-sky-500/25 border border-sky-400/30 hover:bg-sky-500/35 text-sm" href="/article.html?slug=${encodeURIComponent(a.slug)}">Open interactive</a>
      <a class="px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-sm" href="/rss.xml">RSS</a>
      <a class="px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-sm" href="/sitemap.xml">Sitemap</a>
    </div>
  </article>
</main>
</body>
</html>`);
});

// ==============================
// Editor API
// ==============================
app.get("/api/editor/mine", requireRole(["admin", "editor", "author"]), async (req, res) => {
  const uid = req.user.uid;
  const q = safeText(req.query.q, 120);
  const filter = req.user.role === "admin" ? {} : { authorId: uid };

  const list = await Article.find(q ? { ...filter, $text: { $search: q } } : filter, q ? { score: { $meta: "textScore" } } : {})
    .sort(q ? { score: { $meta: "textScore" } } : { updatedAt: -1 })
    .limit(400)
    .select("title slug status category subcategory publishedAt views likes commentsCount authorName updatedAt")
    .lean();

  res.json({ ok: true, items: list });
});

app.get("/api/editor/articles/:id", requireRole(["admin", "editor", "author"]), async (req, res) => {
  const id = safeText(req.params.id, 64);
  const uid = req.user.uid;

  const a = await Article.findById(id).lean();
  if (!a) return res.status(404).json({ error: "Not found" });

  if (req.user.role !== "admin" && String(a.authorId) !== String(uid)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  res.json({ ok: true, item: a });
});

// create/update draft
app.post("/api/editor/articles/upsert", requireRole(["admin", "editor", "author"]), async (req, res) => {
  try {
    const uid = req.user.uid;
    const body = req.body || {};
    const id = safeText(body.id, 64);

    const title = safeText(body.title, 200);
    if (!title || title.length < 3) return res.status(400).json({ error: "Title required" });

    const author = await Author.findById(uid).lean();
    const authorName = [author?.firstName, author?.lastName].filter(Boolean).join(" ").trim() || author?.username || "Author";
    const authorUsername = author?.username || "";

    const doc = {
      title,
      excerpt: safeText(body.excerpt, 300),
      contentHtml: sanitizeRichHtml(safeText(body.contentHtml, 200000)),

      coverUrl: safeText(body.coverUrl, 2000),
      coverPublicId: safeText(body.coverPublicId, 500),

      category: safeText(body.category || "General", 60) || "General",
      subcategory: safeText(body.subcategory, 60),
      tags: Array.isArray(body.tags)
        ? body.tags.map((t) => safeText(t, 30)).filter(Boolean).slice(0, 20)
        : safeText(body.tags || "", 300).split(",").map((t) => safeText(t, 30)).filter(Boolean).slice(0, 20),

      youtubeUrl: safeText(body.youtubeUrl, 2000),
      instagramUrl: safeText(body.instagramUrl, 2000),
      telegramUrl: safeText(body.telegramUrl, 2000),

      authorId: author?._id,
      authorName,
      authorUsername,
    };

    if (!id) {
      doc.slug = await ensureUniqueSlug(title);
      doc.status = "draft";
      doc.publishedAt = null;

      const created = await Article.create(doc);
      return res.json({ ok: true, id: String(created._id), slug: created.slug });
    }

    const existing = await Article.findById(id);
    if (!existing) return res.status(404).json({ error: "Not found" });

    if (req.user.role !== "admin" && String(existing.authorId) !== String(uid)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    // keep slug stable unless empty
    if (!existing.slug) existing.slug = await ensureUniqueSlug(existing.title || title);

    await Article.updateOne({ _id: id }, { $set: doc });
    const updated = await Article.findById(id).lean();

    res.json({ ok: true, id: String(updated._id), slug: updated.slug });
  } catch (e) {
    res.status(500).json({ error: "Upsert failed", details: String(e.message || e) });
  }
});

app.post("/api/editor/articles/:id/publish", requireRole(["admin", "editor", "author"]), async (req, res) => {
  const id = safeText(req.params.id, 64);
  const uid = req.user.uid;

  const a = await Article.findById(id);
  if (!a) return res.status(404).json({ error: "Not found" });

  if (req.user.role !== "admin" && String(a.authorId) !== String(uid)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  if (!a.slug) a.slug = await ensureUniqueSlug(a.title || "news");
  a.status = "published";
  a.publishedAt = a.publishedAt || new Date();

  await a.save();
  res.json({ ok: true });
});

app.post("/api/editor/articles/:id/schedule", requireRole(["admin", "editor", "author"]), async (req, res) => {
  const id = safeText(req.params.id, 64);
  const uid = req.user.uid;

  const iso = safeText(req.body?.publishedAt, 80);
  const dt = new Date(iso);
  if (isNaN(dt.getTime())) return res.status(400).json({ error: "publishedAt invalid" });

  const a = await Article.findById(id);
  if (!a) return res.status(404).json({ error: "Not found" });

  if (req.user.role !== "admin" && String(a.authorId) !== String(uid)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  if (!a.slug) a.slug = await ensureUniqueSlug(a.title || "news");
  a.status = "scheduled";
  a.publishedAt = dt;

  await a.save();
  res.json({ ok: true });
});

// Auto-publish scheduled (every 30s)
setInterval(async () => {
  try {
    const now = new Date();
    await Article.updateMany({ status: "scheduled", publishedAt: { $lte: now } }, { $set: { status: "published" } });
  } catch {}
}, 30_000);

// ==============================
// Profile + Authors
// ==============================
app.patch("/api/profile", requireRole(["admin", "editor", "author"]), async (req, res) => {
  const uid = req.user.uid;

  const patch = {
    firstName: safeText(req.body?.firstName, 60),
    lastName: safeText(req.body?.lastName, 60),
    email: safeText(req.body?.email, 120),
    phone: safeText(req.body?.phone, 60),
    bio: safeText(req.body?.bio, 800),
  };

  await Author.updateOne({ _id: uid }, { $set: patch });
  res.json({ ok: true });
});

app.post("/api/profile/avatar", requireRole(["admin", "editor", "author"]), async (req, res) => {
  const uid = req.user.uid;
  const avatarUrl = safeText(req.body?.avatarUrl, 2000);
  const avatarPublicId = safeText(req.body?.avatarPublicId, 500);
  if (!avatarUrl) return res.status(400).json({ error: "avatarUrl required" });

  await Author.updateOne({ _id: uid }, { $set: { avatarUrl, avatarPublicId } });
  res.json({ ok: true });
});

// Public author profile (username) + stats + follow status
app.get("/api/authors/:username", async (req, res) => {
  const username = safeText(req.params.username, 60);
  const guestId = req.cookies.guestId;

  const a = await Author.findOne({ username, isActive: true })
    .select("username role firstName lastName bio avatarUrl")
    .lean();
  if (!a) return res.status(404).json({ error: "Not found" });

  const statsAgg = await Article.aggregate([
    { $match: { authorId: a._id, status: "published", publishedAt: { $lte: new Date() } } },
    { $group: { _id: "$authorId", posts: { $sum: 1 }, views: { $sum: "$views" }, likes: { $sum: "$likes" } } }
  ]);

  const stats = statsAgg?.[0] || { posts: 0, views: 0, likes: 0 };
  const isFollowing = !!(await Follow.findOne({ authorId: a._id, guestId }).lean());

  res.json({
    ok: true,
    isFollowing,
    author: {
      id: String(a._id),
      role: a.role,
      username: a.username,
      firstName: a.firstName || "",
      lastName: a.lastName || "",
      bio: a.bio || "",
      avatarUrl: a.avatarUrl || "",
      stats,
    }
  });
});

// Author articles
app.get("/api/authors/:username/articles", async (req, res) => {
  const username = safeText(req.params.username, 60);
  const sort = safeText(req.query.sort || "latest", 20);

  const au = await Author.findOne({ username, isActive: true }).lean();
  if (!au) return res.status(404).json({ error: "Author not found" });

  const sortMap = {
    latest: { publishedAt: -1, createdAt: -1 },
    views: { views: -1, publishedAt: -1 },
    likes: { likes: -1, publishedAt: -1 },
    comments: { commentsCount: -1, publishedAt: -1 },
  };

  const items = await Article.find({
    authorId: au._id,
    status: "published",
    publishedAt: { $lte: new Date() }
  })
    .sort(sortMap[sort] || sortMap.latest)
    .limit(30)
    .select("title slug excerpt coverUrl category subcategory publishedAt views likes commentsCount authorName authorUsername")
    .lean();

  res.json({ ok: true, items });
});

// Follow toggle
app.post("/api/authors/:id/follow", async (req, res) => {
  const authorId = req.params.id;
  const guestId = req.cookies.guestId;

  try {
    await Follow.create({ authorId, guestId });
    return res.json({ ok: true, following: true });
  } catch {
    const del = await Follow.deleteOne({ authorId, guestId });
    if (del.deletedCount) return res.json({ ok: true, following: false });
    return res.status(500).json({ error: "Follow toggle failed" });
  }
});

// ==============================
// Admin API (minimal) — authors/articles/stats
// ==============================
app.post("/api/admin/authors", requireRole(["admin"]), async (req, res) => {
  const username = safeText(req.body?.username, 50);
  const password = String(req.body?.password || "");
  const role = safeText(req.body?.role || "author", 20);

  if (!username || username.length < 3) return res.status(400).json({ error: "username required" });
  if (!password || password.length < 4) return res.status(400).json({ error: "password min 4" });
  if (!["admin", "editor", "author"].includes(role)) return res.status(400).json({ error: "invalid role" });

  const exists = await Author.findOne({ username });
  if (exists) return res.status(409).json({ error: "username exists" });

  const created = await Author.create({
    username,
    passwordHash: sha256(password),
    role,
    firstName: safeText(req.body?.firstName, 60),
    lastName: safeText(req.body?.lastName, 60),
    email: safeText(req.body?.email, 120),
    phone: safeText(req.body?.phone, 60),
    bio: safeText(req.body?.bio, 400),
    isActive: true,
  });

  res.json({ ok: true, id: String(created._id) });
});

app.get("/api/admin/authors", requireRole(["admin"]), async (req, res) => {
  const items = await Author.find({})
    .sort({ createdAt: -1 })
    .limit(200)
    .select("username role firstName lastName email phone isActive createdAt")
    .lean();
  res.json({ ok: true, items });
});

app.get("/api/admin/articles", requireRole(["admin"]), async (req, res) => {
  const q = safeText(req.query.q, 120);
  const filter = q ? { $text: { $search: q } } : {};
  const items = await Article.find(filter, q ? { score: { $meta: "textScore" } } : {})
    .sort(q ? { score: { $meta: "textScore" } } : { updatedAt: -1 })
    .limit(400)
    .select("title slug status category subcategory publishedAt views likes commentsCount authorName updatedAt")
    .lean();

  res.json({ ok: true, items });
});

app.delete("/api/admin/articles/:id", requireRole(["admin"]), async (req, res) => {
  const id = req.params.id;

  const a = await Article.findById(id);
  if (!a) return res.status(404).json({ error: "Not found" });

  if (a.coverPublicId && process.env.CLOUDINARY_CLOUD_NAME) {
    try { await cloudinary.uploader.destroy(a.coverPublicId, { resource_type: "image" }); } catch {}
  }

  await Like.deleteMany({ articleId: id });
  await Comment.deleteMany({ articleId: id });
  await View.deleteMany({ articleId: id });
  await Article.deleteOne({ _id: id });

  res.json({ ok: true });
});

// Simple stats for charts
app.get("/api/admin/stats", requireRole(["admin"]), async (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days || "14", 10) || 14, 7), 60);
  const from = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const totalArticles = await Article.countDocuments({});
  const publishedArticles = await Article.countDocuments({ status: "published" });
  const totalAuthors = await Author.countDocuments({});

  const totalViews = await Article.aggregate([{ $group: { _id: null, s: { $sum: "$views" } } }]);
  const totalLikes = await Article.aggregate([{ $group: { _id: null, s: { $sum: "$likes" } } }]);
  const totalComments = await Article.aggregate([{ $group: { _id: null, s: { $sum: "$commentsCount" } } }]);

  // basic series (views/likes/comments by day) from View/Like/Comment collections
  const dayKeys = [];
  for (let i = days - 1; i >= 0; i--) {
    dayKeys.push(new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10));
  }

  const vAgg = await View.aggregate([
    { $match: { createdAt: { $gte: from } } },
    { $group: { _id: "$dayKey", c: { $sum: 1 } } },
  ]);
  const lAgg = await Like.aggregate([
    { $match: { createdAt: { $gte: from } } },
    { $group: { _id: { $substrBytes: ["$createdAt", 0, 10] }, c: { $sum: 1 } } },
  ]);
  const cAgg = await Comment.aggregate([
    { $match: { createdAt: { $gte: from } } },
    { $group: { _id: { $substrBytes: ["$createdAt", 0, 10] }, c: { $sum: 1 } } },
  ]);

  const vmap = Object.fromEntries(vAgg.map(x => [x._id, x.c]));
  const lmap = Object.fromEntries(lAgg.map(x => [x._id, x.c]));
  const cmap = Object.fromEntries(cAgg.map(x => [x._id, x.c]));

  const series = dayKeys.map(k => ({ day: k, views: vmap[k] || 0, likes: lmap[k] || 0, comments: cmap[k] || 0 }));

  res.json({
    ok: true,
    kpis: {
      totalArticles,
      publishedArticles,
      totalAuthors,
      totalViews: totalViews[0]?.s || 0,
      totalLikes: totalLikes[0]?.s || 0,
      totalComments: totalComments[0]?.s || 0,
    },
    series,
  });
});

// ==============================
// RSS + Sitemap + Robots (Google News uchun)
// ==============================
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send(`User-agent: *
Allow: /

Sitemap: ${BASE_URL}/sitemap.xml
`);
});

app.get("/sitemap.xml", async (req, res) => {
  const items = await Article.find({ status: "published", publishedAt: { $lte: new Date() } })
    .sort({ publishedAt: -1 })
    .limit(5000)
    .select("slug updatedAt")
    .lean();

  const urls = items.map(it => {
    const loc = `${BASE_URL}/a/${it.slug}`;
    const lastmod = (it.updatedAt ? new Date(it.updatedAt) : new Date()).toISOString();
    return `<url><loc>${loc}</loc><lastmod>${lastmod}</lastmod></url>`;
  }).join("");

  res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>`);
});

app.get("/rss.xml", async (req, res) => {
  const items = await Article.find({ status: "published", publishedAt: { $lte: new Date() } })
    .sort({ publishedAt: -1 })
    .limit(50)
    .select("title slug excerpt publishedAt")
    .lean();

  const xmlItems = items.map(it => {
    const link = `${BASE_URL}/a/${it.slug}`;
    const pubDate = it.publishedAt ? new Date(it.publishedAt).toUTCString() : new Date().toUTCString();
    return `<item>
<title><![CDATA[${it.title || "News"}]]></title>
<link>${link}</link>
<guid>${link}</guid>
<pubDate>${pubDate}</pubDate>
<description><![CDATA[${it.excerpt || ""}]]></description>
</item>`;
  }).join("");

  res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>${escapeHtml(SITE_NAME)}</title>
<link>${BASE_URL}</link>
<description>${escapeHtml(SITE_NAME)} RSS feed</description>
${xmlItems}
</channel>
</rss>`);
});

// ==============================
// Start
// ==============================
connectMongo()
  .then(async () => {
    await ensureDefaultAdmin();
    app.listen(PORT, () => console.log(`✅ Server running: ${BASE_URL}`));
  })
  .catch((e) => {
    console.error("❌ Mongo connect error:", e);
    process.exit(1);
  });
