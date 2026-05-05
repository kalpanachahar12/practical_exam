/**
 * Secure Blogging Platform API
 * Multi-User + JWT Auth (Single File)
 * 
 * Dependencies:
 *   npm install express bcryptjs jsonwebtoken joi express-rate-limit uuid
 * 
 * Run:
 *   node app.js
 */

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const rateLimit = require("express-rate-limit");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key_change_in_prod";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refresh_secret_key_change_in_prod";
const JWT_EXPIRES_IN = "15m";
const JWT_REFRESH_EXPIRES_IN = "7d";
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// IN-MEMORY DATA STORE (replace with DB in prod)
// ─────────────────────────────────────────────
const db = {
  users: [],         // { id, name, email, passwordHash, role, createdAt }
  posts: [],         // { id, userId, title, content, tags[], createdAt }
  comments: [],      // { id, postId, userId, comment, createdAt }
  refreshTokens: [], // valid refresh tokens
};

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: "Too many requests. Please try again later." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many auth attempts. Please try again later." },
});

app.use(globalLimiter);

// ─────────────────────────────────────────────
// VALIDATION SCHEMAS (Joi)
// ─────────────────────────────────────────────
const schemas = {
  register: Joi.object({
    name: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    role: Joi.string().valid("user", "admin").default("user"),
  }),

  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),

  post: Joi.object({
    title: Joi.string().min(3).max(150).required(),
    content: Joi.string().min(10).required(),
    tags: Joi.array().items(Joi.string()).default([]),
  }),

  comment: Joi.object({
    comment: Joi.string().min(1).max(500).required(),
  }),
};

// ─────────────────────────────────────────────
// MIDDLEWARE: Validate Request Body
// ─────────────────────────────────────────────
const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      error: "Validation failed",
      details: error.details.map((d) => d.message),
    });
  }
  req.body = value;
  next();
};

// ─────────────────────────────────────────────
// MIDDLEWARE: Authenticate JWT
// ─────────────────────────────────────────────
const authenticate = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid Authorization header." });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, role }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
};

// ─────────────────────────────────────────────
// MIDDLEWARE: Role-Based Access
// ─────────────────────────────────────────────
const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: "Access denied. Insufficient permissions." });
  }
  next();
};

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
const generateTokens = (user) => {
  const payload = { id: user.id, email: user.email, role: user.role };
  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  const refreshToken = jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });
  return { accessToken, refreshToken };
};

const findUser = (id) => db.users.find((u) => u.id === id);
const findPost = (id) => db.posts.find((p) => p.id === id);

// ─────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────

// POST /auth/register
app.post("/auth/register", authLimiter, validate(schemas.register), async (req, res) => {
  const { name, email, password, role } = req.body;

  const existing = db.users.find((u) => u.email === email);
  if (existing) {
    return res.status(409).json({ error: "Email already registered." });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: uuidv4(),
    name,
    email,
    passwordHash,
    role,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);

  return res.status(201).json({
    message: "User registered successfully.",
    user: { id: user.id, name, email, role, createdAt: user.createdAt },
  });
});

// POST /auth/login
app.post("/auth/login", authLimiter, validate(schemas.login), async (req, res) => {
  const { email, password } = req.body;

  const user = db.users.find((u) => u.email === email);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials." });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ error: "Invalid credentials." });
  }

  const { accessToken, refreshToken } = generateTokens(user);
  db.refreshTokens.push(refreshToken);

  return res.json({ accessToken, refreshToken });
});

// POST /auth/refresh
app.post("/auth/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token required." });
  }

  if (!db.refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ error: "Invalid refresh token." });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const user = findUser(decoded.id);
    if (!user) return res.status(403).json({ error: "User not found." });

    // Rotate refresh token
    db.refreshTokens = db.refreshTokens.filter((t) => t !== refreshToken);
    const tokens = generateTokens(user);
    db.refreshTokens.push(tokens.refreshToken);

    return res.json(tokens);
  } catch {
    return res.status(403).json({ error: "Invalid or expired refresh token." });
  }
});

// POST /auth/logout
app.post("/auth/logout", authenticate, (req, res) => {
  const { refreshToken } = req.body;
  db.refreshTokens = db.refreshTokens.filter((t) => t !== refreshToken);
  return res.json({ message: "Logged out successfully." });
});

// ─────────────────────────────────────────────
// POST ROUTES
// ─────────────────────────────────────────────

// GET /posts — all posts with their comments
app.get("/posts", authenticate, (req, res) => {
  const posts = db.posts.map((post) => ({
    ...post,
    author: (() => {
      const u = findUser(post.userId);
      return u ? { id: u.id, name: u.name } : null;
    })(),
    comments: db.comments
      .filter((c) => c.postId === post.id)
      .map((c) => ({
        ...c,
        author: (() => {
          const u = findUser(c.userId);
          return u ? { id: u.id, name: u.name } : null;
        })(),
      })),
  }));

  return res.json({ posts, total: posts.length });
});

// GET /posts/trending — sorted by comment count
app.get("/posts/trending", authenticate, (req, res) => {
  const getTrendingPosts = () => {
    return db.posts
      .map((post) => ({
        ...post,
        commentCount: db.comments.filter((c) => c.postId === post.id).length,
      }))
      .sort((a, b) => b.commentCount - a.commentCount);
  };

  return res.json({ trending: getTrendingPosts() });
});

// GET /posts/:id
app.get("/posts/:id", authenticate, (req, res) => {
  const post = findPost(req.params.id);
  if (!post) return res.status(404).json({ error: "Post not found." });

  const comments = db.comments
    .filter((c) => c.postId === post.id)
    .map((c) => ({
      ...c,
      author: (() => {
        const u = findUser(c.userId);
        return u ? { id: u.id, name: u.name } : null;
      })(),
    }));

  return res.json({ ...post, comments });
});

// POST /posts — create post
app.post("/posts", authenticate, validate(schemas.post), (req, res) => {
  const { title, content, tags } = req.body;

  const duplicate = db.posts.find(
    (p) => p.title.toLowerCase() === title.toLowerCase()
  );
  if (duplicate) {
    return res.status(409).json({ error: "A post with this title already exists." });
  }

  const post = {
    id: uuidv4(),
    userId: req.user.id,
    title,
    content,
    tags,
    createdAt: new Date().toISOString(),
  };
  db.posts.push(post);

  return res.status(201).json({ message: "Post created.", post });
});

// PUT /posts/:id — update post (owner only)
app.put("/posts/:id", authenticate, validate(schemas.post), (req, res) => {
  const post = findPost(req.params.id);
  if (!post) return res.status(404).json({ error: "Post not found." });

  if (post.userId !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "You can only edit your own posts." });
  }

  const { title, content, tags } = req.body;

  // Prevent duplicate titles (excluding current post)
  const duplicate = db.posts.find(
    (p) => p.title.toLowerCase() === title.toLowerCase() && p.id !== post.id
  );
  if (duplicate) {
    return res.status(409).json({ error: "A post with this title already exists." });
  }

  post.title = title;
  post.content = content;
  post.tags = tags;

  return res.json({ message: "Post updated.", post });
});

// DELETE /posts/:id — owner or admin
app.delete("/posts/:id", authenticate, (req, res) => {
  const postIndex = db.posts.findIndex((p) => p.id === req.params.id);
  if (postIndex === -1) return res.status(404).json({ error: "Post not found." });

  const post = db.posts[postIndex];

  if (post.userId !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "You can only delete your own posts." });
  }

  db.posts.splice(postIndex, 1);
  // Cascade delete comments
  db.comments = db.comments.filter((c) => c.postId !== req.params.id);

  return res.json({ message: "Post deleted." });
});

// ─────────────────────────────────────────────
// COMMENT ROUTES
// ─────────────────────────────────────────────

// POST /posts/:id/comments — add comment
app.post("/posts/:id/comments", authenticate, validate(schemas.comment), (req, res) => {
  const post = findPost(req.params.id);
  if (!post) return res.status(404).json({ error: "Post not found." });

  const comment = {
    id: uuidv4(),
    postId: post.id,
    userId: req.user.id,
    comment: req.body.comment,
    createdAt: new Date().toISOString(),
  };
  db.comments.push(comment);

  return res.status(201).json({ message: "Comment added.", comment });
});

// DELETE /comments/:id — owner or admin
app.delete("/comments/:id", authenticate, (req, res) => {
  const idx = db.comments.findIndex((c) => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Comment not found." });

  const comment = db.comments[idx];

  if (comment.userId !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "You can only delete your own comments." });
  }

  db.comments.splice(idx, 1);
  return res.json({ message: "Comment deleted." });
});

// ─────────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────────

// GET /admin/users — list all users (admin only)
app.get("/admin/users", authenticate, requireRole("admin"), (req, res) => {
  const users = db.users.map(({ passwordHash, ...rest }) => rest);
  return res.json({ users, total: users.length });
});

// ─────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    users: db.users.length,
    posts: db.posts.length,
    comments: db.comments.length,
  });
});

// ─────────────────────────────────────────────
// 404 FALLBACK
// ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});

// ─────────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error." });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Blogging API running on http://localhost:${PORT}`);
  console.log(`   Health:    GET  /health`);
  console.log(`   Register:  POST /auth/register`);
  console.log(`   Login:     POST /auth/login`);
  console.log(`   Posts:     GET  /posts`);
  console.log(`   Trending:  GET  /posts/trending\n`);
});

module.exports = app;