const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const Joi = require("joi")
const rateLimit = require("express-rate-limit")
const app = express()
app.use(express.json())

const SECRET = "secret"
const REFRESH_SECRET = "refreshsecret"

let users = []
let posts = []
let comments = []
let refreshTokens = []

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 })
app.use(limiter)

const auth = (req, res, next) => {
  const token = req.headers.authorization
  if (!token) return res.sendStatus(401)
  try {
    const decoded = jwt.verify(token, SECRET)
    req.user = decoded
    next()
  } catch {
    res.sendStatus(403)
  }
}

const schemas = {
  register: Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(5).required()
  }),
  login: Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required()
  }),
  post: Joi.object({
    title: Joi.string().required(),
    content: Joi.string().required(),
    tags: Joi.array().items(Joi.string())
  }),
  comment: Joi.object({
    comment: Joi.string().required()
  })
}

app.post("/register", async (req, res) => {
  const { error } = schemas.register.validate(req.body)
  if (error) return res.status(400).send(error.message)
  const exists = users.find(u => u.email === req.body.email)
  if (exists) return res.status(400).send("User exists")
  const hash = await bcrypt.hash(req.body.password, 10)
  const user = { id: Date.now(), name: req.body.name, email: req.body.email, passwordHash: hash, role: "user", createdAt: new Date() }
  users.push(user)
  res.send(user)
})

app.post("/login", async (req, res) => {
  const { error } = schemas.login.validate(req.body)
  if (error) return res.status(400).send(error.message)
  const user = users.find(u => u.email === req.body.email)
  if (!user) return res.status(400).send("Invalid")
  const valid = await bcrypt.compare(req.body.password, user.passwordHash)
  if (!valid) return res.status(400).send("Invalid")
  const accessToken = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: "15m" })
  const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET)
  refreshTokens.push(refreshToken)
  res.send({ accessToken, refreshToken })
})

app.post("/token", (req, res) => {
  const { token } = req.body
  if (!token || !refreshTokens.includes(token)) return res.sendStatus(403)
  try {
    const user = jwt.verify(token, REFRESH_SECRET)
    const accessToken = jwt.sign({ id: user.id }, SECRET, { expiresIn: "15m" })
    res.send({ accessToken })
  } catch {
    res.sendStatus(403)
  }
})

app.post("/posts", auth, (req, res) => {
  const { error } = schemas.post.validate(req.body)
  if (error) return res.status(400).send(error.message)
  const duplicate = posts.find(p => p.title === req.body.title)
  if (duplicate) return res.status(400).send("Duplicate title")
  const post = { id: Date.now(), userId: req.user.id, title: req.body.title, content: req.body.content, tags: req.body.tags || [], createdAt: new Date() }
  posts.push(post)
  res.send(post)
})

app.put("/posts/:id", auth, (req, res) => {
  const post = posts.find(p => p.id == req.params.id)
  if (!post) return res.sendStatus(404)
  if (post.userId !== req.user.id) return res.sendStatus(403)
  post.title = req.body.title || post.title
  post.content = req.body.content || post.content
  res.send(post)
})

app.delete("/posts/:id", auth, (req, res) => {
  const index = posts.findIndex(p => p.id == req.params.id)
  if (index === -1) return res.sendStatus(404)
  const post = posts[index]
  if (post.userId !== req.user.id && req.user.role !== "admin") return res.sendStatus(403)
  posts.splice(index, 1)
  res.send("Deleted")
})

app.post("/posts/:id/comments", auth, (req, res) => {
  const { error } = schemas.comment.validate(req.body)
  if (error) return res.status(400).send(error.message)
  const post = posts.find(p => p.id == req.params.id)
  if (!post) return res.sendStatus(404)
  const comment = { id: Date.now(), postId: post.id, userId: req.user.id, comment: req.body.comment, createdAt: new Date() }
  comments.push(comment)
  res.send(comment)
})

app.get("/posts", (req, res) => {
  const result = posts.map(p => ({
    ...p,
    comments: comments.filter(c => c.postId === p.id)
  }))
  res.send(result)
})

app.get("/trending", (req, res) => {
  const sorted = posts.map(p => ({
    ...p,
    count: comments.filter(c => c.postId === p.id).length
  })).sort((a, b) => b.count - a.count)
  res.send(sorted)
})

app.listen(3000)