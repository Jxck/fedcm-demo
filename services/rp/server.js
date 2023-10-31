const express = require("express")
const session = require("express-session")
const hbs = require("hbs")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")

const app = express()

app.set("view engine", "html")
app.engine("html", hbs.__express)
app.set("views", "./views")

app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(
  express.static("public", {
    setHeaders: (res) => {
      res.header("access-control-allow-origin", "*")
      res.header("access-control-allow-methods", "get")
    }
  })
)
app.use(
  session({
    name: "__Host-session",
    secret: "secret",
    resave: true,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 30 * 1000
    }
  })
)

function sessionCheck(req, res, next) {
  const { user } = req.session
  if (user) return next()
  return res.redirect("/login")
}

app.use((req, res, next) => {
  res.addListener("finish", (e) => {
    console.log(`>> \x1b[35m${res.statusCode} ${req.method} ${req.path}\x1b[0m`)
  })
  next()
})

app.get("/", (req, res) => {
  const nonce = crypto.randomBytes(16).toString("hex")
  req.session.user = {
    nonce
  }
  res.render("index", { nonce })
})

app.post("/verify", (req, res) => {
  const { token } = req.body
  const user = req.session.user
  if (user === undefined) {
    return res.status(401).json({ error: "session expired" })
  }
  const { nonce } = user
  if (nonce === undefined) {
    return res.status(400).json({ error: "nonce missing" })
  }
  try {
    const verified = jwt.verify(token, "idp_public_key", {
      issuer: "https://idp.example",
      nonce,
      audience: "https://rp.example"
    })
    const user = {
      id: verified.sub,
      name: verified.name,
      email: verified.email,
      picture: verified.picture
    }
    res.json(user)
  } catch (err) {
    console.error(err)
    res.status(401).json({ error: "ID Token Verification Failed" })
  }
})

const port = process.env.PORT || 6000
const listener = app.listen(port, () => {
  console.log(`IDP server starts on port ${listener.address().port}`)
})
