const express = require("express")
const session = require("express-session")
const hbs = require("hbs")
const jwt = require("jsonwebtoken")

const app = express()

const IDP = "https://idp.example"
const IDP_PUBLIC_KEY = "idp_public_key"

const accounts = {
  "fedcm@example.com": {
    id: "1001",
    name: "Fed CM",
    email: "fedcm@example.com",
    picture: `${IDP}/img/icon.png`,
    approved_clients: ["https://rp.example"]
  }
}

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
    console.log(`>> \x1b[34m${res.statusCode} ${req.method} ${req.path}\x1b[0m`)
  })
  next()
})

app.get("/", sessionCheck, (req, res) => {
  const { user } = req.session
  res.render("index", { user })
})

app.get("/.well-known/web-identity", (req, res) => {
  res.header("access-control-allow-origin", "*")
  res.json({
    provider_urls: [`${IDP}/fedcm.json`]
  })
})

app.get("/fedcm.json", (req, res) => {
  if (req.get("sec-fetch-dest") !== "webidentity") {
    return res.status(400).json({ error: "sec-fetch-dest is not webidentity" })
  }
  res.header("access-control-allow-origin", "*")
  res.json({
    accounts_endpoint: "/accounts.json",
    client_metadata_endpoint: "/client_metadata.json",
    id_assertion_endpoint: "/id_assertion.json",
    revocation_endpoint: "/revocation.json",
    signin_url: "/",
    branding: {
      background_color: "#54a4ff",
      color: "#ffffff",
      icons: [
        {
          url: `${IDP}/img/fed.png`
        }
      ]
    }
  })
})

app.get("/accounts.json", (req, res) => {
  if (req.get("sec-fetch-dest") !== "webidentity") {
    return res.status(400).json({ error: "sec-fetch-dest is not webidentity" })
  }
  const { user } = req.session
  if (user === undefined) {
    return res.status(401).json({ error: "session expired" })
  }
  res.json({ accounts: [user] })
})

app.post("/id_assertion.json", (req, res) => {
  if (req.get("sec-fetch-dest") !== "webidentity") {
    return res.status(400).json({ error: "sec-fetch-dest is not webidentity" })
  }
  const { user } = req.session
  if (user === undefined) {
    return res.status(401).json({ error: "session expired" })
  }
  const body = req.body

  if (user.id !== body.account_id) {
    return res.status(400).json({ error: "invalid account_id" })
  }

  if (req.get("origin") !== body.client_id) {
    return res.status(400).json({ error: "invalid client_id" })
  }

  if (user.approved_clients.includes(body.client_id) === false) {
    return res.status(400).json({ error: "client_id is not approved_clients" })
  }

  const token = jwt.sign(
    {
      iss: IDP,
      sub: user.id,
      aud: body.client_id,
      nonce: body.nonce,
      exp: new Date().getTime() + 1000 * 60 * 60, // 1h
      iat: new Date().getTime(),
      name: user.name,
      email: user.email,
      picture: user.picture
    },
    IDP_PUBLIC_KEY
  )
  return res.json({
    token
  })
})

app.get("/login", (req, res) => {
  res.render("login")
})

app.post("/sessions/new", (req, res) => {
  const { username, password } = req.body // ignore password
  const user = accounts[username]
  console.log(`login as ${user.name}`)
  req.session.user = user
  res.header("idp-signin-status", "action=signin")
  res.redirect("/")
})

app.get("/logout", (req, res) => {
  req.session.destroy()
  res.redirect("/")
})

const port = process.env.PORT || 5000
const listener = app.listen(port, () => {
  console.log(`IDP server starts on port ${listener.address().port}`)
})
