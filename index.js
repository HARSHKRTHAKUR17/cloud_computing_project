import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import pkg from "pg";

const { Client } = pkg;
env.config();

// PostgreSQL connection (RDS)
const client = new Client({
  connectionString: process.env.RDS_DB,
  ssl: {
    rejectUnauthorized: false
  }
});

try {
  await client.connect();
  console.log("Connected to RDS PostgreSQL");

  await client.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    )
  `);
  console.log("Table 'users' is ready");
} catch (err) {
  console.error("DB setup failed:", err);
  process.exit(1);
}

// Express setup
const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get("/secrets", (req, res) => {
  res.render("secrets.ejs");
});

app.get("/music",(req, res)=>{
  res.render("music.ejs")
});

app.get("/arts",(req, res)=>{
  res.render("arts.ejs")
;})

app.get("/drumkit",(req, res)=>{
  res.render("drumkit.ejs")
});

app.get("/paint",(req, res)=>{
  res.render("paint.ejs")
});

app.get("/science",(req, res)=>{
  res.redirect("https://fold.it/play")
;})

// Registration
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await client.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      return res.redirect("/login");
    }

    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) return res.send("Server error");

      const insertResult = await client.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
        [email, hash]
      );

      const user = insertResult.rows[0];
      req.login(user, (err) => {
        if (err) return res.redirect("/login");
        res.redirect("/secrets");
      });
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).send("Internal server error");
  }
});

// Login
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Passport strategy
passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await client.query("SELECT * FROM users WHERE email = $1", [username]);

      if (result.rows.length === 0) return cb(null, false);

      const user = result.rows[0];
      bcrypt.compare(password, user.password, (err, valid) => {
        if (err) return cb(err);
        if (valid) return cb(null, user);
        else return cb(null, false);
      });
    } catch (err) {
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => cb(null, user.id));

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await client.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err, null);
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
