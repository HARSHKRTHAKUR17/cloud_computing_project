import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import pkg from "pg";
const { Client } = pkg;

// Load environment variables
env.config();

// PostgreSQL connection
const client = new Client({
  connectionString: process.env.NEON_DB,
});
await client.connect(); // Ensure DB connection before any query

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

// ROUTES
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

app.get("/music", (req, res) => {
  res.render("music.ejs");
});

app.get("/arts", (req, res) => {
  res.render("arts.ejs");
});

app.get("/drumkit", (req, res) => {
  res.render("drumkit.ejs");
});

app.get("/paint", (req, res) => {
  res.render("paint.ejs");
});

app.get("/science", (req, res) => {
  res.redirect("https://fold.it/play");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await client.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Hash error:", err);
          return res.send("Server error");
        }

        const insertResult = await client.query(
          "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
          [email, hash]
        );

        const user = insertResult.rows[0];

        req.login(user, (err) => {
          if (err) {
            console.error("Login error:", err);
            return res.redirect("/login");
          }
          res.redirect("/secrets");
        });
      });
    }
  } catch (err) {
    console.error("DB error:", err);
    res.status(500).send("Internal server error");
  }
});

// Passport setup
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

// Server start
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
