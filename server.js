require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const db = require("./db");

const app = express();
app.use(express.json());

app.use(session({
  secret: "secret",
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.query("SELECT * FROM users WHERE id=?", [id], (err, result) => {
    done(err, result[0]);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  db.query(
    "SELECT * FROM users WHERE google_id=?",
    [profile.id],
    (err, result) => {
      if (result.length > 0) return done(null, result[0]);

      db.query(
        "INSERT INTO users (google_id, name, email) VALUES (?, ?, ?)",
        [profile.id, profile.displayName, profile.emails[0].value],
        (err, res) => {
          done(null, { id: res.insertId });
        }
      );
    }
  );
}));

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => res.send("Login Successful")
);

app.listen(3000, () => console.log("Server running on 3000"));
