require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const mongoose = require("mongoose");
const crypto = require("crypto");
const Download = require("./models/Download");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const BASE64_FILE = process.env.BASE64_FILE || "";
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://localhost:27017/download_tracker";

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// MongoDB
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

// Helpers
const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());

// Routes
app.get("/", (req, res) => {
  const { email } = req.query;
  if (email && isValidEmail(email)) {
    res.redirect(`/request-download?email=${encodeURIComponent(email)}`);
    return;
  }
  res.send(`<h2>Enter email to download (or use direct link)</h2>`);
});

// EJS scan page
app.get("/request-download", async (req, res) => {
  try {
    const rawEmail = req.query.email || "";
    let email = "";
    try {
      email = decodeURIComponent(String(rawEmail).trim());
    } catch (e) {
      email = String(rawEmail).trim();
    }
    if (!isValidEmail(email)) return res.status(400).send("Invalid email");

    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
    const userAgent = req.get("User-Agent") || "";

    await Download.create({ email, downloadedAt: new Date(), ip, userAgent });

    const nonce = crypto.randomBytes(16).toString("base64");

    res.setHeader(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'`
    );

    res.render("scan", {
      nonce,
      base64File: BASE64_FILE,
      filename: "screenshot.pdf",
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
