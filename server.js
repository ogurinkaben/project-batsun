require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const mongoose = require("mongoose");
const crypto = require("crypto");
const Download = require("./models/Download");

const app = express();
const PORT = process.env.PORT || 3000;
const BASE64_FILE = process.env.BASE64_FILE || "";
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://localhost:27017/download_tracker";

app.use(
  helmet({
    contentSecurityPolicy: false, // we'll manually set CSP later per request
  })
);
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Connect MongoDB ---
const startDb = async () => {
  await mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  console.log("✅ Connected to MongoDB");
};

startDb().catch((err) => {
  console.error("DB connection error:", err);
  process.exit(1);
});

// --- Helpers ---
const isValidEmail = (email) =>
  typeof email === "string" && /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email);

const escapeHtml = (str) =>
  String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

// --- Routes ---
app.get("/", (req, res) => {
  const { email } = req.query;
  if (email && isValidEmail(email)) {
    // auto-trigger download
    res.redirect(`/request-download?email=${encodeURIComponent(email)}`);
    return;
  }

  res.send(`
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8"/>
        <title>Download</title>
      </head>
      <body>
        <h2>Download file</h2>
        <form method="GET" action="/request-download">
          <label>
            Email:
            <input type="email" name="email" required />
          </label>
          <button type="submit">Get file</button>
        </form>
      </body>
    </html>
  `);
});

app.get("/request-download", async (req, res) => {
  try {
    const rawEmail = req.query.email || "";
    const email = decodeURIComponent(rawEmail.trim());

    const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!isValidEmail(email)) {
      return res.status(400).send("Invalid email address");
    }

    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
    const userAgent = req.get("User-Agent") || "";

    await Download.create({
      email,
      downloadedAt: new Date(),
      ip,
      userAgent,
    });

    const nonce = crypto.randomBytes(16).toString("base64");
    res.setHeader(
      "Content-Security-Policy",
      `default-src 'self'; script-src 'nonce-${nonce}'`
    );

    const filename = "downloaded_file.pdf";

    // Send minimal HTML with inline script to trigger download
    res.send(`
<!doctype html>
<html>
  <head><meta charset="utf-8"/></head>
  <body>
    <script nonce="${nonce}">
      (function(){
        const b64 = "${BASE64_FILE}";
        const binaryString = atob(b64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
        const blob = new Blob([bytes], { type: "application/pdf" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "${filename}";
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
          URL.revokeObjectURL(a.href);
          a.remove();
        }, 1000);
      })();
    </script>
  </body>
</html>
    `);
  } catch (err) {
    console.error("request-download error:", err);
    res.status(500).send("Server error");
  }
});

app.get("/api/downloads", async (req, res) => {
  try {
    const items = await Download.find()
      .sort({ downloadedAt: -1 })
      .limit(200)
      .lean();
    res.json(items);
  } catch (err) {
    console.error("api/downloads error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${PORT}`);
});
