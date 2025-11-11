// models/PhishAttempt.js
const mongoose = require("mongoose");

const phishAttemptSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  },
  event: {
    type: String,
    enum: ["view", "click", "submit"],
    required: true,
  },
  userAgent: { type: String, default: "" },
  ip: { type: String, default: "" },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }, // optional extra info
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("PhishAttempt", phishAttemptSchema);
