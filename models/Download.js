const mongoose = require("mongoose");

const DownloadSchema = new mongoose.Schema({
  email: { type: String, required: true, index: true },
  downloadedAt: { type: Date, default: () => new Date() },
  ip: { type: String },
  userAgent: { type: String },
});

module.exports = mongoose.model("Download", DownloadSchema);
