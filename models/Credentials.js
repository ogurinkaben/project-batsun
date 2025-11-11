const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const credentialsSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  },
  password: {
    type: String,
    required: true,
  },
  userAgent: {
    type: String,
    default: "",
  },
  ip: {
    type: String,
    default: "",
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Hash password before saving
credentialsSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    try {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    } catch (err) {
      return next(err);
    }
  }
  // Always update the updatedAt timestamp
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model("Credentials", credentialsSchema);
