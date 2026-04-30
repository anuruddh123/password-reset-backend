const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const axios = require("axios");

dotenv.config();

const app = express();

// ================= CORS =================
app.use(cors({
  origin: ["http://localhost:3000", "https://pas-reset.netlify.app"],
  credentials: true
}));

app.use(express.json());

// ================= MODELS =================
const User = mongoose.model("User", new mongoose.Schema({
  email: String,
  password: String
}));

const ResetToken = mongoose.model("ResetToken", new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  token: String,
  expiresAt: Date,
  used: { type: Boolean, default: false }
}));

// ================= HEALTH CHECK =================
app.get("/", (req, res) => {
  res.status(200).send("API Running 🚀");
});

// ================= REGISTER =================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const exist = await User.findOne({ email });
    if (exist) return res.status(409).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    await User.create({ email, password: hash });

    res.json({ message: "Registered successfully" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= LOGIN =================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    res.json({ message: "Login successful" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= FORGOT PASSWORD (BREVO) =================
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = uuidv4();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await ResetToken.create({ userId: user._id, token, expiresAt });

    const resetLink = `${process.env.CLIENT_URL}/reset-password/${token}`;

    // 🔥 instant response
    res.json({ message: "Reset link sent to email" });

    // 🔥 async email (NO BLOCK)
    axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: {
          name: "Password Reset App",
          email: process.env.SENDER_EMAIL
        },
        to: [{ email }],
        subject: "Reset Password",
        htmlContent: `
          <h2>Reset Password</h2>
          <p>Click below:</p>
          <a href="${resetLink}">${resetLink}</a>
        `
      },
      {
        headers: {
          "api-key": process.env.BREVO_API_KEY,
          "Content-Type": "application/json"
        }
      }
    )
    .then(() => console.log("✅ Email sent"))
    .catch(err => console.log("❌ EMAIL ERROR:", err.response?.data || err.message));

  } catch (err) {
    console.log("❌ Forgot Error:", err.message);
  }
});

// ================= VERIFY TOKEN =================
app.post("/api/auth/verify-token", async (req, res) => {
  try {
    const { token } = req.body;

    const data = await ResetToken.findOne({ token, used: false });

    if (!data) return res.status(404).json({ error: "Invalid token" });

    if (new Date() > data.expiresAt)
      return res.status(401).json({ error: "Token expired" });

    res.json({ message: "Valid token" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= RESET PASSWORD =================
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const data = await ResetToken.findOne({ token, used: false });

    if (!data) return res.status(404).json({ error: "Invalid token" });

    if (new Date() > data.expiresAt)
      return res.status(401).json({ error: "Token expired" });

    const user = await User.findById(data.userId);

    const same = await bcrypt.compare(newPassword, user.password);
    if (same) return res.status(400).json({ error: "Use different password" });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    data.used = true;
    await data.save();

    res.json({ message: "Password reset successful" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= CONNECT DB + START SERVER =================
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");

    const PORT = process.env.PORT || 10000;

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 Server running on ${PORT}`);
    });

  })
  .catch(err => {
    console.log("❌ MongoDB Error:", err);
  });