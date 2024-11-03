const express = require("express");
const sql = require("mssql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());
const config = {
  user: "sa",
  password: "123",
  server: "localhost",
  database: "userdb",
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
};

// Đăng ký tài khoản
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const pool = await sql.connect(config);
    const result = await pool
      .request()
      .input("username", sql.VarChar, username)
      .input("email", sql.VarChar, email)
      .input("password", sql.VarChar, hashedPassword)
      .query(
        "INSERT INTO users (username, email, password) VALUES (@username, @email, @password)"
      );

    res.status(201).json({ message: "User registered" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Đăng nhập tài khoản
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const pool = await sql.connect(config);
    const result = await pool
      .request()
      .input("email", sql.VarChar, email)
      .query("SELECT * FROM users WHERE email = @email");

    if (result.recordset.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = result.recordset[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id }, "your_secret_key", {
      expiresIn: "1h",
    });
    res.status(200).json({ message: "Logged in successfully", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Middleware xác thực
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ message: "Access token missing" });

  jwt.verify(token, "your_secret_key", (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// Route protected
app.get("/profile", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Profile info", user: req.user });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
