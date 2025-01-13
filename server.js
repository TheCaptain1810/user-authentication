const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(
  session({
    secret: "secretKey", // Replace with a secure secret key
    resave: false,
    saveUninitialized: false,
  })
);

// In-memory user store
const users = [];

// Register endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password are required" });

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.status(201).json({ message: "User registered successfully" });
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(400).json({ error: "Invalid credentials" });

  req.session.user = { username };
  res.json({ message: "Login successful" });
});

// Profile endpoint (protected)
app.get("/profile", (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ error: "Unauthorized access" });

  res.json({ profile: req.session.user });
});

// Logout endpoint
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Failed to log out" });
    res.json({ message: "Logged out successfully" });
  });
});

// Start the server
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
