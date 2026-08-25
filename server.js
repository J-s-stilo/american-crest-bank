const express = require("express");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(18,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      amount NUMERIC(18,2) NOT NULL,
      recipient TEXT,
      reference TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'successful',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS support_tickets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("Database ready.");
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  const token = header.substring(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

function makeReference() {
  return (
    "SIM-" +
    Date.now().toString(36).toUpperCase() +
    "-" +
    Math.random().toString(36).substring(2, 8).toUpperCase()
  );
}
;
app.use(express.static(path.join(__dirname)));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "healthy",
      database: "connected"
    });
  } catch {
    res.status(500).json({
      status: "unhealthy",
      database: "disconnected"
    });
  }
});

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({
        error: "Full name, email and password are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (full_name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, full_name, email, balance, status, created_at`,
      [fullName.trim(), normalizedEmail, passwordHash]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: "Account created successfully.",
      user,
      token: createToken(user)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email.trim().toLowerCase()]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    if (user.status !== "active") {
      return res.status(403).json({
        error: "This account is currently unavailable."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    res.json({
      message: "Login successful.",
      token: createToken(user),
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        balance: user.balance,
        status: user.status
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to sign in."
    });
  }
});

app.get("/api/account", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, balance, status, created_at
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Account not found."
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load account."
    });
  }
});

app.get("/api/transactions", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        id,
        type,
        amount,
        recipient,
        reference,
        status,
        created_at
       FROM transactions
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load transactions."
    });
  }
});

app.post("/api/transfers", authenticate, async (req, res) => {
  const client = await pool.connect();

  try {
    const { amount, recipient } = req.body;
    const transferAmount = Number(amount);

    if (!Number.isFinite(transferAmount) || transferAmount <= 0) {
      return res.status(400).json({
        error: "Enter a valid transfer amount."
      });
    }

    if (!recipient || recipient.trim().length < 3) {
      return res.status(400).json({
        error: "Recipient is required."
      });
    }

    await client.query("BEGIN");

    const account = await client.query(
      `SELECT balance
       FROM users
       WHERE id = $1
       FOR UPDATE`,
      [req.user.id]
    );

    if (!account.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Account not found."
      });
    }

    const balance = Number(account.rows[0].balance);

    if (transferAmount > balance) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Insufficient simulated balance."
      });
    }

    const reference = makeReference();

    await client.query(
      `UPDATE users
       SET balance = balance - $1
       WHERE id = $2`,
      [transferAmount, req.user.id]
    );

    const transaction = await client.query(
      `INSERT INTO transactions
       (user_id, type, amount, recipient, reference, status)
       VALUES ($1, 'transfer', $2, $3, $4, 'successful')
       RETURNING *`,
      [
        req.user.id,
        transferAmount,
        recipient.trim(),
        reference
      ]
    );

    await client.query("COMMIT");

    res.status(201).json({
      message: "Simulated transfer completed successfully.",
      transaction: transaction.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Transfer could not be completed."
    });
  } finally {
    client.release();
  }
});

app.post("/api/support", authenticate, async (req, res) => {
  try {
    const { subject, message } = req.body;

    if (!subject || !message) {
      return res.status(400).json({
        error: "Subject and message are required."
      });
    }

    const result = await pool.query(
      `INSERT INTO support_tickets
       (user_id, subject, message)
       VALUES ($1, $2, $3)
       RETURNING id, subject, message, status, created_at`,
      [
        req.user.id,
        subject.trim(),
        message.trim()
      ]
    );

    res.status(201).json({
      message: "Support request submitted.",
      ticket: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to submit support request."
    });
  }
});

app.get("/api/support", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, subject, message, status, created_at
       FROM support_tickets
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load support requests."
    });
  }
});

async function start() {
  try {
    await setupDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

start();
