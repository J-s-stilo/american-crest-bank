const express = require("express");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");

const app = express();

app.set("trust proxy", 1);

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
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api", apiLimiter);
app.use("/api/login", authLimiter);
app.use("/api/register", authLimiter);

const CURRENCIES = [
  "NGN",
  "USD",
  "EUR",
  "GBP",
  "IDR",
  "CAD",
  "AUD",
  "CHF",
  "JPY",
  "CNY",
  "INR",
  "MYR",
  "SGD",
  "AED",
  "ZAR",
  "KES",
  "GHS"
];

function balanceColumn(currency) {
  const c = String(currency || "").toUpperCase();

  if (!CURRENCIES.includes(c)) {
    return null;
  }

  return `balance_${c.toLowerCase()}`;
}

function formatDate(value) {
  return new Date(value).toLocaleString();
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      isAdmin: Boolean(user.is_admin)
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function publicUser(row) {
  const balances = {};

  for (const currency of CURRENCIES) {
    balances[currency] = Number(
      row[`balance_${currency.toLowerCase()}`] || 0
    );
  }

  return {
    id: row.id,
    name: row.name,
    email: row.email,
    status: row.status,
    primaryCurrency: row.primary_currency,
    balances,
    profileImage: row.profile_image || "",
    isAdmin: Boolean(row.is_admin),
    createdAt: formatDate(row.created_at)
  };
}

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required."
      });
    }

    const token = header.slice(7);

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      primary_currency VARCHAR(3) NOT NULL DEFAULT 'NGN',
      profile_image TEXT DEFAULT '',
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE
`);
  for (const currency of CURRENCIES) {
    await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE
`);

await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
`);

await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS profile_image TEXT DEFAULT ''
`);

await pool.query(`
  ALTER TABLE users
  ADD COLUMN IF NOT EXISTS primary_currency VARCHAR(3) NOT NULL DEFAULT 'NGN'
`);
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS
      balance_${currency.toLowerCase()}
      NUMERIC(30,2) NOT NULL DEFAULT 0
    `);
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('credit','debit')),
      title TEXT NOT NULL,
      amount NUMERIC(30,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL DEFAULT 'Notification',
      message TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS support_messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      sender TEXT NOT NULL CHECK (sender IN ('customer','admin')),
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transfers (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(30,2) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      recipient TEXT NOT NULL,
      reference TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_requests (
      id SERIAL PRIMARY KEY,
      request_type TEXT NOT NULL DEFAULT 'general',
      message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  console.log("Demo database initialized.");
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      application: "American Crest Bank — Fictional Demo",
      mode: "fictional-demo"
    });
  } catch {
    res.status(500).json({
      ok: false
    });
  }
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();

    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const currency = String(
      req.body.primaryCurrency || "NGN"
    ).toUpperCase();

    if (name.length < 2) {
      return res.status(400).json({
        error: "Enter your full name."
      });
    }

    if (!email.includes("@")) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        error: "Password must contain at least 4 characters."
      });
    }

    if (!CURRENCIES.includes(currency)) {
      return res.status(400).json({
        error: "Invalid currency."
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO users
      (name,email,password_hash,primary_currency)
      VALUES ($1,$2,$3,$4)
      RETURNING *
      `,
      [name, email, hash, currency]
    );

    const user = result.rows[0];

    await pool.query(
      `
      INSERT INTO notifications
      (user_id,title,message)
      VALUES ($1,$2,$3)
      `,
      [
        user.id,
        "Account created",
        "Your fictional demo account has been created successfully."
      ]
    );

    const token = makeToken(user);

    res.status(201).json({
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const token = makeToken(user);

    res.json({
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: "Unable to sign in."
    });
  }
});

/* =========================================================
   ME
========================================================= */

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);

    if (!user) {
      return res.status(404).json({
        error: "Account not found."
      });
    }

    res.json({
      user: publicUser(user)
    });
  } catch {
    res.status(500).json({
      error: "Unable to load account."
    });
  }
});

/* =========================================================
   HELPER
========================================================= */

async function getUserById(id) {
  const result = await pool.query(
    "SELECT * FROM users WHERE id = $1",
    [id]
  );

  return result.rows[0] || null;
}

/* =========================================================
   TRANSACTIONS
========================================================= */

app.get("/api/transactions", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id,kind,title,amount,currency,created_at
      FROM transactions
      WHERE user_id = $1
      ORDER BY created_at DESC
      `,
      [req.user.id]
    );

    res.json({
      transactions: result.rows.map(row => ({
        id: String(row.id),
        kind: row.kind,
        title: row.title,
        amount: Number(row.amount),
        currency: row.currency,
        date: formatDate(row.created_at)
      }))
    });
  } catch {
    res.status(500).json({
      error: "Unable to load transactions."
    });
  }
});

/* =========================================================
   CUSTOMER TRANSFER — DEMO ONLY
========================================================= */

app.post("/api/transfers", requireAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const currency = String(
      req.body.currency || ""
    ).toUpperCase();

    const amount = Number(req.body.amount);

    const recipient = String(
      req.body.recipient || ""
    ).trim();

    if (!CURRENCIES.includes(currency)) {
      return res.status(400).json({
        error: "Invalid currency."
      });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({
        error: "Enter a valid amount."
      });
    }

    if (recipient.length < 2) {
      return res.status(400).json({
        error: "Enter the recipient name."
      });
    }

    const column = balanceColumn(currency);

    await client.query("BEGIN");

    const result = await client.query(
      `
      SELECT *
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [req.user.id]
    );

    const user = result.rows[0];

    if (!user) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Account not found."
      });
    }

    const currentBalance = Number(
      user[column] || 0
    );

    if (amount > currentBalance) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Insufficient demo balance."
      });
    }

    await client.query(
      `
      UPDATE users
      SET ${column} = ${column} - $1
      WHERE id = $2
      `,
      [amount, req.user.id]
    );

    const reference =
      "DEMO-" +
      Date.now().toString(36).toUpperCase() +
      "-" +
      Math.random()
        .toString(36)
        .slice(2, 7)
        .toUpperCase();

    await client.query(
      `
      INSERT INTO transfers
      (user_id,amount,currency,recipient,reference,status)
      VALUES ($1,$2,$3,$4,$5,'pending')
      `,
      [
        req.user.id,
        amount,
        currency,
        recipient,
        reference
      ]
    );

    await client.query(
      `
      INSERT INTO transactions
      (user_id,kind,title,amount,currency)
      VALUES ($1,'debit',$2,$3,$4)
      `,
      [
        req.user.id,
        `Demo transfer to ${recipient}`,
        amount,
        currency
      ]
    );

    await client.query(
      `
      INSERT INTO notifications
      (user_id,title,message)
      VALUES ($1,$2,$3)
      `,
      [
        req.user.id,
        "Demo transfer",
        `Your fictional demo transfer of ${amount} ${currency} to ${recipient} is pending.`
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Demo transfer recorded.",
      amount,
      currency,
      reference,
      status: "pending"
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error("TRANSFER ERROR:", error);

    res.status(500).json({
      error: "Unable to process demo transfer."
    });
  } finally {
    client.release();
  }
});

/* =========================================================
   CUSTOMER NOTIFICATIONS
========================================================= */

app.get("/api/notifications", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id,title,message,created_at
      FROM notifications
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [req.user.id]
    );

    res.json({
      notifications: result.rows.map(n => ({
        id: String(n.id),
        title: n.title,
        message: n.message,
        date: formatDate(n.created_at)
      }))
    });
  } catch {
    res.status(500).json({
      error: "Unable to load notifications."
    });
  }
});

/* =========================================================
   CUSTOMER SUPPORT
========================================================= */

app.post("/api/support", requireAuth, async (req, res) => {
  try {
    const message = String(
      req.body.message || ""
    ).trim();

    if (!message) {
      return res.status(400).json({
        error: "Write a message first."
      });
    }

    if (message.length > 2000) {
      return res.status(400).json({
        error: "Message is too long."
      });
    }

    await pool.query(
      `
      INSERT INTO support_messages
      (user_id,sender,message)
      VALUES ($1,'customer',$2)
      `,
      [req.user.id, message]
    );

    await pool.query(
      `
      INSERT INTO notifications
      (user_id,title,message)
      VALUES ($1,$2,$3)
      `,
      [
        req.user.id,
        "Support request",
        "Your demo support message has been sent."
      ]
    );

    res.json({
      success: true,
      message: "Support message sent."
    });
  } catch {
    res.status(500).json({
      error: "Unable to send support message."
    });
  }
});

app.get("/api/support", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id,sender,message,created_at
      FROM support_messages
      WHERE user_id = $1
      ORDER BY created_at ASC
      `,
      [req.user.id]
    );

    res.json({
      messages: result.rows.map(row => ({
        id: String(row.id),
        sender: row.sender,
        message: row.message,
        date: formatDate(row.created_at)
      }))
    });
  } catch {
    res.status(500).json({
      error: "Unable to load support messages."
    });
  }
});

/* =========================================================
   PROFILE
========================================================= */

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const name = String(
      req.body.name || ""
    ).trim();

    if (name.length < 2) {
      return res.status(400).json({
        error: "Enter a valid name."
      });
    }

    const result = await pool.query(
      `
      UPDATE users
      SET name = $1
      WHERE id = $2
      RETURNING *
      `,
      [name, req.user.id]
    );

    res.json({
      user: publicUser(result.rows[0])
    });
  } catch {
    res.status(500).json({
      error: "Unable to update profile."
    });
  }
});

app.put("/api/profile-image", requireAuth, async (req, res) => {
  try {
    const image = String(
      req.body.image || ""
    );

    if (
      image &&
      !image.startsWith("data:image/")
    ) {
      return res.status(400).json({
        error: "Invalid image."
      });
    }

    if (image.length > 3 * 1024 * 1024) {
      return res.status(400).json({
        error: "Image is too large."
      });
    }

    const result = await pool.query(
      `
      UPDATE users
      SET profile_image = $1
      WHERE id = $2
      RETURNING *
      `,
      [image, req.user.id]
    );

    res.json({
      user: publicUser(result.rows[0])
    });
  } catch {
    res.status(500).json({
      error: "Unable to update profile picture."
    });
  }
});

/* =========================================================
   ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const customersResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS count
        FROM users
        WHERE is_admin = FALSE
        `
      );

      const pendingResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS count
        FROM transfers
        WHERE status = 'pending'
        `
      );

      const supportResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS count
        FROM support_messages sm
        WHERE sm.sender = 'customer'
        AND NOT EXISTS (
          SELECT 1
          FROM support_messages reply
          WHERE reply.user_id = sm.user_id
          AND reply.sender = 'admin'
          AND reply.created_at > sm.created_at
        )
        `
      );

      const balanceColumns = CURRENCIES.map(
        currency =>
          `SUM(balance_${currency.toLowerCase()}) AS "${currency.toLowerCase()}"`
      ).join(",\n");

      const balanceResult = await pool.query(`
        SELECT
          ${balanceColumns}
        FROM users
        WHERE is_admin = FALSE
      `);

      const row = balanceResult.rows[0] || {};

      const balances = CURRENCIES
        .map(currency => ({
          currency,
          total: Number(
            row[currency.toLowerCase()] || 0
          )
        }))
        .filter(item => item.total !== 0);

      res.json({
        customers: customersResult.rows[0].count,
        balances,
        pendingTransfers: pendingResult.rows[0].count,
        openSupport: supportResult.rows[0].count
      });
    } catch (error) {
      console.error("SUMMARY ERROR:", error);

      res.status(500).json({
        error: "Unable to load dashboard."
      });
    }
  }
);

/* =========================================================
   ADMIN CUSTOMERS
========================================================= */

app.get(
  "/api/admin/customers",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT *
        FROM users
        WHERE is_admin = FALSE
        ORDER BY created_at DESC
      `);

      res.json(
        result.rows.map(row => ({
          id: row.id,
          full_name: row.name,
          email: row.email,
          status: String(
            row.status || "active"
          ).toLowerCase(),
          created_at: row.created_at,
          accounts: CURRENCIES
            .map(currency => ({
              currency,
              balance: Number(
                row[
                  `balance_${currency.toLowerCase()}`
                ] || 0
              )
            }))
            .filter(
              account => account.balance !== 0
            )
        }))
      );
    } catch (error) {
      console.error(
        "ADMIN CUSTOMERS ERROR:",
        error
      );

      res.status(500).json({
        error: "Unable to load customers."
      });
    }
  }
);

/* =========================================================
   ADMIN CUSTOMER FUNDS
========================================================= */

app.post(
  "/api/admin/customers/:id/funds",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const customerId = Number(
        req.params.id
      );

      const currency = String(
        req.body.currency || ""
      ).toUpperCase();

      const amount = Number(
        req.body.amount
      );

      const description = String(
        req.body.description || ""
      ).trim();

      if (!Number.isInteger(customerId)) {
        return res.status(400).json({
          error: "Invalid customer."
        });
      }

      if (!CURRENCIES.includes(currency)) {
        return res.status(400).json({
          error: "Invalid currency."
        });
      }

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          error: "Enter a valid amount."
        });
      }

      if (amount > 1000000000) {
        return res.status(400).json({
          error: "The amount is too large."
        });
      }

      const column = balanceColumn(currency);

      await client.query("BEGIN");

      const result = await client.query(
        `
        SELECT *
        FROM users
        WHERE id = $1
        AND is_admin = FALSE
        FOR UPDATE
        `,
        [customerId]
      );

      const customer = result.rows[0];

      if (!customer) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Customer not found."
        });
      }

      await client.query(
        `
        UPDATE users
        SET ${column} = ${column} + $1
        WHERE id = $2
        `,
        [amount, customerId]
      );

      await client.query(
        `
        INSERT INTO transactions
        (user_id,kind,title,amount,currency)
        VALUES ($1,'credit',$2,$3,$4)
        `,
        [
          customerId,
          description ||
            "Demo account funding",
          amount,
          currency
        ]
      );

      await client.query(
        `
        INSERT INTO notifications
        (user_id,title,message)
        VALUES ($1,$2,$3)
        `,
        [
          customerId,
          "Demo account credit",
          `Your fictional demo account was credited with ${amount} ${currency}.`
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          "Customer demo account funded successfully.",
        customerId,
        amount,
        currency
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error("FUNDS ERROR:", error);

      res.status(500).json({
        error: "Unable to add funds."
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN CUSTOMER STATUS
========================================================= */

app.patch(
  "/api/admin/customers/:id/status",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      const status = String(
        req.body.status || ""
      ).toLowerCase();

      if (
        !["active", "suspended"].includes(
          status
        )
      ) {
        return res.status(400).json({
          error: "Invalid customer status."
        });
      }

      const result = await pool.query(
        `
        UPDATE users
        SET status = $1
        WHERE id = $2
        AND is_admin = FALSE
        RETURNING id,status
        `,
        [status, id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Customer not found."
        });
      }

      res.json({
        success: true,
        status
      });
    } catch {
      res.status(500).json({
        error: "Unable to update customer status."
      });
    }
  }
);

/* =========================================================
   ADMIN TRANSFERS
========================================================= */

app.get(
  "/api/admin/transfers",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          t.id,
          t.amount,
          t.currency,
          t.recipient,
          t.reference,
          t.status,
          u.name AS full_name,
          u.email
        FROM transfers t
        JOIN users u ON u.id = t.user_id
        ORDER BY t.created_at DESC
      `);

      res.json(
        result.rows.map(row => ({
          id: row.id,
          full_name: row.full_name,
          email: row.email,
          amount: Number(row.amount),
          currency: row.currency,
          recipient: row.recipient,
          reference: row.reference,
          status: row.status
        }))
      );
    } catch {
      res.status(500).json({
        error: "Unable to load transfers."
      });
    }
  }
);

/* =========================================================
   ADMIN TRANSFER STATUS
========================================================= */

app.patch(
  "/api/admin/transfers/:id/status",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const id = Number(
        req.params.id
      );

      const status = String(
        req.body.status || ""
      ).toLowerCase();

      if (
        ![
          "successful",
          "declined",
          "pending"
        ].includes(status)
      ) {
        return res.status(400).json({
          error: "Invalid transfer status."
        });
      }

      await client.query("BEGIN");

      const result = await client.query(
        `
        SELECT *
        FROM transfers
        WHERE id = $1
        FOR UPDATE
        `,
        [id]
      );

      const transfer = result.rows[0];

      if (!transfer) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Transfer not found."
        });
      }

      if (
        transfer.status === "pending" &&
        status === "declined"
      ) {
        const column =
          balanceColumn(
            transfer.currency
          );

        await client.query(
          `
          UPDATE users
          SET ${column} = ${column} + $1
          WHERE id = $2
          `,
          [
            Number(transfer.amount),
            transfer.user_id
          ]
        );

        await client.query(
          `
          INSERT INTO transactions
          (user_id,kind,title,amount,currency)
          VALUES ($1,'credit',$2,$3,$4)
          `,
          [
            transfer.user_id,
            "Demo transfer reversal",
            Number(transfer.amount),
            transfer.currency
          ]
        );
      }

      await client.query(
        `
        UPDATE transfers
        SET status = $1
        WHERE id = $2
        `,
        [status, id]
      );

      await client.query(
        `
        INSERT INTO notifications
        (user_id,title,message)
        VALUES ($1,$2,$3)
        `,
        [
          transfer.user_id,
          "Demo transfer update",
          `Your fictional demo transfer ${transfer.reference} is now ${status}.`
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        status
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(
        "TRANSFER STATUS ERROR:",
        error
      );

      res.status(500).json({
        error: "Unable to update transfer."
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN SUPPORT LIST
========================================================= */

app.get(
  "/api/admin/support",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          sm.id,
          sm.user_id,
          sm.message,
          sm.created_at,
          u.name AS full_name,
          u.email,
          COALESCE(
            (
              SELECT COUNT(*)
              FROM support_messages reply
              WHERE reply.user_id = sm.user_id
              AND reply.sender = 'admin'
              AND reply.created_at > sm.created_at
            ),
            0
          ) AS replies
        FROM support_messages sm
        JOIN users u ON u.id = sm.user_id
        WHERE sm.sender = 'customer'
        ORDER BY sm.created_at DESC
      `);

      res.json(
        result.rows.map(row => ({
          id: row.id,
          full_name: row.full_name,
          email: row.email,
          subject: "Customer support",
          message: row.message,
          status:
            Number(row.replies) > 0
              ? "answered"
              : "pending"
        }))
      );
    } catch {
      res.status(500).json({
        error:
          "Unable to load support requests."
      });
    }
  }
);

/* =========================================================
   ADMIN SUPPORT REPLY
========================================================= */

app.post(
  "/api/admin/support/:id/reply",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      const message = String(
        req.body.message || ""
      ).trim();

      if (!Number.isInteger(id)) {
        return res.status(400).json({
          error: "Invalid support request."
        });
      }

      if (!message) {
        return res.status(400).json({
          error: "Write a reply first."
        });
      }

      const ticket = await pool.query(
        `
        SELECT user_id
        FROM support_messages
        WHERE id = $1
        AND sender = 'customer'
        `,
        [id]
      );

      if (!ticket.rows.length) {
        return res.status(404).json({
          error: "Support request not found."
        });
      }

      const customerId =
        ticket.rows[0].user_id;

      await pool.query(
        `
        INSERT INTO support_messages
        (user_id,sender,message)
        VALUES ($1,'admin',$2)
        `,
        [customerId, message]
      );

      await pool.query(
        `
        INSERT INTO notifications
        (user_id,title,message)
        VALUES ($1,$2,$3)
        `,
        [
          customerId,
          "Support response",
          "You have received a response to your demo support request."
        ]
      );

      res.json({
        success: true,
        message: "Response sent."
      });
    } catch {
      res.status(500).json({
        error: "Unable to send reply."
      });
    }
  }
);

/* =========================================================
   ADMIN NOTIFICATIONS
========================================================= */

app.get(
  "/api/admin/notifications",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          n.id,
          n.title,
          n.message,
          n.is_read,
          n.created_at
        FROM notifications n
        ORDER BY n.created_at DESC
        LIMIT 100
      `);

      res.json(
        result.rows.map(row => ({
          id: row.id,
          title: row.title,
          message: row.message,
          is_read: row.is_read,
          created_at: row.created_at
        }))
      );
    } catch {
      res.status(500).json({
        error:
          "Unable to load notifications."
      });
    }
  }
);

/* =========================================================
   ADMIN MARK NOTIFICATION READ
========================================================= */

app.patch(
  "/api/admin/notifications/:id/read",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      const result = await pool.query(
        `
        UPDATE notifications
        SET is_read = TRUE
        WHERE id = $1
        RETURNING id
        `,
        [id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Notification not found."
        });
      }

      res.json({
        success: true
      });
    } catch {
      res.status(500).json({
        error:
          "Unable to mark notification as read."
      });
    }
  }
);

/* =========================================================
   ADMIN SEND NOTIFICATION
========================================================= */

app.post(
  "/api/admin/notify",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const customerId = Number(
        req.body.customerId
      );

      const message = String(
        req.body.message || ""
      ).trim();

      if (!Number.isInteger(customerId)) {
        return res.status(400).json({
          error: "Invalid customer."
        });
      }

      if (!message) {
        return res.status(400).json({
          error: "Write a notification first."
        });
      }

      const customer =
        await getUserById(customerId);

      if (
        !customer ||
        customer.is_admin
      ) {
        return res.status(404).json({
          error: "Customer not found."
        });
      }

      await pool.query(
        `
        INSERT INTO notifications
        (user_id,title,message)
        VALUES ($1,$2,$3)
        `,
        [
          customerId,
          "Administrator notification",
          message
        ]
      );

      res.json({
        success: true,
        message: "Notification sent."
      });
    } catch {
      res.status(500).json({
        error:
          "Unable to send notification."
      });
    }
  }
);

/* =========================================================
   ADMIN REQUESTS
========================================================= */

app.get(
  "/api/admin/requests",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          request_type,
          message,
          status,
          created_at
        FROM admin_requests
        ORDER BY created_at DESC
        LIMIT 100
      `);

      res.json({
        requests: result.rows.map(row => ({
          id: String(row.id),
          type: row.request_type,
          message: row.message,
          status: row.status,
          date: formatDate(row.created_at)
        }))
      });
    } catch (error) {
      console.error(
        "ADMIN REQUESTS ERROR:",
        error
      );

      res.status(500).json({
        error: "Unable to load requests."
      });
    }
  }
);
/* =========================================================
   ADMIN SETUP PAGE
========================================================= */

app.get("/admin-setup", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Admin Setup</title>
      <meta name="viewport" content="width=device-width,initial-scale=1">
    </head>
    <body style="font-family:Arial;padding:30px;max-width:500px;margin:auto">
      <h2>Administrator Setup</h2>

      <form method="POST" action="/api/admin/setup">
        <input name="setupKey" placeholder="Admin Setup Key"
          required style="width:100%;padding:12px;margin:8px 0">

        <input name="name" placeholder="Admin Name"
          required style="width:100%;padding:12px;margin:8px 0">

        <input name="email" type="email" placeholder="Admin Email"
          required style="width:100%;padding:12px;margin:8px 0">

        <input name="password" type="password" placeholder="Admin Password"
          required style="width:100%;padding:12px;margin:8px 0">

        <button type="submit"
          style="padding:12px 20px;margin-top:10px">
          Create / Update Admin
        </button>
      </form>
    </body>
    </html>
  `);
});
/* =========================================================
   ADMIN SETUP
========================================================= */

app.post(
  "/api/admin/setup",
  async (req, res) => {
    try {
      const setupKey = String(
        req.body.setupKey || ""
      );

      if (
        !process.env.ADMIN_SETUP_KEY ||
        setupKey !==
          process.env.ADMIN_SETUP_KEY
      ) {
        return res.status(403).json({
          error: "Invalid setup key."
        });
      }

      const name = String(
        req.body.name || ""
      ).trim();

      const email = String(
        req.body.email || ""
      )
        .trim()
        .toLowerCase();

      const password = String(
        req.body.password || ""
      );

      if (name.length < 2) {
        return res.status(400).json({
          error:
            "Invalid administrator name."
        });
      }

      if (!email.includes("@")) {
        return res.status(400).json({
          error:
            "Invalid administrator email."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Administrator password must contain at least 8 characters."
        });
      }

      const existing =
        await pool.query(
          "SELECT id FROM users WHERE email = $1",
          [email]
        );

      if (existing.rows.length) {
        await pool.query(
          `
          UPDATE users
          SET is_admin = TRUE,
              name = $1,
              password_hash = $2
          WHERE email = $3
          RETURNING *
          `,
          [
            name,
            await bcrypt.hash(
              password,
              12
            ),
            email
          ]
        );

        return res.json({
          success: true,
          message:
            "Existing account promoted to administrator."
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      await pool.query(
        `
        INSERT INTO users
        (name,email,password_hash,primary_currency,is_admin)
        VALUES ($1,$2,$3,'USD',TRUE)
        `,
        [
          name,
          email,
          hash
        ]
      );

      res.status(201).json({
        success: true,
        message:
          "Administrator account created."
      });
    } catch (error) {
      console.error(
        "ADMIN SETUP ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to create administrator."
      });
    }
  }
);

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  express.static(
    path.join(__dirname)
  )
);

app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found."
    });
  }

  res.sendFile(
    path.join(
      __dirname,
      "index.html"
    )
  );
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    res.status(500).json({
      error: "Internal server error."
    });
  }
);

/* =========================================================
   START
========================================================= */
initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `American Crest fictional demo server running on port ${PORT}`
      );
    });
  })
  .catch(error => {
    console.error(
      "DATABASE STARTUP ERROR:",
      error
    );

    process.exit(1);
  });
