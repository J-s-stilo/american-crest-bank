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
  ssl: { rejectUnauthorized: false }
});

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "5mb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
});

/* =========================================================
   SUPPORTED CURRENCIES
========================================================= */

const CURRENCIES = {
  USD: { name: "US Dollar", symbol: "$" },
  NGN: { name: "Nigerian Naira", symbol: "₦" },
  EUR: { name: "Euro", symbol: "€" },
  GBP: { name: "British Pound", symbol: "£" },
  CAD: { name: "Canadian Dollar", symbol: "C$" },
  AUD: { name: "Australian Dollar", symbol: "A$" },
  CHF: { name: "Swiss Franc", symbol: "CHF" },
  JPY: { name: "Japanese Yen", symbol: "¥" },
  CNY: { name: "Chinese Yuan", symbol: "¥" },
  INR: { name: "Indian Rupee", symbol: "₹" },
  IDR: { name: "Indonesian Rupiah", symbol: "Rp" },
  MYR: { name: "Malaysian Ringgit", symbol: "RM" },
  SGD: { name: "Singapore Dollar", symbol: "S$" },
  AED: { name: "UAE Dirham", symbol: "د.إ" },
  ZAR: { name: "South African Rand", symbol: "R" },
  KES: { name: "Kenyan Shilling", symbol: "KSh" },
  GHS: { name: "Ghanaian Cedi", symbol: "GH₵" }
};

function isCurrency(currency) {
  return Object.prototype.hasOwnProperty.call(
    CURRENCIES,
    String(currency || "").toUpperCase()
  );
}

/* =========================================================
   DATABASE
========================================================= */

async function setupDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      role TEXT NOT NULL DEFAULT 'customer',
      profile_image_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      currency CHAR(3) NOT NULL,
      balance NUMERIC(20,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, currency)
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      currency CHAR(3) NOT NULL,
      amount NUMERIC(20,2) NOT NULL,
      recipient TEXT,
      reference TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      description TEXT,
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

    CREATE TABLE IF NOT EXISTS support_messages (
      id SERIAL PRIMARY KEY,
      ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
      sender_role TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'customer';

    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS profile_image_url TEXT;

    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS currency CHAR(3);

    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS description TEXT;
  `);

  console.log("Multi-currency database ready.");
}

/* =========================================================
   HELPERS
========================================================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
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

  try {
    req.user = jwt.verify(
      header.substring(7),
      JWT_SECRET
    );

    next();

  } catch {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

async function requireAdmin(req, res, next) {

  try {

    const result = await pool.query(
      `SELECT id, role, status
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Account not found."
      });
    }

    const user = result.rows[0];

    if (
      user.role !== "admin" ||
      user.status !== "active"
    ) {
      return res.status(403).json({
        error: "Administrator access required."
      });
    }

    next();

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: "Unable to verify administrator access."
    });
  }
}

function validAmount(value) {

  const amount = Number(value);

  if (!Number.isFinite(amount)) return null;
  if (amount <= 0) return null;
  if (amount > 1000000000) return null;

  return Math.round(amount * 100) / 100;
}

function makeReference(prefix = "BANK") {

  return (
    prefix +
    "-" +
    Date.now().toString(36).toUpperCase() +
    "-" +
    Math.random()
      .toString(36)
      .substring(2, 8)
      .toUpperCase()
  );
}

async function ensureCurrencyAccount(
  client,
  userId,
  currency
) {

  const code = String(currency).toUpperCase();

  if (!isCurrency(code)) {
    throw new Error("Unsupported currency.");
  }

  const result = await client.query(
    `INSERT INTO accounts
     (user_id, currency, balance)
     VALUES ($1, $2, 0)
     ON CONFLICT (user_id, currency)
     DO UPDATE SET currency = EXCLUDED.currency
     RETURNING id, user_id, currency, balance`,
    [userId, code]
  );

  return result.rows[0];
}

/* =========================================================
   STATIC WEBSITE
========================================================= */

app.use(
  express.static(
    path.join(__dirname)
  )
);

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({
      status: "healthy",
      database: "connected",
      service: "Multi-Currency Banking Platform"
    });

  } catch {

    res.status(500).json({
      status: "unhealthy",
      database: "disconnected"
    });
  }
});

/* =========================================================
   CURRENCIES
========================================================= */

app.get("/api/currencies", (req, res) => {

  res.json(
    Object.entries(CURRENCIES).map(
      ([code, data]) => ({
        code,
        ...data
      })
    )
  );
});

/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/register",
  authLimiter,
  async (req, res) => {

    try {

      const {
        fullName,
        email,
        password
      } = req.body;

      if (!fullName || !email || !password) {
        return res.status(400).json({
          error:
            "Full name, email and password are required."
        });
      }

      if (String(fullName).trim().length < 2) {
        return res.status(400).json({
          error: "Please enter a valid full name."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Password must contain at least 8 characters."
        });
      }

      const normalizedEmail =
        String(email).trim().toLowerCase();

      const existing =
        await pool.query(
          "SELECT id FROM users WHERE email = $1",
          [normalizedEmail]
        );

      if (existing.rows.length) {
        return res.status(409).json({
          error:
            "An account with this email already exists."
        });
      }

      const passwordHash =
        await bcrypt.hash(password, 12);

      const result =
        await pool.query(
          `INSERT INTO users
          (full_name, email, password_hash)
          VALUES ($1, $2, $3)
          RETURNING
            id,
            full_name,
            email,
            status,
            role,
            profile_image_url,
            created_at`,
          [
            String(fullName).trim(),
            normalizedEmail,
            passwordHash
          ]
        );

      const user = result.rows[0];

      res.status(201).json({
        message:
          "Account created successfully.",
        user,
        token:
          createToken(user)
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to create account."
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  authLimiter,
  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          error:
            "Email and password are required."
        });
      }

      const result =
        await pool.query(
          `SELECT *
           FROM users
           WHERE email = $1`,
          [
            String(email)
              .trim()
              .toLowerCase()
          ]
        );

      if (!result.rows.length) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      const user = result.rows[0];

      if (user.status !== "active") {
        return res.status(403).json({
          error:
            "This account is currently unavailable."
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      res.json({
        message:
          "Login successful.",
        token:
          createToken(user),
        user: {
          id: user.id,
          fullName: user.full_name,
          email: user.email,
          status: user.status,
          role: user.role,
          profileImageUrl:
            user.profile_image_url
        }
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to sign in."
      });
    }
  }
);

/* =========================================================
   CUSTOMER ACCOUNT
========================================================= */

app.get(
  "/api/account",
  authenticate,
  async (req, res) => {

    try {

      const user =
        await pool.query(
          `SELECT
            id,
            full_name,
            email,
            status,
            role,
            profile_image_url,
            created_at
           FROM users
           WHERE id = $1`,
          [req.user.id]
        );

      if (!user.rows.length) {
        return res.status(404).json({
          error:
            "Account not found."
        });
      }

      const accounts =
        await pool.query(
          `SELECT
            currency,
            balance,
            created_at
           FROM accounts
           WHERE user_id = $1
           ORDER BY currency`,
          [req.user.id]
        );

      res.json({
        ...user.rows[0],
        accounts:
          accounts.rows
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load account."
      });
    }
  }
);

/* =========================================================
   CUSTOMER BALANCES
========================================================= */

app.get(
  "/api/accounts",
  authenticate,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
            currency,
            balance,
            created_at
           FROM accounts
           WHERE user_id = $1
           ORDER BY currency`,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load currency accounts."
      });
    }
  }
);

/* =========================================================
   PROFILE
========================================================= */

app.patch(
  "/api/profile",
  authenticate,
  async (req, res) => {

    try {

      const {
        fullName,
        profileImageUrl
      } = req.body;

      const updates = [];
      const values = [];
      let index = 1;

      if (fullName !== undefined) {

        const name =
          String(fullName).trim();

        if (name.length < 2) {
          return res.status(400).json({
            error:
              "Please enter a valid name."
          });
        }

        updates.push(
          `full_name = $${index++}`
        );

        values.push(name);
      }

      if (profileImageUrl !== undefined) {

        if (
          profileImageUrl !== null &&
          String(profileImageUrl).length > 1000000
        ) {
          return res.status(400).json({
            error:
              "Profile image is too large."
          });
        }

        updates.push(
          `profile_image_url = $${index++}`
        );

        values.push(
          profileImageUrl
            ? String(profileImageUrl)
            : null
        );
      }

      if (!updates.length) {
        return res.status(400).json({
          error:
            "No profile changes were provided."
        });
      }

      values.push(req.user.id);

      const result =
        await pool.query(
          `UPDATE users
           SET ${updates.join(", ")}
           WHERE id = $${index}
           RETURNING
             id,
             full_name,
             email,
             status,
             role,
             profile_image_url`,
          values
        );

      res.json({
        message:
          "Profile updated successfully.",
        user:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to update profile."
      });
    }
  }
);

/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
  "/api/transactions",
  authenticate,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
            id,
            type,
            currency,
            amount,
            recipient,
            reference,
            status,
            description,
            created_at
           FROM transactions
           WHERE user_id = $1
           ORDER BY created_at DESC`,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load transactions."
      });
    }
  }
);

/* =========================================================
   TRANSFER REQUEST
========================================================= */

app.post(
  "/api/transfers",
  authenticate,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const amount =
        validAmount(req.body.amount);

      const currency =
        String(
          req.body.currency || ""
        ).toUpperCase();

      const recipient =
        String(
          req.body.recipient || ""
        ).trim();

      if (!amount) {
        return res.status(400).json({
          error:
            "Enter a valid transfer amount."
        });
      }

      if (!isCurrency(currency)) {
        return res.status(400).json({
          error:
            "Please select a supported currency."
        });
      }

      if (recipient.length < 3) {
        return res.status(400).json({
          error:
            "Recipient is required."
        });
      }

      await client.query("BEGIN");

      const account =
        await client.query(
          `SELECT
            id,
            balance
           FROM accounts
           WHERE user_id = $1
             AND currency = $2
           FOR UPDATE`,
          [
            req.user.id,
            currency
          ]
        );

      if (!account.rows.length) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            `You do not have a ${currency} account.`
        });
      }

      const balance =
        Number(
          account.rows[0].balance
        );

      if (amount > balance) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "Insufficient available balance."
        });
      }

      /*
        Funds remain recorded in the account until
        an authorized payment/banking provider processes
        the actual external transfer.
      */

      const reference =
        makeReference("TRF");

      const transaction =
        await client.query(
          `INSERT INTO transactions
          (
            user_id,
            type,
            currency,
            amount,
            recipient,
            reference,
            status,
            description
          )
          VALUES
          (
            $1,
            'transfer',
            $2,
            $3,
            $4,
            $5,
            'pending',
            $6
          )
          RETURNING *`,
          [
            req.user.id,
            currency,
            amount,
            recipient,
            reference,
            "International transfer request"
          ]
        );

      await client.query("COMMIT");

      res.status(201).json({
        message:
          "Transfer request submitted for processing.",
        transaction:
          transaction.rows[0]
      });

    } catch (error) {

      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error(error);

      res.status(500).json({
        error:
          "Transfer could not be submitted."
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   SUPPORT
========================================================= */

app.post(
  "/api/support",
  authenticate,
  async (req, res) => {

    try {

      const subject =
        String(
          req.body.subject || ""
        ).trim();

      const message =
        String(
          req.body.message || ""
        ).trim();

      if (
        subject.length < 2 ||
        message.length < 2
      ) {
        return res.status(400).json({
          error:
            "Subject and message are required."
        });
      }

      const ticket =
        await pool.query(
          `INSERT INTO support_tickets
          (user_id, subject, message)
          VALUES ($1, $2, $3)
          RETURNING
            id,
            subject,
            message,
            status,
            created_at`,
          [
            req.user.id,
            subject,
            message
          ]
        );

      res.status(201).json({
        message:
          "Support request submitted.",
        ticket:
          ticket.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to submit support request."
      });
    }
  }
);

app.get(
  "/api/support",
  authenticate,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
            id,
            subject,
            message,
            status,
            created_at
           FROM support_tickets
           WHERE user_id = $1
           ORDER BY created_at DESC`,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load support requests."
      });
    }
  }
);
/* =========================================================
   CUSTOMER SUPPORT MESSAGES
========================================================= */

app.get(
  "/api/support/:id/messages",
  authenticate,
  async (req, res) => {

    try {

      const ticketId = Number(req.params.id);

      if (!Number.isInteger(ticketId)) {
        return res.status(400).json({
          error: "Invalid support ticket."
        });
      }

      const ticket = await pool.query(
        `SELECT id
         FROM support_tickets
         WHERE id = $1
           AND user_id = $2`,
        [
          ticketId,
          req.user.id
        ]
      );

      if (!ticket.rows.length) {
        return res.status(404).json({
          error: "Support ticket not found."
        });
      }

      const result = await pool.query(
        `SELECT
          id,
          sender_role,
          message,
          created_at
         FROM support_messages
         WHERE ticket_id = $1
         ORDER BY created_at ASC`,
        [ticketId]
      );

      res.json(result.rows);

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Unable to load support messages."
      });
    }
  }
);
/* =========================================================
   ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const customers =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM users
           WHERE role = 'customer'`
        );

      const total =
        await pool.query(
          `SELECT
             currency,
             COALESCE(SUM(a.balance), 0) AS total
           FROM accounts a
           JOIN users u
             ON u.id = a.user_id
           WHERE u.role = 'customer'
           GROUP BY currency
           ORDER BY currency`
        );

      const pending =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM transactions
           WHERE type = 'transfer'
             AND status = 'pending'`
        );

      const support =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM support_tickets
           WHERE status = 'open'`
        );

      res.json({
        customers:
          customers.rows[0].count,
        balances:
          total.rows,
        pendingTransfers:
          pending.rows[0].count,
        openSupport:
          support.rows[0].count
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load administrator summary."
      });
    }
  }
);

/* =========================================================
   ADMIN CUSTOMER LIST
========================================================= */

app.get(
  "/api/admin/customers",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
            u.id,
            u.full_name,
            u.email,
            u.status,
            u.role,
            u.profile_image_url,
            u.created_at,
            COALESCE(
              json_agg(
                json_build_object(
                  'currency', a.currency,
                  'balance', a.balance
                )
              ) FILTER (
                WHERE a.id IS NOT NULL
              ),
              '[]'
            ) AS accounts
           FROM users u
           LEFT JOIN accounts a
             ON a.user_id = u.id
           WHERE u.role = 'customer'
           GROUP BY
             u.id
           ORDER BY
             u.created_at DESC`
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load customers."
      });
    }
  }
);

/* =========================================================
   ADMIN ADD FUNDS
========================================================= */

app.post(
  "/api/admin/customers/:id/funds",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const userId =
        Number(req.params.id);

      const amount =
        validAmount(
          req.body.amount
        );

      const currency =
        String(
          req.body.currency || ""
        ).toUpperCase();

      const description =
        String(
          req.body.description ||
          "Administrator account funding"
        ).trim();

      if (!Number.isInteger(userId)) {
        return res.status(400).json({
          error:
            "Invalid customer ID."
        });
      }

      if (!amount) {
        return res.status(400).json({
          error:
            "Enter a valid amount."
        });
      }

      if (!isCurrency(currency)) {
        return res.status(400).json({
          error:
            "Please select a supported currency."
        });
      }

      await client.query("BEGIN");

      const customer =
        await client.query(
          `SELECT
            id,
            full_name,
            email,
            status
           FROM users
           WHERE id = $1
             AND role = 'customer'
           FOR UPDATE`,
          [userId]
        );

      if (!customer.rows.length) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "Customer not found."
        });
      }

      if (
        customer.rows[0].status !== "active"
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "This customer account is not active."
        });
      }

      const account =
        await ensureCurrencyAccount(
          client,
          userId,
          currency
        );

      await client.query(
        `UPDATE accounts
         SET balance = balance + $1
         WHERE id = $2`,
        [
          amount,
          account.id
        ]
      );

      const reference =
        makeReference("FUND");

      const transaction =
        await client.query(
          `INSERT INTO transactions
          (
            user_id,
            type,
            currency,
            amount,
            reference,
            status,
            description
          )
          VALUES
          (
            $1,
            'credit',
            $2,
            $3,
            $4,
            'successful',
            $5
          )
          RETURNING *`,
          [
            userId,
            currency,
            amount,
            reference,
            description
          ]
        );

      await client.query(
        `INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          $2,
          $3
        )`,
        [
          userId,
          "Account funded",
          `Your ${currency} account has received a new credit.`
        ]
      );

      const updated =
        await client.query(
          `SELECT
            currency,
            balance
           FROM accounts
           WHERE user_id = $1
           ORDER BY currency`,
          [userId]
        );

      await client.query("COMMIT");

      res.json({
        message:
          "Customer account funded successfully.",
        customer: {
          id:
            customer.rows[0].id,
          fullName:
            customer.rows[0].full_name,
          email:
            customer.rows[0].email
        },
        fundedCurrency:
          currency,
        fundedAmount:
          amount,
        accounts:
          updated.rows,
        transaction:
          transaction.rows[0]
      });

    } catch (error) {

      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error(error);

      res.status(500).json({
        error:
          "Unable to fund customer account."
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
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const userId =
        Number(req.params.id);

      const status =
        String(
          req.body.status || ""
        ).toLowerCase();

      const allowed = [
        "active",
        "pending",
        "suspended"
      ];

      if (
        !Number.isInteger(userId) ||
        !allowed.includes(status)
      ) {
        return res.status(400).json({
          error:
            "Invalid customer or account status."
        });
      }

      const result =
        await pool.query(
          `UPDATE users
           SET status = $1
           WHERE id = $2
             AND role = 'customer'
           RETURNING
             id,
             full_name,
             email,
             status`,
          [
            status,
            userId
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Customer not found."
        });
      }

      res.json({
        message:
          "Customer account status updated.",
        customer:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to update customer status."
      });
    }
  }
);

/* =========================================================
   ADMIN TRANSFERS
========================================================= */

app.get(
  "/api/admin/transfers",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
            t.id,
            t.user_id,
            u.full_name,
            u.email,
            t.currency,
            t.amount,
            t.recipient,
            t.reference,
            t.status,
            t.description,
            t.created_at
           FROM transactions t
           JOIN users u
             ON u.id = t.user_id
           WHERE t.type = 'transfer'
           ORDER BY t.created_at DESC`
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load transfers."
      });
    }
  }
);

/* =========================================================
   ADMIN UPDATE TRANSFER STATUS
========================================================= */

app.patch(
  "/api/admin/transfers/:id/status",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const transactionId =
        Number(req.params.id);

      const status =
        String(
          req.body.status || ""
        ).toLowerCase();

      const allowed = [
        "pending",
        "successful",
        "declined"
      ];

      if (
        !Number.isInteger(transactionId) ||
        !allowed.includes(status)
      ) {
        return res.status(400).json({
          error:
            "Invalid transaction or status."
        });
      }

      const result =
        await pool.query(
          `UPDATE transactions
           SET status = $1
           WHERE id = $2
             AND type = 'transfer'
           RETURNING
             id,
             user_id,
             currency,
             amount,
             recipient,
             reference,
             status,
             created_at`,
          [
            status,
            transactionId
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Transfer not found."
        });
      }

      const transaction =
        result.rows[0];

      await pool.query(
        `INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          $2,
          $3
        )`,
        [
          transaction.user_id,
          "Transfer status updated",
          `Transfer ${transaction.reference} is now ${status}.`
        ]
      );

      res.json({
        message:
          "Transfer status updated.",
        transaction
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to update transfer status."
      });
    }
  }
);

/* =========================================================
   ADMIN SUPPORT
========================================================= */

app.get(
  "/api/admin/support",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
            s.id,
            s.user_id,
            u.full_name,
            u.email,
            s.subject,
            s.message,
            s.status,
            s.created_at
           FROM support_tickets s
           JOIN users u
             ON u.id = s.user_id
           ORDER BY s.created_at DESC`
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load support requests."
      });
    }
  }
);

/* =========================================================
   ADMIN REPLY
========================================================= */

app.post(
  "/api/admin/support/:id/reply",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const ticketId =
        Number(req.params.id);

      const message =
        String(
          req.body.message || ""
        ).trim();

      if (
        !Number.isInteger(ticketId) ||
        message.length < 1
      ) {
        return res.status(400).json({
          error:
            "Valid ticket and reply are required."
        });
      }

      await client.query("BEGIN");

      const ticket =
        await client.query(
          `SELECT id, user_id
           FROM support_tickets
           WHERE id = $1
           FOR UPDATE`,
          [ticketId]
        );

      if (!ticket.rows.length) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "Support ticket not found."
        });
      }

      await client.query(
        `INSERT INTO support_messages
        (
          ticket_id,
          sender_role,
          message
        )
        VALUES
        (
          $1,
          'admin',
          $2
        )`,
        [
          ticketId,
          message
        ]
      );

      await client.query(
        `UPDATE support_tickets
         SET status = 'answered'
         WHERE id = $1`,
        [ticketId]
      );

      await client.query(
        `INSERT INTO notifications
        (
          user_id,
          title,
          message
        )
        VALUES
        (
          $1,
          $2,
          $3
        )`,
        [
          ticket.rows[0].user_id,
          "Support response",
          "Customer support has replied to your request."
        ]
      );

      await client.query("COMMIT");

      res.json({
        message:
          "Support response sent."
      });

    } catch (error) {

      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error(error);

      res.status(500).json({
        error:
          "Unable to send support response."
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN NOTIFICATIONS
========================================================= */

app.get(
  "/api/admin/notifications",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `SELECT
            id,
            title,
            message,
            is_read,
            created_at
           FROM notifications
           WHERE user_id = $1
           ORDER BY created_at DESC
           LIMIT 100`,
          [req.user.id]
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to load notifications."
      });
    }
  }
);

app.patch(
  "/api/admin/notifications/:id/read",
  authenticate,
  adminLimiter,
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const result =
        await pool.query(
          `UPDATE notifications
           SET is_read = TRUE
           WHERE id = $1
             AND user_id = $2
           RETURNING id`,
          [
            id,
            req.user.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            "Notification not found."
        });
      }

      res.json({
        message:
          "Notification marked as read."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Unable to update notification."
      });
    }
  }
);

/* =========================================================
   ADMIN ACCOUNT
========================================================= */

async function ensureAdminAccount() {

  const adminEmail =
    process.env.ADMIN_EMAIL;

  const adminPassword =
    process.env.ADMIN_PASSWORD;

  if (!adminEmail || !adminPassword) {

    console.log(
      "ADMIN_EMAIL or ADMIN_PASSWORD is not configured."
    );

    return;
  }

  if (adminPassword.length < 12) {

    console.error(
      "ADMIN_PASSWORD must contain at least 12 characters."
    );

    return;
  }

  const email =
    adminEmail.trim().toLowerCase();

  const passwordHash =
    await bcrypt.hash(
      adminPassword,
      12
    );

  const existing =
    await pool.query(
      `SELECT id
       FROM users
       WHERE email = $1`,
      [email]
    );

  if (!existing.rows.length) {

    await pool.query(
      `INSERT INTO users
      (
        full_name,
        email,
        password_hash,
        role,
        status
      )
      VALUES
      (
        'Administrator',
        $1,
        $2,
        'admin',
        'active'
      )`,
      [
        email,
        passwordHash
      ]
    );

    console.log(
      "Administrator account created."
    );

  } else {

    await pool.query(
      `UPDATE users
       SET
         password_hash = $1,
         role = 'admin',
         status = 'active'
       WHERE email = $2`,
      [
        passwordHash,
        email
      ]
    );

    console.log(
      "Administrator account verified."
    );
  }
}

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(err);

    if (res.headersSent) {
      return next(err);
    }

    res.status(500).json({
      error:
        "An unexpected server error occurred."
    });
  }
);

/* =========================================================
   START
========================================================= */

async function start() {

  try {

    await setupDatabase();

    await ensureAdminAccount();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `Multi-Currency Banking Platform running on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "Startup failed:",
      error
    );

    process.exit(1);
  }
}

start();
